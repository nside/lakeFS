package auth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/crypt"
	"github.com/treeverse/lakefs/pkg/auth/model"
	authparams "github.com/treeverse/lakefs/pkg/auth/params"
	"github.com/treeverse/lakefs/pkg/kv"
	"github.com/treeverse/lakefs/pkg/kv/kvtest"
	"github.com/treeverse/lakefs/pkg/logging"
	"google.golang.org/protobuf/proto"
)

var secret string = "Secret"

func SetupService(t *testing.T, secret string) (*auth.BasicAuthService, kv.Store) {
	t.Helper()
	kvStore := kvtest.GetStore(t.Context(), t)
	return auth.NewBasicAuthService(kvStore, crypt.NewSecretStore([]byte(secret)), authparams.ServiceCache{
		Enabled: false,
	}, logging.ContextUnavailable()), kvStore
}

func TestBasicAuthService_Users(t *testing.T) {
	ctx := t.Context()
	s, store := SetupService(t, secret)
	username := "testUser"

	// Get user not exists
	_, err := s.GetUser(ctx, username)
	require.ErrorIs(t, err, auth.ErrNotFound)

	// List users with no users
	listRes, _, err := s.ListUsers(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, 0, len(listRes))

	// Delete no user
	err = s.DeleteUser(ctx, username)
	require.ErrorIs(t, err, auth.ErrNotFound)

	user := &model.User{
		Username: username,
	}
	createRes, err := s.CreateUser(ctx, user)
	require.NoError(t, err)
	require.Equal(t, username, createRes)

	// Check get user
	getRes, err := s.GetUser(ctx, user.Username)
	require.NoError(t, err)
	require.Equal(t, user.Username, getRes.Username)

	// Check it is saved under the user's own key (not SuperAdminKey)
	_, err = store.Get(ctx, []byte(auth.BasicPartitionKey), model.UserPath(username))
	require.NoError(t, err)

	// List users
	listRes, _, err = s.ListUsers(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, 1, len(listRes))
	require.Equal(t, username, listRes[0].Username)

	// Create a second user (now supported)
	user2 := &model.User{Username: "testUser2"}
	_, err = s.CreateUser(ctx, user2)
	require.NoError(t, err)

	// List users should return 2
	listRes, _, err = s.ListUsers(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, 2, len(listRes))

	// Delete first user
	err = s.DeleteUser(ctx, username)
	require.NoError(t, err)

	// Check user key is deleted
	_, err = store.Get(ctx, []byte(auth.BasicPartitionKey), model.UserPath(username))
	require.ErrorIs(t, err, kv.ErrNotFound)

	// Second user still exists
	_, err = s.GetUser(ctx, "testUser2")
	require.NoError(t, err)

	// Clean up
	err = s.DeleteUser(ctx, "testUser2")
	require.NoError(t, err)
}

func TestBasicAuthService_Credentials(t *testing.T) {
	ctx := t.Context()
	s, _ := SetupService(t, secret)
	username := "testUser"
	accessKeyID := "SomeAccessKeyID"
	secretAccessKey := "SomeSecretAccessKey"

	// Get credentials no user
	_, err := s.GetCredentials(ctx, username)
	require.ErrorIs(t, err, auth.ErrNotFound)

	// Create credentials no user
	_, err = s.CreateCredentials(ctx, username)
	require.ErrorIs(t, err, auth.ErrNotFound)

	// Add credentials no user
	_, err = s.AddCredentials(ctx, username, accessKeyID, secretAccessKey)
	require.ErrorIs(t, err, auth.ErrNotFound)

	user := &model.User{
		Username: username,
	}
	createRes, err := s.CreateUser(ctx, user)
	require.NoError(t, err)
	require.Equal(t, username, createRes)

	// Get credentials (no creds)
	_, err = s.GetCredentials(ctx, accessKeyID)
	require.ErrorIs(t, err, auth.ErrNotFound)

	// Create credentials for user
	creds, err := s.CreateCredentials(ctx, username)
	require.NoError(t, err)

	// Get credentials
	_, err = s.GetCredentials(ctx, creds.AccessKeyID)
	require.NoError(t, err)

	// Add a second credential (now allowed, up to MaxCredentialsPerUser)
	creds2, err := s.AddCredentials(ctx, username, accessKeyID, secretAccessKey)
	require.NoError(t, err)
	require.Equal(t, accessKeyID, creds2.AccessKeyID)

	// Get both credentials
	_, err = s.GetCredentials(ctx, creds.AccessKeyID)
	require.NoError(t, err)
	_, err = s.GetCredentials(ctx, creds2.AccessKeyID)
	require.NoError(t, err)
}

func TestBasicAuthService_CredentialsImport(t *testing.T) {
	ctx := t.Context()
	s, store := SetupService(t, secret)
	username := "testUser"
	accessKeyID := "SomeAccessKeyID"
	secretAccessKey := "SomeSecretAccessKey"

	// Import credentials no user
	_, err := s.AddCredentials(ctx, username, accessKeyID, "")
	require.ErrorIs(t, err, auth.ErrNotFound)

	// Create users with creds under auth
	user := createOldUser(t, ctx, store, "user-old")
	createOldCreds(t, ctx, store, s, user.Username, accessKeyID, secretAccessKey)
	createOldCreds(t, ctx, store, s, user.Username, "A"+accessKeyID, "BadSecret")

	// Create a different user
	createRes, err := s.CreateUser(ctx, &model.User{
		Username: username,
	})
	require.NoError(t, err)
	require.Equal(t, username, createRes)

	// Try to import credentials of different user
	_, err = s.AddCredentials(ctx, username, accessKeyID, "")
	require.ErrorIs(t, err, auth.ErrNotFound)

	// Delete user and create the right one this time
	require.NoError(t, s.DeleteUser(ctx, username))
	_, err = s.CreateUser(ctx, &model.User{
		Username: user.Username,
	})
	require.NoError(t, err)

	// Import credentials not exist
	_, err = s.AddCredentials(ctx, user.Username, "NotExisting", "")
	require.ErrorIs(t, err, auth.ErrNotFound)

	// Import credentials
	credsResp, err := s.AddCredentials(ctx, user.Username, accessKeyID, "")
	require.NoError(t, err)
	require.Equal(t, accessKeyID, credsResp.AccessKeyID)
	require.Equal(t, secretAccessKey, credsResp.SecretAccessKey)

	// Import after exists - should return already exists error
	_, err = s.AddCredentials(ctx, user.Username, accessKeyID, "")
	require.ErrorIs(t, err, auth.ErrAlreadyExists)

	// Get credentials and verify
	getCred, err := s.GetCredentials(ctx, accessKeyID)
	require.NoError(t, err)
	require.Equal(t, accessKeyID, getCred.AccessKeyID)
	require.Equal(t, secretAccessKey, getCred.SecretAccessKey)
}

func TestBasicAuthService_Migrate(t *testing.T) {
	ctx := t.Context()
	accessKeyID := "SomeAccessKeyID"
	secretAccessKey := "SomeSecretAccessKey"

	t.Run("no users", func(t *testing.T) {
		s, _ := SetupService(t, secret)
		_, err := s.Migrate(ctx)
		require.ErrorIs(t, err, auth.ErrMigrationNotPossible)
	})

	t.Run("superadmin exists", func(t *testing.T) {
		s, store := SetupService(t, secret)

		expectedUser, err := s.CreateUser(ctx, &model.User{Username: "test"})
		require.NoError(t, err)

		// create a user for potential migration
		createOldUser(t, ctx, store, "unexpected")
		createOldCreds(t, ctx, store, s, "unexpected", accessKeyID, secretAccessKey)

		// Should not run migration flow
		username, err := s.Migrate(ctx)
		require.NoError(t, err)
		require.Equal(t, "", username) // No migration so username is empty

		// Verify user didn't change
		user, err := s.GetUser(ctx, expectedUser)
		require.NoError(t, err)
		require.Equal(t, expectedUser, user.Username)
	})

	t.Run("multiple users migration", func(t *testing.T) {
		s, store := SetupService(t, secret)

		// Create multiple users with credentials in old partition
		user1 := createOldUser(t, ctx, store, "user1")
		createOldCreds(t, ctx, store, s, user1.Username, "key1", "secret1")
		user2 := createOldUser(t, ctx, store, "user2")
		createOldCreds(t, ctx, store, s, user2.Username, "key2", "secret2")

		// Multi-user migration should succeed
		username, err := s.Migrate(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, username) // Returns last migrated username

		// Verify both users were migrated
		_, err = s.GetUser(ctx, "user1")
		require.NoError(t, err)
		_, err = s.GetUser(ctx, "user2")
		require.NoError(t, err)

		// Verify credentials were migrated
		creds1, err := s.GetCredentials(ctx, "key1")
		require.NoError(t, err)
		require.Equal(t, "user1", creds1.Username)
		creds2, err := s.GetCredentials(ctx, "key2")
		require.NoError(t, err)
		require.Equal(t, "user2", creds2.Username)
	})

	t.Run("multiple credentials migration", func(t *testing.T) {
		s, store := SetupService(t, secret)

		user := createOldUser(t, ctx, store, "user1")
		createOldCreds(t, ctx, store, s, user.Username, "key1", "secret1")
		createOldCreds(t, ctx, store, s, user.Username, "key2", "secret2")

		// Migration should succeed with multiple credentials
		username, err := s.Migrate(ctx)
		require.NoError(t, err)
		require.Equal(t, user.Username, username)

		// Verify both credentials were migrated
		creds1, err := s.GetCredentials(ctx, "key1")
		require.NoError(t, err)
		require.Equal(t, "user1", creds1.Username)
		creds2, err := s.GetCredentials(ctx, "key2")
		require.NoError(t, err)
		require.Equal(t, "user1", creds2.Username)
	})

	t.Run("successful migration", func(t *testing.T) {
		s, store := SetupService(t, secret)

		expectedUser := createOldUser(t, ctx, store, "old-user")
		createOldCreds(t, ctx, store, s, expectedUser.Username, accessKeyID, secretAccessKey)
		username, err := s.Migrate(ctx)
		require.NoError(t, err)
		require.Equal(t, expectedUser.Username, username)

		user, err := s.GetUser(ctx, expectedUser.Username)
		require.NoError(t, err)
		require.Equal(t, expectedUser.Username, user.Username)

		creds, err := s.GetCredentials(ctx, accessKeyID)
		require.NoError(t, err)
		require.Equal(t, creds.Username, expectedUser.Username)
		decryptedKey, err := model.DecryptSecret(s.SecretStore(), creds.SecretAccessKeyEncryptedBytes)
		require.NoError(t, err)
		require.Equal(t, secretAccessKey, decryptedKey)
	})
}

func createOldUser(t *testing.T, ctx context.Context, store kv.Store, username string) *model.UserData {
	t.Helper()
	user := &model.UserData{
		Username: username,
	}
	userData, err := proto.Marshal(user)
	require.NoError(t, err)
	require.NoError(t, store.Set(ctx, []byte(model.PartitionKey), model.UserPath(user.Username), userData))
	return user
}

func createOldCreds(t *testing.T, ctx context.Context, store kv.Store, s *auth.BasicAuthService, username, accessKeyID, secretAccessKey string) *model.CredentialData {
	t.Helper()
	encryptedKey, err := model.EncryptSecret(s.SecretStore(), secretAccessKey)
	require.NoError(t, err)
	creds := &model.CredentialData{
		AccessKeyId:                   accessKeyID,
		SecretAccessKeyEncryptedBytes: encryptedKey,
		UserId:                        []byte(username),
	}
	credsData, err := proto.Marshal(creds)
	require.NoError(t, err)
	require.NoError(t, store.Set(ctx, []byte(model.PartitionKey), model.CredentialPath(username, creds.AccessKeyId), credsData))
	return creds
}

// SetupServiceWithIAMAuth creates a BasicAuthService with IAM auth enabled
func SetupServiceWithIAMAuth(t *testing.T, secret string) (*auth.BasicAuthService, kv.Store) {
	t.Helper()
	kvStore := kvtest.GetStore(t.Context(), t)
	return auth.NewBasicAuthServiceWithIAMAuth(kvStore, crypt.NewSecretStore([]byte(secret)), authparams.ServiceCache{
		Enabled: false,
	}, logging.ContextUnavailable(), auth.IAMAuthConfig{
		Enabled:          true,
		DefaultUserGroup: "Developers",
	}), kvStore
}

func TestBasicAuthService_ExternalPrincipal_CreateSuccess(t *testing.T) {
	ctx := t.Context()
	s, _ := SetupServiceWithIAMAuth(t, secret)
	username := "testUser"

	// Create user first
	_, err := s.CreateUser(ctx, &model.User{Username: username})
	require.NoError(t, err)

	// Create external principal
	principalID := "arn:aws:iam::123456789012:role/TestRole"
	err = s.CreateUserExternalPrincipal(ctx, username, principalID)
	require.NoError(t, err)

	// Verify it exists
	ep, err := s.GetExternalPrincipal(ctx, principalID)
	require.NoError(t, err)
	require.Equal(t, principalID, ep.ID)
	require.Equal(t, username, ep.UserID)
}

func TestBasicAuthService_ExternalPrincipal_CreateUserNotFound(t *testing.T) {
	ctx := t.Context()
	s, _ := SetupServiceWithIAMAuth(t, secret)

	// Try to create external principal for non-existent user
	principalID := "arn:aws:iam::123456789012:role/TestRole"
	err := s.CreateUserExternalPrincipal(ctx, "nonexistent", principalID)
	require.ErrorIs(t, err, auth.ErrNotFound)
}

func TestBasicAuthService_ExternalPrincipal_CreateAlreadyExists(t *testing.T) {
	ctx := t.Context()
	s, _ := SetupServiceWithIAMAuth(t, secret)
	username := "testUser"

	// Create user first
	_, err := s.CreateUser(ctx, &model.User{Username: username})
	require.NoError(t, err)

	// Create external principal
	principalID := "arn:aws:iam::123456789012:role/TestRole"
	err = s.CreateUserExternalPrincipal(ctx, username, principalID)
	require.NoError(t, err)

	// Try to create the same principal again
	err = s.CreateUserExternalPrincipal(ctx, username, principalID)
	require.ErrorIs(t, err, auth.ErrAlreadyExists)
}

func TestBasicAuthService_ExternalPrincipal_DeleteSuccess(t *testing.T) {
	ctx := t.Context()
	s, _ := SetupServiceWithIAMAuth(t, secret)
	username := "testUser"

	// Create user and external principal
	_, err := s.CreateUser(ctx, &model.User{Username: username})
	require.NoError(t, err)

	principalID := "arn:aws:iam::123456789012:role/TestRole"
	err = s.CreateUserExternalPrincipal(ctx, username, principalID)
	require.NoError(t, err)

	// Delete external principal
	err = s.DeleteUserExternalPrincipal(ctx, username, principalID)
	require.NoError(t, err)

	// Verify it's gone
	_, err = s.GetExternalPrincipal(ctx, principalID)
	require.ErrorIs(t, err, auth.ErrNotFound)
}

func TestBasicAuthService_ExternalPrincipal_DeleteNotFound(t *testing.T) {
	ctx := t.Context()
	s, _ := SetupServiceWithIAMAuth(t, secret)
	username := "testUser"

	// Create user first
	_, err := s.CreateUser(ctx, &model.User{Username: username})
	require.NoError(t, err)

	// Try to delete non-existent principal
	err = s.DeleteUserExternalPrincipal(ctx, username, "arn:aws:iam::123456789012:role/NonExistent")
	require.ErrorIs(t, err, auth.ErrNotFound)
}

func TestBasicAuthService_ExternalPrincipal_GetSuccess(t *testing.T) {
	ctx := t.Context()
	s, _ := SetupServiceWithIAMAuth(t, secret)
	username := "testUser"

	// Create user and external principal
	_, err := s.CreateUser(ctx, &model.User{Username: username})
	require.NoError(t, err)

	principalID := "arn:aws:iam::123456789012:role/TestRole"
	err = s.CreateUserExternalPrincipal(ctx, username, principalID)
	require.NoError(t, err)

	// Get external principal
	ep, err := s.GetExternalPrincipal(ctx, principalID)
	require.NoError(t, err)
	require.Equal(t, principalID, ep.ID)
	require.Equal(t, username, ep.UserID)
}

func TestBasicAuthService_ExternalPrincipal_GetNotFound(t *testing.T) {
	ctx := t.Context()
	s, _ := SetupServiceWithIAMAuth(t, secret)

	// Try to get non-existent principal
	_, err := s.GetExternalPrincipal(ctx, "arn:aws:iam::123456789012:role/NonExistent")
	require.ErrorIs(t, err, auth.ErrNotFound)
}

func TestBasicAuthService_ExternalPrincipal_ListEmpty(t *testing.T) {
	ctx := t.Context()
	s, _ := SetupServiceWithIAMAuth(t, secret)
	username := "testUser"

	// Create user
	_, err := s.CreateUser(ctx, &model.User{Username: username})
	require.NoError(t, err)

	// List external principals (should be empty)
	principals, paginator, err := s.ListUserExternalPrincipals(ctx, username, &model.PaginationParams{Amount: 10})
	require.NoError(t, err)
	require.Empty(t, principals)
	require.NotNil(t, paginator)
	require.Equal(t, 0, paginator.Amount)
}

func TestBasicAuthService_ExternalPrincipal_ListMultiple(t *testing.T) {
	ctx := t.Context()
	s, _ := SetupServiceWithIAMAuth(t, secret)
	username := "testUser"

	// Create user
	_, err := s.CreateUser(ctx, &model.User{Username: username})
	require.NoError(t, err)

	// Create multiple external principals
	principals := []string{
		"arn:aws:iam::123456789012:role/Role1",
		"arn:aws:iam::123456789012:role/Role2",
		"arn:aws:iam::123456789012:role/Role3",
	}
	for _, pid := range principals {
		err = s.CreateUserExternalPrincipal(ctx, username, pid)
		require.NoError(t, err)
	}

	// List all external principals
	result, paginator, err := s.ListUserExternalPrincipals(ctx, username, &model.PaginationParams{Amount: 10})
	require.NoError(t, err)
	require.Len(t, result, 3)
	require.NotNil(t, paginator)
	require.Equal(t, 3, paginator.Amount)
}

func TestBasicAuthService_ExternalPrincipal_ListPagination(t *testing.T) {
	ctx := t.Context()
	s, _ := SetupServiceWithIAMAuth(t, secret)
	username := "testUser"

	// Create user
	_, err := s.CreateUser(ctx, &model.User{Username: username})
	require.NoError(t, err)

	// Create multiple external principals with simple IDs for predictable ordering
	principals := []string{
		"principal-a",
		"principal-b",
		"principal-c",
	}
	for _, pid := range principals {
		err = s.CreateUserExternalPrincipal(ctx, username, pid)
		require.NoError(t, err)
	}

	// List with pagination (page size 2) - should get first page
	result, paginator, err := s.ListUserExternalPrincipals(ctx, username, &model.PaginationParams{Amount: 2})
	require.NoError(t, err)
	require.Len(t, result, 2, "First page should have 2 items")
	require.NotEmpty(t, paginator.NextPageToken, "Should have next page token")

	// List all items (no pagination) to verify total count
	allResult, _, err := s.ListUserExternalPrincipals(ctx, username, &model.PaginationParams{Amount: 100})
	require.NoError(t, err)
	require.Len(t, allResult, 3, "Should have all 3 principals")

	// Verify all principals are present
	foundPrincipals := make(map[string]bool)
	for _, p := range allResult {
		foundPrincipals[p.ID] = true
	}
	for _, pid := range principals {
		require.True(t, foundPrincipals[pid], "Should have principal %s", pid)
	}
}

func TestBasicAuthService_IsExternalPrincipalsEnabled_Enabled(t *testing.T) {
	ctx := t.Context()
	s, _ := SetupServiceWithIAMAuth(t, secret)

	enabled := s.IsExternalPrincipalsEnabled(ctx)
	require.True(t, enabled)
}

func TestBasicAuthService_IsExternalPrincipalsEnabled_Disabled(t *testing.T) {
	ctx := t.Context()
	s, _ := SetupService(t, secret) // Uses default (IAM auth disabled)

	enabled := s.IsExternalPrincipalsEnabled(ctx)
	require.False(t, enabled)
}

func TestBasicAuthService_ExternalPrincipal_DisabledReturnsError(t *testing.T) {
	ctx := t.Context()
	s, _ := SetupService(t, secret) // Uses default (IAM auth disabled)
	username := "testUser"

	// Create user
	_, err := s.CreateUser(ctx, &model.User{Username: username})
	require.NoError(t, err)

	// All external principal operations should fail when IAM auth is disabled
	principalID := "arn:aws:iam::123456789012:role/TestRole"

	err = s.CreateUserExternalPrincipal(ctx, username, principalID)
	require.ErrorIs(t, err, auth.ErrNotImplemented)

	err = s.DeleteUserExternalPrincipal(ctx, username, principalID)
	require.ErrorIs(t, err, auth.ErrNotImplemented)

	_, err = s.GetExternalPrincipal(ctx, principalID)
	require.ErrorIs(t, err, auth.ErrNotImplemented)

	_, _, err = s.ListUserExternalPrincipals(ctx, username, &model.PaginationParams{Amount: 10})
	require.ErrorIs(t, err, auth.ErrNotImplemented)
}

func TestBasicAuthService_ExternalPrincipal_DeleteWrongUser(t *testing.T) {
	ctx := t.Context()
	s, _ := SetupServiceWithIAMAuth(t, secret)
	username := "testUser"
	otherUsername := "otherUser"

	// In basic auth mode, there's only one user (the admin)
	// So we test with a different scenario - delete with mismatched user
	_, err := s.CreateUser(ctx, &model.User{Username: username})
	require.NoError(t, err)

	principalID := "arn:aws:iam::123456789012:role/TestRole"
	err = s.CreateUserExternalPrincipal(ctx, username, principalID)
	require.NoError(t, err)

	// Try to delete with wrong user - should fail because user doesn't exist
	err = s.DeleteUserExternalPrincipal(ctx, otherUsername, principalID)
	require.ErrorIs(t, err, auth.ErrNotFound)
}
