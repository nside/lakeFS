package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/treeverse/lakefs/pkg/auth/crypt"
	"github.com/treeverse/lakefs/pkg/auth/keys"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/params"
	"github.com/treeverse/lakefs/pkg/kv"
	"github.com/treeverse/lakefs/pkg/logging"
	"google.golang.org/protobuf/proto"
)

const (
	BasicPartitionKey     = "basicAuth"
	SuperAdminKey         = "superAdmin" // Legacy key, kept for migration
	MaxCredentialsPerUser = 10           // Allow multiple credentials per user
)

// IAMAuthConfig holds configuration for IAM authentication
type IAMAuthConfig struct {
	Enabled          bool
	DefaultUserGroup string
}

type BasicAuthService struct {
	store                     kv.Store
	secretStore               crypt.SecretStore
	cache                     Cache
	log                       logging.Logger
	iamAuthEnabled            bool
	iamAuthDefaultUserGroup   string
}

func NewBasicAuthService(store kv.Store, secretStore crypt.SecretStore, cacheConf params.ServiceCache, logger logging.Logger) *BasicAuthService {
	return NewBasicAuthServiceWithIAMAuth(store, secretStore, cacheConf, logger, IAMAuthConfig{})
}

func NewBasicAuthServiceWithIAMAuth(store kv.Store, secretStore crypt.SecretStore, cacheConf params.ServiceCache, logger logging.Logger, iamConfig IAMAuthConfig) *BasicAuthService {
	logger.Info("initialized Auth service")
	var cache Cache
	if cacheConf.Enabled {
		cache = NewLRUCache(cacheConf.Size, cacheConf.TTL, cacheConf.Jitter)
	} else {
		cache = &DummyCache{}
	}
	res := &BasicAuthService{
		store:                   store,
		secretStore:             secretStore,
		cache:                   cache,
		log:                     logger,
		iamAuthEnabled:          iamConfig.Enabled,
		iamAuthDefaultUserGroup: iamConfig.DefaultUserGroup,
	}
	return res
}

func (s *BasicAuthService) IsAdvancedAuth() bool {
	return false
}

// Migrate tries to perform migration of existing lakeFS server to basic auth
func (s *BasicAuthService) Migrate(ctx context.Context) (string, error) {
	// Check if we already have users in the new partition
	existingUsers, _, err := s.ListUsers(ctx, &model.PaginationParams{Amount: 1})
	if err != nil {
		return "", err
	}
	if len(existingUsers) > 0 {
		// Already have users, no migration needed
		return "", nil
	}

	// No users in the new partition - try to migrate from old partition
	users, err := s.listUserForMigration(ctx)
	if err != nil {
		return "", err
	}

	if len(users) == 0 {
		return "", fmt.Errorf("no users configured: %w", ErrMigrationNotPossible)
	}

	// Migrate all users and their credentials
	var lastUsername string
	for _, user := range users {
		// Try to import credentials for each user
		creds, credErr := s.listUserCredentials(ctx, user.Username, model.PartitionKey, "")
		if credErr != nil {
			s.log.WithError(credErr).WithField("username", user.Username).Warn("failed to list credentials for migration")
			continue
		}
		// Create the user first
		lastUsername, err = s.CreateUser(ctx, user)
		if err != nil {
			return "", fmt.Errorf("failed to create user %s: %w", user.Username, err)
		}
		// Import credentials
		for _, cred := range creds {
			_, err = s.addCredentials(ctx, user.Username, cred.AccessKeyID, cred.SecretAccessKey)
			if err != nil {
				s.log.WithError(err).WithField("username", user.Username).Warn("failed to import credential")
			}
		}
	}
	return lastUsername, nil
}

func (s *BasicAuthService) listUserForMigration(ctx context.Context) ([]*model.User, error) {
	var userData model.UserData
	usersKey := model.UserPath("")
	// Using old partition key to get users from pre-basic auth installation
	it, err := kv.NewPrimaryIterator(ctx, s.store, (&userData).ProtoReflect().Type(), model.PartitionKey, usersKey, kv.IteratorOptionsAfter([]byte("")))
	if err != nil {
		return nil, fmt.Errorf("create iterator: %w", err)
	}
	defer it.Close()

	entries := make([]proto.Message, 0)
	for it.Next() {
		entry := it.Entry()
		value := entry.Value
		entries = append(entries, value)
	}
	if err = it.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}

	users := model.ConvertUsersDataList(entries)
	return users, nil
}

func (s *BasicAuthService) Authorize(ctx context.Context, req *AuthorizationRequest) (*AuthorizationResponse, error) {
	_, err := s.GetUser(ctx, req.Username)
	if err != nil {
		return nil, err
	}

	// If user exists - single admin user - allow
	return &AuthorizationResponse{Allowed: true}, nil
}

func (s *BasicAuthService) GetUser(ctx context.Context, username string) (*model.User, error) {
	return s.cache.GetUser(UserKey{Username: username}, func() (*model.User, error) {
		userKey := model.UserPath(username)
		m := model.UserData{}
		_, err := kv.GetMsg(ctx, s.store, BasicPartitionKey, userKey, &m)
		if err != nil {
			if errors.Is(err, kv.ErrNotFound) {
				return nil, fmt.Errorf("user %s: %w", username, ErrNotFound)
			}
			return nil, fmt.Errorf("get user %s: %w", username, err)
		}
		return model.UserFromProto(&m), nil
	})
}

// getFirstUser returns the first user in the system (for backward compatibility)
func (s *BasicAuthService) getFirstUser(ctx context.Context) (*model.User, error) {
	users, _, err := s.ListUsers(ctx, &model.PaginationParams{Amount: 1})
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, ErrNotFound
	}
	return users[0], nil
}

func (s *BasicAuthService) CreateUser(ctx context.Context, user *model.User) (string, error) {
	if err := model.ValidateAuthEntityID(user.Username); err != nil {
		return InvalidUserID, err
	}
	userKey := model.UserPath(user.Username)

	err := kv.SetMsgIf(ctx, s.store, BasicPartitionKey, userKey, model.ProtoFromUser(user), nil)
	if err != nil {
		if errors.Is(err, kv.ErrPredicateFailed) {
			err = ErrAlreadyExists
		}
		return "", fmt.Errorf("failed to create user (%s): %w", user.Username, err)
	}
	return user.Username, err
}

func (s *BasicAuthService) DeleteUser(ctx context.Context, username string) error {
	if _, err := s.GetUser(ctx, username); err != nil {
		return err
	}

	// Delete user external principals first
	if s.iamAuthEnabled {
		if err := s.deleteUserExternalPrincipals(ctx, username); err != nil {
			s.log.WithError(err).WithField("username", username).Warn("failed to delete user external principals")
		}
	}

	// Delete user credentials
	if err := s.deleteUserCredentials(ctx, username, BasicPartitionKey, ""); err != nil {
		return fmt.Errorf("delete user credentials (%s): %w", username, err)
	}

	// Delete the user
	userPath := model.UserPath(username)
	if err := s.store.Delete(ctx, []byte(BasicPartitionKey), userPath); err != nil {
		return fmt.Errorf("delete user (%s): %w", username, err)
	}

	return nil
}

// deleteUserExternalPrincipals deletes all external principals for a user
func (s *BasicAuthService) deleteUserExternalPrincipals(ctx context.Context, userID string) error {
	principals, _, err := s.ListUserExternalPrincipals(ctx, userID, &model.PaginationParams{Amount: -1})
	if err != nil {
		if errors.Is(err, ErrNotImplemented) {
			return nil
		}
		return err
	}
	for _, p := range principals {
		if err := s.DeleteUserExternalPrincipal(ctx, userID, p.ID); err != nil {
			return err
		}
	}
	return nil
}

func (s *BasicAuthService) ListUsers(ctx context.Context, params *model.PaginationParams) ([]*model.User, *model.Paginator, error) {
	if params == nil {
		params = &model.PaginationParams{}
	}

	var userData model.UserData
	usersPrefix := model.UserPath("")

	it, err := kv.NewPrimaryIterator(ctx, s.store, (&userData).ProtoReflect().Type(), BasicPartitionKey, usersPrefix, kv.IteratorOptionsAfter([]byte(params.After)))
	if err != nil {
		return nil, nil, fmt.Errorf("create iterator: %w", err)
	}
	defer it.Close()

	amount := params.Amount
	if amount <= 0 {
		amount = 1000 // reasonable max
	}

	users := make([]*model.User, 0)
	for it.Next() {
		if len(users) >= amount {
			break
		}
		entry := it.Entry()
		userData, ok := entry.Value.(*model.UserData)
		if !ok {
			continue
		}
		users = append(users, model.UserFromProto(userData))
	}
	if err := it.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate users: %w", err)
	}

	paginator := &model.Paginator{Amount: len(users)}
	if len(users) >= amount {
		paginator.NextPageToken = users[len(users)-1].Username
	}

	return users, paginator, nil
}

func (s *BasicAuthService) GetCredentials(ctx context.Context, accessKeyID string) (*model.Credential, error) {
	return s.cache.GetCredential(accessKeyID, func() (*model.Credential, error) {
		// First, try to find via the credentials index
		indexPath := credentialsIndexPath(accessKeyID)
		var idx kv.SecondaryIndex
		_, err := kv.GetMsg(ctx, s.store, BasicPartitionKey, indexPath, &idx)
		if err != nil {
			if errors.Is(err, kv.ErrNotFound) {
				return nil, fmt.Errorf("credentials %w", ErrNotFound)
			}
			return nil, fmt.Errorf("get credentials index: %w", err)
		}

		// Fetch the actual credential using the primary key
		c := model.CredentialData{}
		_, err = kv.GetMsg(ctx, s.store, BasicPartitionKey, idx.PrimaryKey, &c)
		if err != nil {
			if errors.Is(err, kv.ErrNotFound) {
				return nil, fmt.Errorf("credentials %w", ErrNotFound)
			}
			return nil, fmt.Errorf("get credentials: %w", err)
		}
		return model.CredentialFromProto(s.secretStore, &c)
	})
}

// credentialsIndexPath returns the path for the credentials secondary index
func credentialsIndexPath(accessKeyID string) []byte {
	return []byte(kv.FormatPath("credentialsIndex", accessKeyID))
}

func (s *BasicAuthService) GetCredentialsForUser(ctx context.Context, username, accessKeyID string) (*model.Credential, error) {
	if _, err := s.GetUser(ctx, username); err != nil {
		return nil, err
	}
	return s.GetCredentials(ctx, accessKeyID)
}

func (s *BasicAuthService) CreateCredentials(ctx context.Context, username string) (*model.Credential, error) {
	accessKeyID := keys.GenAccessKeyID()
	secretAccessKey := keys.GenSecretAccessKey()
	user, err := s.GetUser(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.AddCredentials(ctx, user.Username, accessKeyID, secretAccessKey)
}

func (s *BasicAuthService) AddCredentials(ctx context.Context, username, accessKeyID, secretAccessKey string) (*model.Credential, error) {
	_, err := s.GetUser(ctx, username)
	if err != nil {
		return nil, err
	}

	currCreds, err := s.listUserCredentials(ctx, username, BasicPartitionKey, "")
	if err != nil {
		return nil, err
	}
	if len(currCreds) >= MaxCredentialsPerUser {
		return nil, fmt.Errorf("exceeded number of allowed credentials (%d): %w", MaxCredentialsPerUser, ErrInvalidRequest)
	}

	// Handle user import flow from previous auth service
	if accessKeyID != "" && secretAccessKey == "" {
		return s.importUserCredentials(ctx, username, accessKeyID)
	}

	return s.addCredentials(ctx, username, accessKeyID, secretAccessKey)
}

func (s *BasicAuthService) importUserCredentials(ctx context.Context, username, accessKeyID string) (*model.Credential, error) {
	creds, err := s.listUserCredentials(ctx, username, model.PartitionKey, accessKeyID)
	if err != nil {
		return nil, err
	}
	switch len(creds) {
	case 0:
		return nil, fmt.Errorf("no credentials found for user (%s): %w", username, ErrNotFound)
	case 1:
		return s.addCredentials(ctx, username, creds[0].AccessKeyID, creds[0].SecretAccessKey)
	default: // more than 1 credential for user
		return nil, fmt.Errorf("too many credentials for user (%s): %w", username, ErrInvalidRequest)
	}
}

func (s *BasicAuthService) addCredentials(ctx context.Context, username, accessKeyID, secretAccessKey string) (*model.Credential, error) {
	encryptedKey, err := model.EncryptSecret(s.secretStore, secretAccessKey)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	c := &model.Credential{
		BaseCredential: model.BaseCredential{
			AccessKeyID:                   accessKeyID,
			SecretAccessKey:               secretAccessKey,
			SecretAccessKeyEncryptedBytes: encryptedKey,
			IssuedDate:                    now,
		},
		Username: username,
	}

	// Store the credential under the user's path
	credentialsKey := model.CredentialPath(username, c.AccessKeyID)
	err = kv.SetMsgIf(ctx, s.store, BasicPartitionKey, credentialsKey, model.ProtoFromCredential(c), nil)
	if err != nil {
		if errors.Is(err, kv.ErrPredicateFailed) {
			err = ErrAlreadyExists
		}
		return nil, fmt.Errorf("save credentials (credentialsKey %s): %w", credentialsKey, err)
	}

	// Create a secondary index for looking up credentials by accessKeyID
	indexPath := credentialsIndexPath(c.AccessKeyID)
	err = kv.SetMsgIf(ctx, s.store, BasicPartitionKey, indexPath, &kv.SecondaryIndex{PrimaryKey: credentialsKey}, nil)
	if err != nil {
		// Try to rollback the primary credential
		_ = s.store.Delete(ctx, []byte(BasicPartitionKey), credentialsKey)
		if errors.Is(err, kv.ErrPredicateFailed) {
			err = ErrAlreadyExists
		}
		return nil, fmt.Errorf("save credentials index: %w", err)
	}

	return c, nil
}

func (s *BasicAuthService) deleteUserCredentials(ctx context.Context, username, partition, prefix string) error {
	var credential model.CredentialData
	credentialsKey := model.CredentialPath(username, "")
	var (
		it  kv.MessageIterator
		err error
	)
	it, err = kv.NewPrimaryIterator(ctx, s.store, (&credential).ProtoReflect().Type(), partition, credentialsKey, kv.IteratorOptionsFrom([]byte(prefix)))
	if err != nil {
		return fmt.Errorf("create iterator: %w", err)
	}
	defer it.Close()

	for it.Next() {
		entry := it.Entry()
		credData, ok := entry.Value.(*model.CredentialData)
		if ok && credData.AccessKeyId != "" {
			// Delete the secondary index
			indexPath := credentialsIndexPath(credData.AccessKeyId)
			_ = s.store.Delete(ctx, []byte(partition), indexPath)
		}
		if err = s.store.Delete(ctx, []byte(partition), entry.Key); err != nil {
			return fmt.Errorf("delete credentials: %w", err)
		}
	}
	if err = it.Err(); err != nil {
		return fmt.Errorf("iterate credentials: %w", err)
	}

	return nil
}

func (s *BasicAuthService) listUserCredentials(ctx context.Context, username, partition, prefix string) ([]*model.Credential, error) {
	var credential model.CredentialData
	credentialsKey := model.CredentialPath(username, prefix)
	var (
		it  kv.MessageIterator
		err error
	)
	it, err = kv.NewPrimaryIterator(ctx, s.store, (&credential).ProtoReflect().Type(), partition, credentialsKey, kv.IteratorOptionsAfter([]byte("")))
	if err != nil {
		return nil, fmt.Errorf("create iterator: %w", err)
	}
	defer it.Close()

	entries := make([]proto.Message, 0)
	for len(entries) <= MaxCredentialsPerUser && it.Next() {
		entry := it.Entry()
		value := entry.Value
		entries = append(entries, value)
	}
	if err = it.Err(); err != nil {
		return nil, fmt.Errorf("iterate credentials: %w", err)
	}

	creds, err := model.ConvertCredDataList(s.secretStore, entries, true)
	if err != nil {
		return nil, err
	}
	return creds, nil
}

func (s *BasicAuthService) Cache() Cache {
	return s.cache
}

func (s *BasicAuthService) SecretStore() crypt.SecretStore {
	return s.secretStore
}

func (s *BasicAuthService) GetUserByID(_ context.Context, _ string) (*model.User, error) {
	return nil, ErrNotImplemented
}

func (s *BasicAuthService) GetUserByExternalID(_ context.Context, _ string) (*model.User, error) {
	return nil, ErrNotImplemented
}

func (s *BasicAuthService) GetUserByEmail(_ context.Context, _ string) (*model.User, error) {
	return nil, ErrNotImplemented
}

func (s *BasicAuthService) UpdateUserFriendlyName(_ context.Context, _ string, _ string) error {
	return ErrNotImplemented
}

func (s *BasicAuthService) IsExternalPrincipalsEnabled(_ context.Context) bool {
	return s.iamAuthEnabled
}

func (s *BasicAuthService) CreateUserExternalPrincipal(ctx context.Context, userID, principalID string) error {
	if !s.iamAuthEnabled {
		return ErrNotImplemented
	}

	// Verify the user exists
	_, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}

	// Check if principal already exists
	existingPrincipal, err := s.GetExternalPrincipal(ctx, principalID)
	if err == nil && existingPrincipal != nil {
		return fmt.Errorf("external principal %s: %w", principalID, ErrAlreadyExists)
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}

	// Create the external principal
	ep := &model.ExternalPrincipal{
		ID:     principalID,
		UserID: userID,
	}

	// Store the external principal (primary index by principal ID)
	principalPath := model.ExternalPrincipalPath(principalID)
	err = kv.SetMsgIf(ctx, s.store, BasicPartitionKey, principalPath, model.ProtoFromExternalPrincipal(ep), nil)
	if err != nil {
		if errors.Is(err, kv.ErrPredicateFailed) {
			return fmt.Errorf("external principal %s: %w", principalID, ErrAlreadyExists)
		}
		return fmt.Errorf("create external principal: %w", err)
	}

	// Create secondary index (user -> principal)
	userPrincipalPath := model.UserExternalPrincipalPath(userID, principalID)
	err = kv.SetMsgIf(ctx, s.store, BasicPartitionKey, userPrincipalPath, &kv.SecondaryIndex{PrimaryKey: principalPath}, nil)
	if err != nil {
		// Try to rollback the primary entry
		_ = s.store.Delete(ctx, []byte(BasicPartitionKey), principalPath)
		return fmt.Errorf("create user external principal index: %w", err)
	}

	s.log.WithFields(logging.Fields{
		"user_id":      userID,
		"principal_id": principalID,
	}).Info("created external principal")

	return nil
}

func (s *BasicAuthService) DeleteUserExternalPrincipal(ctx context.Context, userID, principalID string) error {
	if !s.iamAuthEnabled {
		return ErrNotImplemented
	}

	// Verify the external principal exists and belongs to the user
	ep, err := s.GetExternalPrincipal(ctx, principalID)
	if err != nil {
		return err
	}
	if ep.UserID != userID {
		return fmt.Errorf("external principal %s does not belong to user %s: %w", principalID, userID, ErrNotFound)
	}

	// Delete the secondary index
	userPrincipalPath := model.UserExternalPrincipalPath(userID, principalID)
	if err := s.store.Delete(ctx, []byte(BasicPartitionKey), userPrincipalPath); err != nil && !errors.Is(err, kv.ErrNotFound) {
		return fmt.Errorf("delete user external principal index: %w", err)
	}

	// Delete the primary entry
	principalPath := model.ExternalPrincipalPath(principalID)
	if err := s.store.Delete(ctx, []byte(BasicPartitionKey), principalPath); err != nil {
		return fmt.Errorf("delete external principal: %w", err)
	}

	s.log.WithFields(logging.Fields{
		"user_id":      userID,
		"principal_id": principalID,
	}).Info("deleted external principal")

	return nil
}

func (s *BasicAuthService) GetExternalPrincipal(ctx context.Context, principalID string) (*model.ExternalPrincipal, error) {
	if !s.iamAuthEnabled {
		return nil, ErrNotImplemented
	}

	principalPath := model.ExternalPrincipalPath(principalID)
	m := model.ExternalPrincipalData{}
	_, err := kv.GetMsg(ctx, s.store, BasicPartitionKey, principalPath, &m)
	if err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return nil, fmt.Errorf("external principal %s: %w", principalID, ErrNotFound)
		}
		return nil, fmt.Errorf("get external principal: %w", err)
	}

	return model.ExternalPrincipalFromProto(&m), nil
}

func (s *BasicAuthService) ListUserExternalPrincipals(ctx context.Context, userID string, params *model.PaginationParams) ([]*model.ExternalPrincipal, *model.Paginator, error) {
	if !s.iamAuthEnabled {
		return nil, nil, ErrNotImplemented
	}
	if params == nil {
		params = &model.PaginationParams{}
	}

	// Verify the user exists
	_, err := s.GetUser(ctx, userID)
	if err != nil {
		return nil, nil, err
	}

	// List external principals for this user using the secondary index
	// The secondary iterator will automatically fetch the primary data for each entry
	var primaryType model.ExternalPrincipalData
	userPrincipalPrefix := model.UserExternalPrincipalPath(userID, "")
	it, err := kv.NewSecondaryIterator(ctx, s.store, (&primaryType).ProtoReflect().Type(), BasicPartitionKey, userPrincipalPrefix, []byte(params.After))
	if err != nil {
		return nil, nil, fmt.Errorf("create iterator: %w", err)
	}
	defer it.Close()

	principals := make([]*model.ExternalPrincipal, 0)
	for it.Next() {
		if params.Amount > 0 && len(principals) >= params.Amount {
			break
		}

		entry := it.Entry()
		epData, ok := entry.Value.(*model.ExternalPrincipalData)
		if !ok {
			continue
		}

		principals = append(principals, model.ExternalPrincipalFromProto(epData))
	}

	if err := it.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate external principals: %w", err)
	}

	paginator := &model.Paginator{Amount: len(principals)}
	if params.Amount > 0 && len(principals) >= params.Amount {
		paginator.NextPageToken = principals[len(principals)-1].ID
	}

	return principals, paginator, nil
}

func (s *BasicAuthService) CreateGroup(_ context.Context, _ *model.Group) (*model.Group, error) {
	return nil, ErrNotImplemented
}

func (s *BasicAuthService) DeleteGroup(_ context.Context, _ string) error {
	return ErrNotImplemented
}

func (s *BasicAuthService) GetGroup(_ context.Context, _ string) (*model.Group, error) {
	return nil, ErrNotImplemented
}

func (s *BasicAuthService) ListGroups(_ context.Context, _ *model.PaginationParams) ([]*model.Group, *model.Paginator, error) {
	return nil, nil, ErrNotImplemented
}

func (s *BasicAuthService) AddUserToGroup(_ context.Context, _, _ string) error {
	return ErrNotImplemented
}

func (s *BasicAuthService) RemoveUserFromGroup(_ context.Context, _, _ string) error {
	return ErrNotImplemented
}

func (s *BasicAuthService) ListUserGroups(_ context.Context, _ string, _ *model.PaginationParams) ([]*model.Group, *model.Paginator, error) {
	return nil, nil, ErrNotImplemented
}

func (s *BasicAuthService) ListGroupUsers(_ context.Context, _ string, _ *model.PaginationParams) ([]*model.User, *model.Paginator, error) {
	return nil, nil, ErrNotImplemented
}

func (s *BasicAuthService) WritePolicy(_ context.Context, _ *model.Policy, _ bool) error {
	return ErrNotImplemented
}

func (s *BasicAuthService) GetPolicy(_ context.Context, _ string) (*model.Policy, error) {
	return nil, ErrNotImplemented
}

func (s *BasicAuthService) DeletePolicy(_ context.Context, _ string) error {
	return ErrNotImplemented
}

func (s *BasicAuthService) ListPolicies(_ context.Context, _ *model.PaginationParams) ([]*model.Policy, *model.Paginator, error) {
	return nil, nil, ErrNotImplemented
}

func (s *BasicAuthService) DeleteCredentials(_ context.Context, _, _ string) error {
	return ErrNotImplemented
}

func (s *BasicAuthService) ListUserCredentials(_ context.Context, _ string, _ *model.PaginationParams) ([]*model.Credential, *model.Paginator, error) {
	return nil, nil, ErrNotImplemented
}

func (s *BasicAuthService) AttachPolicyToUser(_ context.Context, _, _ string) error {
	return ErrNotImplemented
}

func (s *BasicAuthService) DetachPolicyFromUser(_ context.Context, _, _ string) error {
	return ErrNotImplemented
}

func (s *BasicAuthService) ListUserPolicies(_ context.Context, _ string, _ *model.PaginationParams) ([]*model.Policy, *model.Paginator, error) {
	return nil, nil, ErrNotImplemented
}

func (s *BasicAuthService) ListEffectivePolicies(_ context.Context, _ string, _ *model.PaginationParams) ([]*model.Policy, *model.Paginator, error) {
	return nil, nil, ErrNotImplemented
}

func (s *BasicAuthService) AttachPolicyToGroup(_ context.Context, _, _ string) error {
	return ErrNotImplemented
}

func (s *BasicAuthService) DetachPolicyFromGroup(_ context.Context, _, _ string) error {
	return ErrNotImplemented
}

func (s *BasicAuthService) ListGroupPolicies(context.Context, string, *model.PaginationParams) ([]*model.Policy, *model.Paginator, error) {
	return nil, nil, ErrNotImplemented
}

func (s *BasicAuthService) ClaimTokenIDOnce(_ context.Context, _ string, _ int64) error {
	return ErrNotImplemented
}
