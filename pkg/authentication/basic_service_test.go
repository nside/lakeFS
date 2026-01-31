package authentication

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/logging"
)

func createValidTokenInfo(t *testing.T, host string) string {
	t.Helper()
	now := time.Now().UTC()
	tokenInfo := AWSIdentityTokenInfo{
		Method:             "POST",
		Host:               host,
		Region:             "us-east-1",
		Action:             "GetCallerIdentity",
		Date:               now.Format(stsDatetimeFormat),
		ExpirationDuration: "300",
		AccessKeyID:        "AKIAIOSFODNN7EXAMPLE",
		Signature:          "test-signature",
		SignedHeaders:      []string{"host"},
		Version:            "2011-06-15",
		Algorithm:          "AWS4-HMAC-SHA256",
	}
	data, err := json.Marshal(tokenInfo)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(data)
}

func createExpiredTokenInfo(t *testing.T) string {
	t.Helper()
	// Token signed 10 minutes ago with 5 minute expiration
	pastTime := time.Now().UTC().Add(-10 * time.Minute)
	tokenInfo := AWSIdentityTokenInfo{
		Method:             "POST",
		Host:               "sts.amazonaws.com",
		Region:             "us-east-1",
		Action:             "GetCallerIdentity",
		Date:               pastTime.Format(stsDatetimeFormat),
		ExpirationDuration: "300", // 5 minutes
		AccessKeyID:        "AKIAIOSFODNN7EXAMPLE",
		Signature:          "test-signature",
		SignedHeaders:      []string{"host"},
		Version:            "2011-06-15",
		Algorithm:          "AWS4-HMAC-SHA256",
	}
	data, err := json.Marshal(tokenInfo)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(data)
}

// createMockTLSSTSServer creates a TLS mock server that can handle the HTTPS requests
func createMockTLSSTSServer(t *testing.T, arn, accountID, userID string) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		stsResp := GetCallerIdentityResponse{}
		stsResp.Result.ARN = arn
		stsResp.Result.Account = accountID
		stsResp.Result.UserID = userID
		data, _ := xml.Marshal(stsResp)
		_, _ = w.Write(data)
	}))
	return server
}

func TestExternalPrincipalLogin_ValidToken(t *testing.T) {
	mockServer := createMockTLSSTSServer(t,
		"arn:aws:iam::123456789012:user/testuser",
		"123456789012",
		"AIDAIOSFODNN7EXAMPLE",
	)
	defer mockServer.Close()

	// Extract host from TLS server (starts with https://)
	host := strings.TrimPrefix(mockServer.URL, "https://")
	token := createValidTokenInfo(t, host)

	logger := logging.ContextUnavailable()
	service := NewBasicAuthenticationService(
		STSValidatorConfig{MaxTokenAge: 5 * time.Minute},
		BasicAuthenticationServiceConfig{},
		logger,
	)

	// Use the TLS client from the mock server (with certificate verification disabled)
	service.stsValidator.httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		Timeout: 10 * time.Second,
	}

	result, err := service.ExternalPrincipalLogin(context.Background(), map[string]any{
		IdentityTokenKey: token,
	})

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "arn:aws:iam::123456789012:user/testuser", result.Id)
}

func TestExternalPrincipalLogin_MissingToken(t *testing.T) {
	logger := logging.ContextUnavailable()
	service := NewBasicAuthenticationService(
		STSValidatorConfig{},
		BasicAuthenticationServiceConfig{},
		logger,
	)

	_, err := service.ExternalPrincipalLogin(context.Background(), map[string]any{
		"some_other_key": "value",
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidRequest)
}

func TestExternalPrincipalLogin_InvalidBase64(t *testing.T) {
	logger := logging.ContextUnavailable()
	service := NewBasicAuthenticationService(
		STSValidatorConfig{},
		BasicAuthenticationServiceConfig{},
		logger,
	)

	_, err := service.ExternalPrincipalLogin(context.Background(), map[string]any{
		IdentityTokenKey: "not-valid-base64!@#$%",
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidTokenFormat)
}

func TestExternalPrincipalLogin_InvalidJSON(t *testing.T) {
	logger := logging.ContextUnavailable()
	service := NewBasicAuthenticationService(
		STSValidatorConfig{},
		BasicAuthenticationServiceConfig{},
		logger,
	)

	// Valid base64 but not valid JSON
	invalidToken := base64.StdEncoding.EncodeToString([]byte("this is not json"))

	_, err := service.ExternalPrincipalLogin(context.Background(), map[string]any{
		IdentityTokenKey: invalidToken,
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidTokenFormat)
}

func TestExternalPrincipalLogin_STSValidationFails(t *testing.T) {
	// Create a TLS server that returns an error
	mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		errResp := ErrorResponse{}
		errResp.Error.Code = "SignatureDoesNotMatch"
		errResp.Error.Message = "Signature mismatch"
		data, _ := xml.Marshal(errResp)
		_, _ = w.Write(data)
	}))
	defer mockServer.Close()

	host := strings.TrimPrefix(mockServer.URL, "https://")
	token := createValidTokenInfo(t, host)

	logger := logging.ContextUnavailable()
	service := NewBasicAuthenticationService(
		STSValidatorConfig{MaxTokenAge: 5 * time.Minute},
		BasicAuthenticationServiceConfig{},
		logger,
	)
	service.stsValidator.httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		Timeout: 10 * time.Second,
	}

	_, err := service.ExternalPrincipalLogin(context.Background(), map[string]any{
		IdentityTokenKey: token,
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrExternalLoginFailed)
}

func TestExternalPrincipalLogin_TokenNotString(t *testing.T) {
	logger := logging.ContextUnavailable()
	service := NewBasicAuthenticationService(
		STSValidatorConfig{},
		BasicAuthenticationServiceConfig{},
		logger,
	)

	_, err := service.ExternalPrincipalLogin(context.Background(), map[string]any{
		IdentityTokenKey: 12345, // Not a string
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidRequest)
}

func TestMatchARNPattern_Wildcard(t *testing.T) {
	tests := []struct {
		name     string
		arn      string
		pattern  string
		expected bool
	}{
		{
			name:     "wildcard matches any ARN",
			arn:      "arn:aws:iam::123456789012:role/MyRole",
			pattern:  "*",
			expected: true,
		},
		{
			name:     "wildcard matches empty string",
			arn:      "",
			pattern:  "*",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchARNPattern(tt.arn, tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchARNPattern_PrefixWildcard(t *testing.T) {
	tests := []struct {
		name     string
		arn      string
		pattern  string
		expected bool
	}{
		{
			name:     "prefix with wildcard matches",
			arn:      "arn:aws:iam::123456789012:role/LakeFSUser-Admin",
			pattern:  "arn:aws:iam::123456789012:role/LakeFSUser*",
			expected: true,
		},
		{
			name:     "prefix with wildcard does not match different prefix",
			arn:      "arn:aws:iam::123456789012:role/OtherRole",
			pattern:  "arn:aws:iam::123456789012:role/LakeFSUser*",
			expected: false,
		},
		{
			name:     "prefix with wildcard matches exact prefix",
			arn:      "arn:aws:iam::123456789012:role/LakeFSUser",
			pattern:  "arn:aws:iam::123456789012:role/LakeFSUser*",
			expected: true,
		},
		{
			name:     "prefix wildcard with account",
			arn:      "arn:aws:iam::123456789012:user/john",
			pattern:  "arn:aws:iam::123456789012:*",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchARNPattern(tt.arn, tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchARNPattern_ExactMatch(t *testing.T) {
	tests := []struct {
		name     string
		arn      string
		pattern  string
		expected bool
	}{
		{
			name:     "exact match succeeds",
			arn:      "arn:aws:iam::123456789012:role/MyRole",
			pattern:  "arn:aws:iam::123456789012:role/MyRole",
			expected: true,
		},
		{
			name:     "different ARN fails",
			arn:      "arn:aws:iam::123456789012:role/MyRole",
			pattern:  "arn:aws:iam::123456789012:role/OtherRole",
			expected: false,
		},
		{
			name:     "different account fails",
			arn:      "arn:aws:iam::123456789012:role/MyRole",
			pattern:  "arn:aws:iam::999999999999:role/MyRole",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchARNPattern(tt.arn, tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchARNPattern_NoMatch(t *testing.T) {
	tests := []struct {
		name    string
		arn     string
		pattern string
	}{
		{
			name:    "completely different ARN",
			arn:     "arn:aws:iam::123456789012:role/MyRole",
			pattern: "arn:aws:sts::123456789012:assumed-role/OtherRole/session",
		},
		{
			name:    "empty pattern does not match",
			arn:     "arn:aws:iam::123456789012:role/MyRole",
			pattern: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchARNPattern(tt.arn, tt.pattern)
			assert.False(t, result)
		})
	}
}

func TestIsARNAllowed_EmptyPatterns(t *testing.T) {
	logger := logging.ContextUnavailable()
	service := NewBasicAuthenticationService(
		STSValidatorConfig{},
		BasicAuthenticationServiceConfig{
			AllowedARNPatterns: []string{}, // Empty patterns
		},
		logger,
	)

	// With empty patterns, isARNAllowed should return false (no patterns to match)
	result := service.isARNAllowed("arn:aws:iam::123456789012:role/MyRole")
	assert.False(t, result)
}

func TestIsARNAllowed_MultiplePatterns(t *testing.T) {
	logger := logging.ContextUnavailable()
	service := NewBasicAuthenticationService(
		STSValidatorConfig{},
		BasicAuthenticationServiceConfig{
			AllowedARNPatterns: []string{
				"arn:aws:iam::111111111111:role/*",
				"arn:aws:iam::222222222222:role/SpecificRole",
				"arn:aws:iam::333333333333:*",
			},
		},
		logger,
	)

	tests := []struct {
		name     string
		arn      string
		expected bool
	}{
		{
			name:     "matches first pattern",
			arn:      "arn:aws:iam::111111111111:role/AnyRole",
			expected: true,
		},
		{
			name:     "matches second pattern exactly",
			arn:      "arn:aws:iam::222222222222:role/SpecificRole",
			expected: true,
		},
		{
			name:     "matches third pattern",
			arn:      "arn:aws:iam::333333333333:user/john",
			expected: true,
		},
		{
			name:     "does not match any pattern",
			arn:      "arn:aws:iam::999999999999:role/SomeRole",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.isARNAllowed(tt.arn)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsARNAllowed_NoMatch(t *testing.T) {
	logger := logging.ContextUnavailable()
	service := NewBasicAuthenticationService(
		STSValidatorConfig{},
		BasicAuthenticationServiceConfig{
			AllowedARNPatterns: []string{
				"arn:aws:iam::123456789012:role/AllowedRole*",
			},
		},
		logger,
	)

	result := service.isARNAllowed("arn:aws:iam::123456789012:role/DeniedRole")
	assert.False(t, result)
}

func TestIsExternalPrincipalsEnabled(t *testing.T) {
	logger := logging.ContextUnavailable()
	service := NewBasicAuthenticationService(
		STSValidatorConfig{},
		BasicAuthenticationServiceConfig{},
		logger,
	)

	// BasicAuthenticationService always returns true for IsExternalPrincipalsEnabled
	assert.True(t, service.IsExternalPrincipalsEnabled())
}

func TestExternalPrincipalLogin_WithAllowedARNPatterns(t *testing.T) {
	mockServer := createMockTLSSTSServer(t,
		"arn:aws:iam::123456789012:role/AllowedRole",
		"123456789012",
		"AROAIOSFODNN7EXAMPLE:session",
	)
	defer mockServer.Close()

	host := strings.TrimPrefix(mockServer.URL, "https://")
	token := createValidTokenInfo(t, host)

	logger := logging.ContextUnavailable()
	service := NewBasicAuthenticationService(
		STSValidatorConfig{MaxTokenAge: 5 * time.Minute},
		BasicAuthenticationServiceConfig{
			AllowedARNPatterns: []string{"arn:aws:iam::123456789012:role/Allowed*"},
		},
		logger,
	)
	service.stsValidator.httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		Timeout: 10 * time.Second,
	}

	result, err := service.ExternalPrincipalLogin(context.Background(), map[string]any{
		IdentityTokenKey: token,
	})

	require.NoError(t, err)
	assert.Equal(t, "arn:aws:iam::123456789012:role/AllowedRole", result.Id)
}

func TestExternalPrincipalLogin_ARNNotAllowed(t *testing.T) {
	mockServer := createMockTLSSTSServer(t,
		"arn:aws:iam::123456789012:role/DeniedRole",
		"123456789012",
		"AROAIOSFODNN7EXAMPLE:session",
	)
	defer mockServer.Close()

	host := strings.TrimPrefix(mockServer.URL, "https://")
	token := createValidTokenInfo(t, host)

	logger := logging.ContextUnavailable()
	service := NewBasicAuthenticationService(
		STSValidatorConfig{MaxTokenAge: 5 * time.Minute},
		BasicAuthenticationServiceConfig{
			AllowedARNPatterns: []string{"arn:aws:iam::123456789012:role/Allowed*"},
		},
		logger,
	)
	service.stsValidator.httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		Timeout: 10 * time.Second,
	}

	_, err := service.ExternalPrincipalLogin(context.Background(), map[string]any{
		IdentityTokenKey: token,
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInsufficientPermissions)
}

func TestValidateSTS_NotImplemented(t *testing.T) {
	logger := logging.ContextUnavailable()
	service := NewBasicAuthenticationService(
		STSValidatorConfig{},
		BasicAuthenticationServiceConfig{},
		logger,
	)

	_, err := service.ValidateSTS(context.Background(), "code", "redirect", "state")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotImplemented)
}
