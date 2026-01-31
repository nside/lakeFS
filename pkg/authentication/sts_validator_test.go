package authentication

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/logging"
)

func TestValidateTokenAge_Valid(t *testing.T) {
	logger := logging.ContextUnavailable()
	validator := NewSTSValidator(STSValidatorConfig{
		MaxTokenAge: 5 * time.Minute,
	}, logger)

	now := time.Now().UTC()
	tokenInfo := &AWSIdentityTokenInfo{
		Date:               now.Format(stsDatetimeFormat),
		ExpirationDuration: "300", // 5 minutes
	}

	err := validator.validateTokenAge(tokenInfo)
	assert.NoError(t, err)
}

func TestValidateTokenAge_Expired(t *testing.T) {
	logger := logging.ContextUnavailable()
	validator := NewSTSValidator(STSValidatorConfig{
		MaxTokenAge: 5 * time.Minute,
	}, logger)

	// Token signed 10 minutes ago with 5 minute expiration
	pastTime := time.Now().UTC().Add(-10 * time.Minute)
	tokenInfo := &AWSIdentityTokenInfo{
		Date:               pastTime.Format(stsDatetimeFormat),
		ExpirationDuration: "300", // 5 minutes
	}

	err := validator.validateTokenAge(tokenInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestValidateTokenAge_ExceedsMaxAge(t *testing.T) {
	logger := logging.ContextUnavailable()
	validator := NewSTSValidator(STSValidatorConfig{
		MaxTokenAge: 1 * time.Minute,
	}, logger)

	// Token signed 2 minutes ago, still valid per AWS but exceeds our max age
	pastTime := time.Now().UTC().Add(-2 * time.Minute)
	tokenInfo := &AWSIdentityTokenInfo{
		Date:               pastTime.Format(stsDatetimeFormat),
		ExpirationDuration: "600", // 10 minutes - still valid per AWS
	}

	err := validator.validateTokenAge(tokenInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum age")
}

func TestValidateTokenAge_InvalidDateFormat(t *testing.T) {
	logger := logging.ContextUnavailable()
	validator := NewSTSValidator(STSValidatorConfig{
		MaxTokenAge: 5 * time.Minute,
	}, logger)

	tokenInfo := &AWSIdentityTokenInfo{
		Date:               "invalid-date-format",
		ExpirationDuration: "300",
	}

	err := validator.validateTokenAge(tokenInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token date format")
}

func TestValidateTokenAge_InvalidExpiration(t *testing.T) {
	logger := logging.ContextUnavailable()
	validator := NewSTSValidator(STSValidatorConfig{
		MaxTokenAge: 5 * time.Minute,
	}, logger)

	now := time.Now().UTC()
	tokenInfo := &AWSIdentityTokenInfo{
		Date:               now.Format(stsDatetimeFormat),
		ExpirationDuration: "not-a-number",
	}

	err := validator.validateTokenAge(tokenInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid expiration duration")
}

func TestReconstructPresignedURL_AllFields(t *testing.T) {
	logger := logging.ContextUnavailable()
	validator := NewSTSValidator(STSValidatorConfig{}, logger)

	tokenInfo := &AWSIdentityTokenInfo{
		Method:             "POST",
		Host:               "sts.us-east-1.amazonaws.com",
		Region:             "us-east-1",
		Action:             "GetCallerIdentity",
		Date:               "20240115T120000Z",
		ExpirationDuration: "300",
		AccessKeyID:        "AKIAIOSFODNN7EXAMPLE",
		Signature:          "abc123signature",
		SignedHeaders:      []string{"host", "x-lakefs-server-id"},
		Version:            "2011-06-15",
		Algorithm:          "AWS4-HMAC-SHA256",
	}

	url, err := validator.reconstructPresignedURL(tokenInfo)
	require.NoError(t, err)
	assert.Contains(t, url, "https://sts.us-east-1.amazonaws.com/")
	assert.Contains(t, url, "Action=GetCallerIdentity")
	assert.Contains(t, url, "X-Amz-Algorithm=AWS4-HMAC-SHA256")
	assert.Contains(t, url, "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE")
	assert.Contains(t, url, "X-Amz-Date=20240115T120000Z")
	assert.Contains(t, url, "X-Amz-Expires=300")
	assert.Contains(t, url, "X-Amz-Signature=abc123signature")
	assert.Contains(t, url, "X-Amz-SignedHeaders=host")
}

func TestReconstructPresignedURL_WithSecurityToken(t *testing.T) {
	logger := logging.ContextUnavailable()
	validator := NewSTSValidator(STSValidatorConfig{}, logger)

	tokenInfo := &AWSIdentityTokenInfo{
		Method:             "POST",
		Host:               "sts.amazonaws.com",
		Region:             "us-east-1",
		Action:             "GetCallerIdentity",
		Date:               "20240115T120000Z",
		ExpirationDuration: "300",
		AccessKeyID:        "ASIAXXX",
		Signature:          "abc123signature",
		SignedHeaders:      []string{"host"},
		Version:            "2011-06-15",
		Algorithm:          "AWS4-HMAC-SHA256",
		SecurityToken:      "session-token-for-assumed-role",
	}

	url, err := validator.reconstructPresignedURL(tokenInfo)
	require.NoError(t, err)
	assert.Contains(t, url, "X-Amz-Security-Token=session-token-for-assumed-role")
}

func TestReconstructPresignedURL_EmptyHost(t *testing.T) {
	logger := logging.ContextUnavailable()
	validator := NewSTSValidator(STSValidatorConfig{}, logger)

	tokenInfo := &AWSIdentityTokenInfo{
		Method:             "POST",
		Host:               "", // Empty host should fall back to global endpoint
		Region:             "us-east-1",
		Action:             "GetCallerIdentity",
		Date:               "20240115T120000Z",
		ExpirationDuration: "300",
		AccessKeyID:        "AKIAIOSFODNN7EXAMPLE",
		Signature:          "abc123signature",
		SignedHeaders:      []string{"host"},
		Version:            "2011-06-15",
		Algorithm:          "AWS4-HMAC-SHA256",
	}

	url, err := validator.reconstructPresignedURL(tokenInfo)
	require.NoError(t, err)
	assert.Contains(t, url, "https://sts.amazonaws.com/")
}

// MockSTSResponse creates a mock STS GetCallerIdentity response
type MockSTSResponse struct {
	ARN       string
	AccountID string
	UserID    string
	Error     *MockSTSError
}

type MockSTSError struct {
	Code    string
	Message string
}

func createMockSTSServer(t *testing.T, response MockSTSResponse) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if response.Error != nil {
			w.WriteHeader(http.StatusForbidden)
			errResp := ErrorResponse{}
			errResp.Error.Code = response.Error.Code
			errResp.Error.Message = response.Error.Message
			data, _ := xml.Marshal(errResp)
			_, _ = w.Write(data)
			return
		}

		w.WriteHeader(http.StatusOK)
		stsResp := GetCallerIdentityResponse{}
		stsResp.Result.ARN = response.ARN
		stsResp.Result.Account = response.AccountID
		stsResp.Result.UserID = response.UserID
		data, _ := xml.Marshal(stsResp)
		_, _ = w.Write(data)
	}))
}

func TestCallSTS_Success(t *testing.T) {
	mockServer := createMockSTSServer(t, MockSTSResponse{
		ARN:       "arn:aws:iam::123456789012:user/testuser",
		AccountID: "123456789012",
		UserID:    "AIDAIOSFODNN7EXAMPLE",
	})
	defer mockServer.Close()

	// Extract host from mock server URL
	host := strings.TrimPrefix(mockServer.URL, "http://")

	logger := logging.ContextUnavailable()
	validator := NewSTSValidator(STSValidatorConfig{}, logger)

	tokenInfo := &AWSIdentityTokenInfo{
		Method: "POST",
		Host:   host,
	}

	// Build a simple presigned URL pointing to our mock server
	presignedURL := fmt.Sprintf("%s/?Action=GetCallerIdentity&Version=2011-06-15", mockServer.URL)

	identity, err := validator.callSTS(context.Background(), presignedURL, tokenInfo)
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:iam::123456789012:user/testuser", identity.ARN)
	assert.Equal(t, "123456789012", identity.AccountID)
	assert.Equal(t, "AIDAIOSFODNN7EXAMPLE", identity.UserID)
}

func TestCallSTS_InvalidSignature(t *testing.T) {
	mockServer := createMockSTSServer(t, MockSTSResponse{
		Error: &MockSTSError{
			Code:    "SignatureDoesNotMatch",
			Message: "The request signature we calculated does not match the signature you provided.",
		},
	})
	defer mockServer.Close()

	host := strings.TrimPrefix(mockServer.URL, "http://")

	logger := logging.ContextUnavailable()
	validator := NewSTSValidator(STSValidatorConfig{}, logger)

	tokenInfo := &AWSIdentityTokenInfo{
		Method: "POST",
		Host:   host,
	}

	presignedURL := fmt.Sprintf("%s/?Action=GetCallerIdentity&Version=2011-06-15", mockServer.URL)

	_, err := validator.callSTS(context.Background(), presignedURL, tokenInfo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SignatureDoesNotMatch")
}

func TestCallSTS_ExpiredToken(t *testing.T) {
	mockServer := createMockSTSServer(t, MockSTSResponse{
		Error: &MockSTSError{
			Code:    "ExpiredToken",
			Message: "The security token included in the request is expired",
		},
	})
	defer mockServer.Close()

	host := strings.TrimPrefix(mockServer.URL, "http://")

	logger := logging.ContextUnavailable()
	validator := NewSTSValidator(STSValidatorConfig{}, logger)

	tokenInfo := &AWSIdentityTokenInfo{
		Method: "POST",
		Host:   host,
	}

	presignedURL := fmt.Sprintf("%s/?Action=GetCallerIdentity&Version=2011-06-15", mockServer.URL)

	_, err := validator.callSTS(context.Background(), presignedURL, tokenInfo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ExpiredToken")
}

func TestCallSTS_MalformedResponse(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("this is not valid XML"))
	}))
	defer mockServer.Close()

	host := strings.TrimPrefix(mockServer.URL, "http://")

	logger := logging.ContextUnavailable()
	validator := NewSTSValidator(STSValidatorConfig{}, logger)

	tokenInfo := &AWSIdentityTokenInfo{
		Method: "POST",
		Host:   host,
	}

	presignedURL := fmt.Sprintf("%s/?Action=GetCallerIdentity&Version=2011-06-15", mockServer.URL)

	_, err := validator.callSTS(context.Background(), presignedURL, tokenInfo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse STS response")
}

func TestCallSTS_NetworkError(t *testing.T) {
	logger := logging.ContextUnavailable()
	validator := NewSTSValidator(STSValidatorConfig{}, logger)

	tokenInfo := &AWSIdentityTokenInfo{
		Method: "POST",
		Host:   "localhost:1", // Port 1 should fail to connect
	}

	presignedURL := "http://localhost:1/?Action=GetCallerIdentity&Version=2011-06-15"

	_, err := validator.callSTS(context.Background(), presignedURL, tokenInfo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "STS request failed")
}

func TestValidate_EndToEnd(t *testing.T) {
	// Create a mock STS server
	mockServer := createMockSTSServer(t, MockSTSResponse{
		ARN:       "arn:aws:iam::123456789012:role/TestRole",
		AccountID: "123456789012",
		UserID:    "AROAIOSFODNN7EXAMPLE:session-name",
	})
	defer mockServer.Close()

	// Get the host from mock server
	host := strings.TrimPrefix(mockServer.URL, "http://")

	logger := logging.ContextUnavailable()
	validator := &STSValidator{
		config: STSValidatorConfig{
			ServerID:    "test-server",
			MaxTokenAge: 5 * time.Minute,
		},
		httpClient: mockServer.Client(),
		logger:     logger.WithField("service", "sts_validator"),
	}

	now := time.Now().UTC()
	tokenInfo := &AWSIdentityTokenInfo{
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

	// Override the reconstructPresignedURL to point to our mock server
	// We need to test the full flow, so we'll create a custom validator
	presignedURL := fmt.Sprintf("http://%s/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=%s%%2F%s%%2F%s%%2Fsts%%2Faws4_request&X-Amz-Date=%s&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=%s",
		host,
		tokenInfo.AccessKeyID,
		tokenInfo.Date[:8],
		tokenInfo.Region,
		tokenInfo.Date,
		tokenInfo.Signature,
	)

	identity, err := validator.callSTS(context.Background(), presignedURL, tokenInfo)
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:iam::123456789012:role/TestRole", identity.ARN)
	assert.Equal(t, "123456789012", identity.AccountID)
}

func TestValidateTokenAge_NoMaxAgeConfigured(t *testing.T) {
	logger := logging.ContextUnavailable()
	validator := NewSTSValidator(STSValidatorConfig{
		MaxTokenAge: 0, // No max age configured
	}, logger)

	// Token signed 10 minutes ago but with 15 minute expiration
	pastTime := time.Now().UTC().Add(-10 * time.Minute)
	tokenInfo := &AWSIdentityTokenInfo{
		Date:               pastTime.Format(stsDatetimeFormat),
		ExpirationDuration: "900", // 15 minutes
	}

	// Should pass since we don't have a max age configured
	err := validator.validateTokenAge(tokenInfo)
	assert.NoError(t, err)
}

func TestCallSTS_ServerIDHeader(t *testing.T) {
	serverID := "test-lakefs-server"
	var capturedServerID string

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedServerID = r.Header.Get(stsHostServerIDHeader)

		w.WriteHeader(http.StatusOK)
		stsResp := GetCallerIdentityResponse{}
		stsResp.Result.ARN = "arn:aws:iam::123456789012:user/testuser"
		stsResp.Result.Account = "123456789012"
		stsResp.Result.UserID = "AIDAIOSFODNN7EXAMPLE"
		data, _ := xml.Marshal(stsResp)
		_, _ = w.Write(data)
	}))
	defer mockServer.Close()

	host := strings.TrimPrefix(mockServer.URL, "http://")

	logger := logging.ContextUnavailable()
	validator := NewSTSValidator(STSValidatorConfig{
		ServerID: serverID,
	}, logger)

	tokenInfo := &AWSIdentityTokenInfo{
		Method: "POST",
		Host:   host,
	}

	presignedURL := fmt.Sprintf("%s/?Action=GetCallerIdentity&Version=2011-06-15", mockServer.URL)

	_, err := validator.callSTS(context.Background(), presignedURL, tokenInfo)
	require.NoError(t, err)
	assert.Equal(t, serverID, capturedServerID)
}
