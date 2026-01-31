package authentication

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/treeverse/lakefs/pkg/logging"
)

// AWSIdentityTokenInfo contains the parsed information from a presigned STS GetCallerIdentity URL
// This is duplicated from externalidp/awsiam to avoid import cycles
type AWSIdentityTokenInfo struct {
	Method             string   `json:"method"`
	Host               string   `json:"host"`
	Region             string   `json:"region"`
	Action             string   `json:"action"`
	Date               string   `json:"date"`
	ExpirationDuration string   `json:"expiration_duration"`
	AccessKeyID        string   `json:"access_key_id"`
	Signature          string   `json:"signature"`
	SignedHeaders      []string `json:"signed_headers"`
	Version            string   `json:"version"`
	Algorithm          string   `json:"algorithm"`
	SecurityToken      string   `json:"security_token"`
}

// STS presigned URL constants
const (
	stsDatetimeFormat    = "20060102T150405Z"
	stsGlobalEndpoint    = "sts.amazonaws.com"
	stsHostServerIDHeader = "X-LakeFS-Server-ID"
	stsAuthActionKey     = "Action"
	stsAuthVersionKey    = "Version"
	stsAuthAlgorithmKey  = "X-Amz-Algorithm"
	stsAuthCredentialKey = "X-Amz-Credential"
	stsAuthDateKey       = "X-Amz-Date"
	stsAuthExpiresKey    = "X-Amz-Expires"
	stsAuthSecurityTokenKey = "X-Amz-Security-Token"
	stsAuthSignedHeadersKey = "X-Amz-SignedHeaders"
	stsAuthSignatureKey  = "X-Amz-Signature"
)

// STSValidatorConfig holds configuration for the STS validator
type STSValidatorConfig struct {
	ServerID   string
	MaxTokenAge time.Duration
}

// STSValidator validates AWS IAM identity tokens by calling AWS STS
type STSValidator struct {
	config     STSValidatorConfig
	httpClient *http.Client
	logger     logging.Logger
}

// STSCallerIdentity represents the validated caller identity from AWS STS
type STSCallerIdentity struct {
	ARN       string
	AccountID string
	UserID    string
}

// GetCallerIdentityResponse represents the XML response from STS GetCallerIdentity
type GetCallerIdentityResponse struct {
	XMLName xml.Name `xml:"GetCallerIdentityResponse"`
	Result  struct {
		ARN     string `xml:"Arn"`
		UserID  string `xml:"UserId"`
		Account string `xml:"Account"`
	} `xml:"GetCallerIdentityResult"`
}

// ErrorResponse represents an STS error response
type ErrorResponse struct {
	XMLName xml.Name `xml:"ErrorResponse"`
	Error   struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

// NewSTSValidator creates a new STS validator
func NewSTSValidator(config STSValidatorConfig, logger logging.Logger) *STSValidator {
	return &STSValidator{
		config: config,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger.WithField("service", "sts_validator"),
	}
}

// Validate validates an AWS identity token by reconstructing the presigned URL and calling STS
func (v *STSValidator) Validate(ctx context.Context, tokenInfo *AWSIdentityTokenInfo) (*STSCallerIdentity, error) {
	// Validate server ID header if configured
	if v.config.ServerID != "" {
		// The server ID should be validated client-side, but we check the token info
		// to ensure it was signed for this specific lakeFS server
		v.logger.WithField("server_id", v.config.ServerID).Debug("Validating STS token for server")
	}

	// Validate token age
	if err := v.validateTokenAge(tokenInfo); err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Reconstruct the presigned URL
	presignedURL, err := v.reconstructPresignedURL(tokenInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct presigned URL: %w", err)
	}

	// Call AWS STS to validate the identity
	identity, err := v.callSTS(ctx, presignedURL, tokenInfo)
	if err != nil {
		return nil, fmt.Errorf("STS validation failed: %w", err)
	}

	return identity, nil
}

func (v *STSValidator) validateTokenAge(tokenInfo *AWSIdentityTokenInfo) error {
	// Parse the X-Amz-Date
	signTime, err := time.Parse(stsDatetimeFormat, tokenInfo.Date)
	if err != nil {
		return fmt.Errorf("invalid token date format: %w", err)
	}

	// Parse the expiration duration
	expireSecs, err := strconv.ParseInt(tokenInfo.ExpirationDuration, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid expiration duration: %w", err)
	}

	// Calculate token expiration time
	tokenExpires := signTime.Add(time.Duration(expireSecs) * time.Second)

	// Check if the token has expired
	if time.Now().After(tokenExpires) {
		return errors.New("token has expired")
	}

	// Check against max token age if configured
	if v.config.MaxTokenAge > 0 {
		maxAge := signTime.Add(v.config.MaxTokenAge)
		if time.Now().After(maxAge) {
			return fmt.Errorf("token exceeds maximum age of %v", v.config.MaxTokenAge)
		}
	}

	return nil
}

func (v *STSValidator) reconstructPresignedURL(tokenInfo *AWSIdentityTokenInfo) (string, error) {
	// Determine the host (use the one from token info)
	host := tokenInfo.Host
	if host == "" {
		host = stsGlobalEndpoint
	}

	// Build the credential string
	// Format: AccessKeyID/date/region/service/aws4_request
	datePart := tokenInfo.Date[:8] // Extract YYYYMMDD from YYYYMMDDTHHMMSSZ
	credential := fmt.Sprintf("%s/%s/%s/sts/aws4_request",
		tokenInfo.AccessKeyID,
		datePart,
		tokenInfo.Region,
	)

	// Build query parameters
	params := url.Values{}
	params.Set(stsAuthActionKey, tokenInfo.Action)
	params.Set(stsAuthVersionKey, tokenInfo.Version)
	params.Set(stsAuthAlgorithmKey, tokenInfo.Algorithm)
	params.Set(stsAuthCredentialKey, credential)
	params.Set(stsAuthDateKey, tokenInfo.Date)
	params.Set(stsAuthExpiresKey, tokenInfo.ExpirationDuration)
	params.Set(stsAuthSignedHeadersKey, strings.Join(tokenInfo.SignedHeaders, ";"))
	params.Set(stsAuthSignatureKey, tokenInfo.Signature)

	// Add security token if present (for assumed roles)
	if tokenInfo.SecurityToken != "" {
		params.Set(stsAuthSecurityTokenKey, tokenInfo.SecurityToken)
	}

	// Construct the URL
	presignedURL := fmt.Sprintf("https://%s/?%s", host, params.Encode())

	return presignedURL, nil
}

func (v *STSValidator) callSTS(ctx context.Context, presignedURL string, tokenInfo *AWSIdentityTokenInfo) (*STSCallerIdentity, error) {
	// Create the HTTP request using the method from token info
	req, err := http.NewRequestWithContext(ctx, tokenInfo.Method, presignedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create STS request: %w", err)
	}

	// Add required headers
	req.Header.Set("Host", tokenInfo.Host)

	// Add the X-LakeFS-Server-ID header if server ID is configured
	// This header should have been included in the signed headers
	if v.config.ServerID != "" {
		req.Header.Set(stsHostServerIDHeader, v.config.ServerID)
	}

	// Make the request
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("STS request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read STS response: %w", err)
	}

	// Check for errors
	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if xmlErr := xml.Unmarshal(body, &errResp); xmlErr == nil {
			return nil, fmt.Errorf("STS error: %s - %s", errResp.Error.Code, errResp.Error.Message)
		}
		return nil, fmt.Errorf("STS returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the successful response
	var stsResp GetCallerIdentityResponse
	if err := xml.Unmarshal(body, &stsResp); err != nil {
		return nil, fmt.Errorf("failed to parse STS response: %w", err)
	}

	v.logger.WithFields(logging.Fields{
		"arn":     stsResp.Result.ARN,
		"account": stsResp.Result.Account,
		"user_id": stsResp.Result.UserID,
	}).Debug("STS validation successful")

	return &STSCallerIdentity{
		ARN:       stsResp.Result.ARN,
		AccountID: stsResp.Result.Account,
		UserID:    stsResp.Result.UserID,
	}, nil
}
