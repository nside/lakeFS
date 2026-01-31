package authentication

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/sessions"
	"github.com/treeverse/lakefs/pkg/authentication/apiclient"
	"github.com/treeverse/lakefs/pkg/logging"
)

const (
	// IdentityTokenKey is the key used to extract the identity token from the request
	IdentityTokenKey = "identity_token"
)

// BasicAuthenticationServiceConfig holds configuration for the BasicAuthenticationService
type BasicAuthenticationServiceConfig struct {
	ServerID           string
	MaxTokenAge        string // duration string like "5m"
	AllowedARNPatterns []string
}

// BasicAuthenticationService implements authentication.Service for AWS IAM authentication
type BasicAuthenticationService struct {
	stsValidator *STSValidator
	logger       logging.Logger
	config       BasicAuthenticationServiceConfig
}

// NewBasicAuthenticationService creates a new BasicAuthenticationService
func NewBasicAuthenticationService(stsConfig STSValidatorConfig, authConfig BasicAuthenticationServiceConfig, logger logging.Logger) *BasicAuthenticationService {
	return &BasicAuthenticationService{
		stsValidator: NewSTSValidator(stsConfig, logger),
		logger:       logger.WithField("service", "basic_authentication"),
		config:       authConfig,
	}
}

// IsExternalPrincipalsEnabled returns true when IAM auth is enabled
func (s *BasicAuthenticationService) IsExternalPrincipalsEnabled() bool {
	return true
}

// ExternalPrincipalLogin validates an AWS IAM identity token and returns the external principal
func (s *BasicAuthenticationService) ExternalPrincipalLogin(ctx context.Context, identityRequest map[string]any) (*apiclient.ExternalPrincipal, error) {
	// Extract the identity token from the request
	identityTokenRaw, ok := identityRequest[IdentityTokenKey]
	if !ok {
		return nil, fmt.Errorf("missing %s in identity request: %w", IdentityTokenKey, ErrInvalidRequest)
	}

	identityToken, ok := identityTokenRaw.(string)
	if !ok {
		return nil, fmt.Errorf("identity token must be a string: %w", ErrInvalidRequest)
	}

	// Decode the base64-encoded identity token
	tokenBytes, err := base64.StdEncoding.DecodeString(identityToken)
	if err != nil {
		s.logger.WithError(err).Debug("Failed to decode identity token")
		return nil, fmt.Errorf("failed to decode identity token: %w", ErrInvalidTokenFormat)
	}

	// Parse the AWSIdentityTokenInfo
	var tokenInfo AWSIdentityTokenInfo
	if err := json.Unmarshal(tokenBytes, &tokenInfo); err != nil {
		s.logger.WithError(err).Debug("Failed to parse identity token")
		return nil, fmt.Errorf("failed to parse identity token: %w", ErrInvalidTokenFormat)
	}

	// Validate the token using STS
	identity, err := s.stsValidator.Validate(ctx, &tokenInfo)
	if err != nil {
		s.logger.WithError(err).Debug("STS validation failed")
		return nil, fmt.Errorf("STS validation failed: %w", ErrExternalLoginFailed)
	}

	// Check if the ARN matches allowed patterns (if configured)
	if len(s.config.AllowedARNPatterns) > 0 {
		if !s.isARNAllowed(identity.ARN) {
			s.logger.WithField("arn", identity.ARN).Debug("ARN not in allowed patterns")
			return nil, fmt.Errorf("ARN not authorized: %w", ErrInsufficientPermissions)
		}
	}

	s.logger.WithField("arn", identity.ARN).Debug("External principal login successful")

	// Return the external principal with the ARN as the ID
	return &apiclient.ExternalPrincipal{
		Id: identity.ARN,
	}, nil
}

// isARNAllowed checks if the ARN matches any of the allowed patterns
func (s *BasicAuthenticationService) isARNAllowed(arn string) bool {
	for _, pattern := range s.config.AllowedARNPatterns {
		if matchARNPattern(arn, pattern) {
			return true
		}
	}
	return false
}

// matchARNPattern checks if an ARN matches a pattern
// Supports simple wildcards: * matches any sequence of characters
func matchARNPattern(arn, pattern string) bool {
	// Simple wildcard matching
	if pattern == "*" {
		return true
	}

	// Check for prefix match with wildcard at end
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(arn) >= len(prefix) && arn[:len(prefix)] == prefix
	}

	// Exact match
	return arn == pattern
}

// ValidateSTS is not used for basic IAM auth, returns not implemented
func (s *BasicAuthenticationService) ValidateSTS(_ context.Context, _, _, _ string) (string, error) {
	return "", ErrNotImplemented
}

// RegisterAdditionalRoutes is a no-op for basic auth service
func (s *BasicAuthenticationService) RegisterAdditionalRoutes(_ *chi.Mux, _ sessions.Store) {
	s.logger.Trace("no additional routes to register for basic authentication service")
}

// OauthCallback is not supported for basic IAM auth
func (s *BasicAuthenticationService) OauthCallback(w http.ResponseWriter, r *http.Request, _ sessions.Store) {
	s.logger.Warn("OAuth callback not supported for basic authentication service")
	http.Redirect(w, r, "/auth/login", http.StatusNotImplemented)
}
