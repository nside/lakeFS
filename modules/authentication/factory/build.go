package factory

import (
	"context"
	"fmt"

	"github.com/treeverse/lakefs/pkg/auth"
	authremote "github.com/treeverse/lakefs/pkg/auth/remoteauthenticator"
	"github.com/treeverse/lakefs/pkg/authentication"
	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/logging"
)

func NewAuthenticationService(_ context.Context, c config.Config, logger logging.Logger) (authentication.Service, error) {
	baseAuthCfg := c.AuthConfig().GetBaseAuthConfig()

	// If using external authentication API, use the API service
	if baseAuthCfg.IsAuthenticationTypeAPI() {
		return authentication.NewAPIService(
			baseAuthCfg.AuthenticationAPI.Endpoint,
			baseAuthCfg.CookieAuthVerification.ValidateIDTokenClaims,
			logger.WithField("service", "authentication_api"),
			baseAuthCfg.AuthenticationAPI.ExternalPrincipalsEnabled)
	}

	// If IAM authentication is enabled, use the basic authentication service
	if baseAuthCfg.IAMAuth.Enabled {
		stsConfig := authentication.STSValidatorConfig{
			ServerID:    baseAuthCfg.IAMAuth.ServerID,
			MaxTokenAge: baseAuthCfg.IAMAuth.MaxTokenAge,
		}
		authConfig := authentication.BasicAuthenticationServiceConfig{
			ServerID:           baseAuthCfg.IAMAuth.ServerID,
			AllowedARNPatterns: baseAuthCfg.IAMAuth.AllowedARNPatterns,
		}
		return authentication.NewBasicAuthenticationService(
			stsConfig,
			authConfig,
			logger.WithField("service", "basic_authentication"),
		), nil
	}

	return authentication.NewDummyService(), nil
}

func BuildAuthenticatorChain(c config.Config, logger logging.Logger, authService auth.Service) (auth.ChainAuthenticator, error) {
	authCfg := c.AuthConfig()
	baseAuthCfg := authCfg.GetBaseAuthConfig()
	authenticators := auth.ChainAuthenticator{
		auth.NewBuiltinAuthenticator(authService),
	}

	// remote authenticator setup
	if baseAuthCfg.RemoteAuthenticator.Enabled {
		remoteAuthenticator, err := authremote.NewAuthenticator(
			authremote.AuthenticatorConfig(baseAuthCfg.RemoteAuthenticator),
			authService,
			logger)
		if err != nil {
			return authenticators, fmt.Errorf("failed to create remote authenticator: %w", err)
		}

		authenticators = append(authenticators, remoteAuthenticator)
	}

	return authenticators, nil
}
