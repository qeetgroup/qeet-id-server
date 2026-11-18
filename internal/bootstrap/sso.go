package bootstrap

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
)

// platformSocialProviders are the platform-level (organization-less) social
// sign-ins for the console's own accounts whose credentials cfg sets; each is
// off until they are.
func platformSocialProviders(cfg *config.Config) []social.PlatformProvider {
	var providers []social.PlatformProvider
	if cfg.GoogleClientID != "" && cfg.GoogleClientSecret != "" {
		providers = append(providers, social.PlatformOIDC("google", cfg.GoogleClientID, cfg.GoogleClientSecret,
			"https://accounts.google.com/.well-known/openid-configuration"))
	}
	if cfg.MicrosoftClientID != "" && cfg.MicrosoftClientSecret != "" {
		// /common allows both work/school and personal Microsoft accounts.
		providers = append(providers, social.PlatformOIDC("microsoft", cfg.MicrosoftClientID, cfg.MicrosoftClientSecret,
			"https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"))
	}
	if cfg.GithubClientID != "" && cfg.GithubClientSecret != "" {
		providers = append(providers, social.PlatformGitHub(cfg.GithubClientID, cfg.GithubClientSecret)) // GitHub isn't OIDC — dedicated adapter
	}
	if cfg.AppleClientID != "" && cfg.AppleTeamID != "" && cfg.AppleKeyID != "" && cfg.ApplePrivateKey != "" {
		providers = append(providers, social.PlatformApple(cfg.AppleClientID, cfg.AppleTeamID, cfg.AppleKeyID, cfg.ApplePrivateKey))
	}
	return providers
}

// samlIdPIdentity returns the SAML IdP's signing key and certificate, PEM:
// the configured RSA key and certificate, or in dev, when unset, an ephemeral
// self-signed pair.
func samlIdPIdentity(cfg *config.Config) (keyPEM, certPEM string, err error) {
	if cfg.SAMLIdPKey != "" && cfg.SAMLIdPCert != "" {
		return cfg.SAMLIdPKey, cfg.SAMLIdPCert, nil
	}
	if !cfg.IsDev() {
		return "", "", errors.New("SAML_IDP_KEY and SAML_IDP_CERT are required outside dev (RSA private key + X.509 cert, PEM)")
	}
	keyPEM, certPEM, err = saml.GenerateIdPKeyPEM("Qeet ID SAML IdP")
	if err != nil {
		return "", "", fmt.Errorf("generate an ephemeral signing certificate: %w", err)
	}
	slog.Warn("SAML_IDP_KEY/SAML_IDP_CERT unset — generated an ephemeral SAML IdP signing cert; SPs must re-import IdP metadata after a restart (dev only)")
	return keyPEM, certPEM, nil
}
