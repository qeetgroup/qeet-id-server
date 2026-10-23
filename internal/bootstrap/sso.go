package bootstrap

import (
	"log/slog"
	"os"

	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
)

// setPlatformSocialProviders enables the platform-level (tenant-less) social
// sign-ins whose credentials cfg sets.
func setPlatformSocialProviders(socialService *social.Service, cfg *config.Config) {
	// Platform-level (tenant-less) social login for the console's own accounts.
	// Off until credentials are set; Google only for now.
	if cfg.GoogleClientID != "" && cfg.GoogleClientSecret != "" {
		socialService.SetPlatformProvider("google", cfg.GoogleClientID, cfg.GoogleClientSecret,
			"https://accounts.google.com/.well-known/openid-configuration")
	}
	if cfg.MicrosoftClientID != "" && cfg.MicrosoftClientSecret != "" {
		// /common allows both work/school and personal Microsoft accounts.
		socialService.SetPlatformProvider("microsoft", cfg.MicrosoftClientID, cfg.MicrosoftClientSecret,
			"https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration")
	}
	if cfg.GithubClientID != "" && cfg.GithubClientSecret != "" {
		socialService.SetPlatformGitHub(cfg.GithubClientID, cfg.GithubClientSecret) // GitHub isn't OIDC — dedicated adapter
	}
	if cfg.AppleClientID != "" && cfg.AppleTeamID != "" && cfg.AppleKeyID != "" && cfg.ApplePrivateKey != "" {
		socialService.SetPlatformApple(cfg.AppleClientID, cfg.AppleTeamID, cfg.AppleKeyID, cfg.ApplePrivateKey)
	}
}

// samlIdPIdentity returns the SAML IdP's signing key and certificate, PEM.
func samlIdPIdentity(cfg *config.Config) (keyPEM, certPEM string) {
	// SAML IdP signing identity: configured RSA key+cert in prod, or an
	// ephemeral self-signed cert in dev when unset.
	samlIdPKeyPEM, samlIdPCertPEM := cfg.SAMLIdPKey, cfg.SAMLIdPCert
	if samlIdPKeyPEM == "" || samlIdPCertPEM == "" {
		if !cfg.IsDev() {
			slog.Error("SAML_IDP_KEY and SAML_IDP_CERT are required outside dev (RSA private key + X.509 cert, PEM)")
			os.Exit(1)
		}
		k, c, gerr := saml.GenerateIdPKeyPEM("Qeet ID SAML IdP")
		if gerr != nil {
			slog.Error("generate ephemeral SAML IdP signing cert", "err", gerr)
			os.Exit(1)
		}
		samlIdPKeyPEM, samlIdPCertPEM = k, c
		slog.Warn("SAML_IDP_KEY/SAML_IDP_CERT unset — generated an ephemeral SAML IdP signing cert; SPs must re-import IdP metadata after a restart (dev only)")
	}
	return samlIdPKeyPEM, samlIdPCertPEM
}
