package tokens

import (
	"crypto/x509"
	"encoding/pem"
)

// PublicKeyPEM returns the SPKI ("PUBLIC KEY") PEM for an EC private key, the
// form JWT_RETIRED_KEYS accepts.
func PublicKeyPEM(privateKeyPEM string) (string, error) {
	priv, err := parseECPrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}
