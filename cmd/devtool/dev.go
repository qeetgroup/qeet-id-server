package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// secretsDir is the folder of the persistent local signing material (git-ignored); DEV_SECRETS_DIR overrides it.
func secretsDir() string { return envOr("DEV_SECRETS_DIR", ".secrets") }

// devSecrets generates, once, the persistent local signing material into .secrets/ (git-ignored):
// an ES256 JWT key, and a SAML IdP RSA key with its self-signed certificate, always as a pair.
// Whatever is already there is kept.
func devSecrets() error {
	if err := os.MkdirAll(secretsDir(), 0o700); err != nil {
		return err
	}
	jwt := filepath.Join(secretsDir(), "jwt_es256.pem")
	if !present(jwt) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
		if err := writePEM(jwt, "EC PRIVATE KEY", der); err != nil {
			return err
		}
		fmt.Println("generated", jwt, "(JWT ES256 signing key)")
	}
	samlKey, samlCert := filepath.Join(secretsDir(), "saml_idp_key.pem"), filepath.Join(secretsDir(), "saml_idp_cert.pem")
	if present(samlKey) && present(samlCert) {
		return nil
	}
	if err := samlPair(samlKey, samlCert); err != nil {
		return err
	}
	fmt.Println("generated", samlKey, "+", filepath.Base(samlCert), "(SAML IdP pair)")
	return nil
}

// samlPair writes a fresh RSA-2048 key (PKCS#8) and a self-signed certificate for it, valid 10 years.
func samlPair(keyPath, certPath string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Qeet ID SAML IdP"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, SignatureAlgorithm: x509.SHA256WithRSA,
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writePEM(keyPath, "PRIVATE KEY", der); err != nil {
		return err
	}
	return writePEM(certPath, "CERTIFICATE", cert)
}

func present(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Size() > 0
}

func writePEM(path, kind string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600)
}

// pprofAddr is where make dev-observed serves profiles for the local stack's Alloy container:
// loopback, which Docker Desktop reaches, and every address only on Linux, whose Docker bridge can't.
func pprofAddr() string {
	if runtime.GOOS == "linux" {
		return "0.0.0.0:6060"
	}
	return "127.0.0.1:6060"
}

// dev runs the API with the persistent keys from .secrets/, which a .env line can't carry (they span
// lines). observed adds JSON logs, also appended to bin/logs/api.log, and traces to the local collector.
func dev(observed bool) error {
	if err := devSecrets(); err != nil {
		return err
	}
	env := []string{}
	for name, file := range map[string]string{"JWT_SIGNING_KEY": "jwt_es256.pem", "SAML_IDP_KEY": "saml_idp_key.pem", "SAML_IDP_CERT": "saml_idp_cert.pem"} {
		b, err := os.ReadFile(filepath.Join(secretsDir(), file)) // #nosec G304 -- the files devSecrets just wrote
		if err != nil {
			return err
		}
		env = append(env, name+"="+string(b))
	}
	port := envOr("HTTP_PORT", "4001")
	var out io.Writer = os.Stdout
	if observed {
		logFile := envOr("DEV_LOG_FILE", filepath.Join("bin", "logs", "api.log"))
		if err := os.MkdirAll(filepath.Dir(logFile), 0o750); err != nil {
			return err
		}
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- the developer's own log path
		if err != nil {
			return err
		}
		defer f.Close()
		out = io.MultiWriter(os.Stdout, f)
		otlp := envOr("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
		pprof := envOr("PPROF_ADDR", pprofAddr())
		env = append(env, "LOG_FORMAT="+envOr("LOG_FORMAT", "json"), "OTEL_EXPORTER_OTLP_ENDPOINT="+otlp, "PPROF_ADDR="+pprof)
		fmt.Printf("starting qeet-id on :%s, observed (logs %s, traces %s, profiles %s)\n", port, logFile, otlp, pprof)
	} else {
		fmt.Printf("starting qeet-id on :%s with the persistent JWT and SAML keys from %s/\n", port, secretsDir())
	}
	err := runIn("", env, out, "go", "run", "./cmd/api")
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}
