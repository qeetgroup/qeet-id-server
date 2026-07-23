// Benchmark JWT signing throughput — ES256 access tokens minted per second.
//
//	go run ./tools/benchmarks/jwt_signing
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	signingKey := cfg.JWTSigningKey
	if signingKey == "" {
		// No configured key (dev/offline) — generate an ephemeral one to benchmark.
		signingKey, err = tokens.GenerateES256KeyPEM()
		if err != nil {
			fmt.Fprintf(os.Stderr, "generate key: %v\n", err)
			os.Exit(1)
		}
	}

	issuer, err := tokens.NewIssuer(signingKey, cfg.JWTIssuer, cfg.JWTAudience, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "new issuer: %v\n", err)
		os.Exit(1)
	}

	userID := uuid.New()
	tenantID := uuid.New()
	sessionID := uuid.New()

	const n = 10_000
	start := time.Now()
	for range n {
		if _, _, err := issuer.IssueAccess(userID, tenantID, sessionID, "openid profile"); err != nil {
			fmt.Fprintf(os.Stderr, "issue: %v\n", err)
			os.Exit(1)
		}
	}
	elapsed := time.Since(start)

	fmt.Printf("minted %d access tokens in %v\n", n, elapsed)
	fmt.Printf("throughput: %.0f tokens/sec\n", float64(n)/elapsed.Seconds())
	fmt.Printf("latency:    %v per token\n", elapsed/n)
}
