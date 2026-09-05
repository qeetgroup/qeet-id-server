//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
)

func TestSigningKeyRegistryConvergesAcrossInstancesAndRestart(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	box := testEnvelope(t)
	firstRegistry, err := tokens.NewSigningKeyRegistry(testPool, box)
	if err != nil {
		t.Fatalf("create first registry: %v", err)
	}
	secondRegistry, err := tokens.NewSigningKeyRegistry(testPool, box)
	if err != nil {
		t.Fatalf("create second registry: %v", err)
	}
	oldPEM, err := tokens.GenerateES256KeyPEM()
	if err != nil {
		t.Fatalf("generate old key: %v", err)
	}
	newPEM, err := tokens.GenerateES256KeyPEM()
	if err != nil {
		t.Fatalf("generate new key: %v", err)
	}
	oldStandalone, err := tokens.NewIssuer(oldPEM, "registry-test", "registry-test", 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("parse old key: %v", err)
	}
	newStandalone, err := tokens.NewIssuer(newPEM, "registry-test", "registry-test", 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("parse new key: %v", err)
	}
	oldKID, newKID := oldStandalone.KID(), newStandalone.KID()

	if err := firstRegistry.Reconcile(ctx, oldPEM, "", false, time.Hour); err != nil {
		t.Fatalf("bootstrap registry: %v", err)
	}
	firstIssuer, err := firstRegistry.NewIssuer(ctx, "registry-test", "registry-test", 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("load first issuer: %v", err)
	}
	secondIssuer, err := secondRegistry.NewIssuer(ctx, "registry-test", "registry-test", 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("load second issuer: %v", err)
	}
	if firstIssuer.KID() != oldKID || secondIssuer.KID() != oldKID {
		t.Fatalf("initial active KIDs = %s/%s, want %s", firstIssuer.KID(), secondIssuer.KID(), oldKID)
	}
	oldToken, _, err := firstIssuer.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "user.read")
	if err != nil {
		t.Fatalf("issue old token: %v", err)
	}
	if _, err := secondIssuer.VerifyAccess(oldToken); err != nil {
		t.Fatalf("second instance rejected old token: %v", err)
	}

	if err := firstRegistry.Reconcile(ctx, newPEM, "", false, time.Hour); err != nil {
		t.Fatalf("stage candidate: %v", err)
	}
	if err := firstRegistry.Sync(ctx, firstIssuer); err != nil {
		t.Fatalf("sync staged candidate: %v", err)
	}
	if firstIssuer.KID() != oldKID {
		t.Fatalf("staging changed active KID to %s", firstIssuer.KID())
	}
	candidatePublished := false
	for _, key := range firstIssuer.KeyInfo() {
		if key.Kid == newKID && key.Status == "candidate" {
			candidatePublished = true
		}
	}
	if !candidatePublished {
		t.Fatal("staged candidate was not published in key metadata")
	}

	if err := firstRegistry.Reconcile(ctx, newPEM, "", true, time.Hour); err != nil {
		t.Fatalf("activate candidate: %v", err)
	}
	if err := firstRegistry.Sync(ctx, firstIssuer); err != nil {
		t.Fatalf("sync first issuer after activation: %v", err)
	}
	if err := secondRegistry.Sync(ctx, secondIssuer); err != nil {
		t.Fatalf("sync second issuer after activation: %v", err)
	}
	if firstIssuer.KID() != newKID || secondIssuer.KID() != newKID {
		t.Fatalf("activated KIDs = %s/%s, want %s", firstIssuer.KID(), secondIssuer.KID(), newKID)
	}
	newToken, _, err := firstIssuer.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "user.read")
	if err != nil {
		t.Fatalf("issue new token: %v", err)
	}
	if _, err := secondIssuer.VerifyAccess(newToken); err != nil {
		t.Fatalf("second instance rejected new token: %v", err)
	}
	if _, err := secondIssuer.VerifyAccess(oldToken); err != nil {
		t.Fatalf("retired key did not verify during grace: %v", err)
	}

	if err := secondRegistry.Reconcile(ctx, oldPEM, "", false, time.Hour); err != nil {
		t.Fatalf("stale replica reconcile: %v", err)
	}
	if err := secondRegistry.Sync(ctx, secondIssuer); err != nil {
		t.Fatalf("sync stale replica: %v", err)
	}
	if secondIssuer.KID() != newKID {
		t.Fatalf("stale configuration reverted active KID to %s", secondIssuer.KID())
	}

	restartedIssuer, err := firstRegistry.NewIssuer(ctx, "registry-test", "registry-test", 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("reload issuer after restart: %v", err)
	}
	if restartedIssuer.KID() != newKID {
		t.Fatalf("restart active KID = %s, want %s", restartedIssuer.KID(), newKID)
	}
	if _, err := restartedIssuer.VerifyAccess(oldToken); err != nil {
		t.Fatalf("restarted issuer rejected grace token: %v", err)
	}
	if _, err := restartedIssuer.VerifyAccess(newToken); err != nil {
		t.Fatalf("restarted issuer rejected active token: %v", err)
	}

	var wait sync.WaitGroup
	raceErrors := make(chan error, 8)
	for worker := 0; worker < 4; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 50 {
				token, _, err := firstIssuer.IssueAccess(uuid.New(), uuid.New(), uuid.New(), "user.read")
				if err != nil {
					raceErrors <- err
					return
				}
				if _, err := secondIssuer.VerifyAccess(token); err != nil {
					raceErrors <- err
					return
				}
				_ = firstIssuer.JWKS()
				_ = secondIssuer.KeyInfo()
			}
		}()
	}
	for worker := 0; worker < 2; worker++ {
		wait.Add(1)
		go func(registry *tokens.SigningKeyRegistry, issuer *tokens.Issuer) {
			defer wait.Done()
			for range 25 {
				if err := registry.Sync(ctx, issuer); err != nil {
					raceErrors <- fmt.Errorf("sync issuer: %w", err)
					return
				}
			}
		}(firstRegistry, firstIssuer)
	}
	wait.Wait()
	close(raceErrors)
	for err := range raceErrors {
		t.Fatalf("concurrent keyring operation: %v", err)
	}

	var activeCiphertext []byte
	var activePrivatePresent bool
	var retiredPrivatePresent bool
	if err := testPool.QueryRow(ctx, `
		SELECT private_key_ct, private_key_ct IS NOT NULL
		FROM platform.jwt_signing_keys WHERE kid = $1 AND state = 'active'
	`, newKID).Scan(&activeCiphertext, &activePrivatePresent); err != nil {
		t.Fatalf("inspect active key storage: %v", err)
	}
	if !activePrivatePresent || len(activeCiphertext) == 0 || bytes.Contains(activeCiphertext, []byte("PRIVATE KEY")) {
		t.Fatal("active JWT private key is not ciphertext-only")
	}
	if err := testPool.QueryRow(ctx, `
		SELECT private_key_ct IS NOT NULL FROM platform.jwt_signing_keys WHERE kid = $1 AND state = 'retired'
	`, oldKID).Scan(&retiredPrivatePresent); err != nil {
		t.Fatalf("inspect retired key storage: %v", err)
	}
	if retiredPrivatePresent {
		t.Fatal("retired signing key retained private material")
	}

	if _, err := testPool.Exec(ctx, `
		UPDATE platform.jwt_signing_keys SET retire_at = NOW() - INTERVAL '1 second' WHERE kid = $1
	`, oldKID); err != nil {
		t.Fatalf("expire retired key: %v", err)
	}
	if err := firstRegistry.Sync(ctx, firstIssuer); err != nil {
		t.Fatalf("sync expired keyring: %v", err)
	}
	if _, err := firstIssuer.VerifyAccess(oldToken); err == nil {
		t.Fatal("expired retired key still verified a token")
	}
	if _, err := firstIssuer.VerifyAccess(newToken); err != nil {
		t.Fatalf("active key stopped verifying after retired expiry: %v", err)
	}
}
