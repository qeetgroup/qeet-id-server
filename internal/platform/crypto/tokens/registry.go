package tokens

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
)

// DefaultSigningKeyRetireGrace is how long a retired key keeps verifying.
// SyncFailuresUntilNotReady is how many keyring refreshes in a row may fail
// before Ready reports the instance not ready.
const (
	DefaultSigningKeyRetireGrace = 30 * 24 * time.Hour
	signingKeyAdvisoryLock       = int64(0x514545544A5754)
	SyncFailuresUntilNotReady    = 3
)

// ErrActiveKeySealedElsewhere means the database's active signing key was
// sealed with a different vault key, so this instance can't sign with it.
var ErrActiveKeySealedElsewhere = errors.New("the active JWT signing key in the database was sealed with a different vault key (SECRETS_KEY / KMS data key)")

//nolint:gochecknoglobals // Prometheus collectors are process-wide by design.
var (
	activeKeyInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "jwt_signing_key_active",
		Help: "1 for the kid this instance signs with.",
	}, []string{"kid"})
	snapshotTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "jwt_signing_key_snapshot_timestamp_seconds",
		Help: "When this instance last loaded the keyring (Unix seconds); its age is time() minus this.",
	})
	syncFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "jwt_signing_key_sync_failures_total",
		Help: "Keyring refreshes that failed.",
	})
)

var signingKeyEncryptionNamespace = uuid.MustParse("00000000-0000-5000-8000-000000000017")

// SigningKeyRegistry persists the JWT key lifecycle in PostgreSQL. Candidate
// and active private keys are envelope-encrypted with the deployment KMS/DEK;
// retired rows retain public material only until their explicit retirement
// timestamp passes.
type SigningKeyRegistry struct {
	pool *pgxpool.Pool
	box  *envelope.Cipher

	// health is how the keyring's refreshes have gone; see Ready.
	mu           sync.Mutex
	failedInARow int
	lastErr      error
	activeKID    string
}

// NewSigningKeyRegistry returns a registry over pool that seals private keys
// with box. Both are required.
func NewSigningKeyRegistry(pool *pgxpool.Pool, box *envelope.Cipher) (*SigningKeyRegistry, error) {
	if pool == nil || box == nil {
		return nil, errors.New("signing key registry requires database and envelope cipher")
	}
	return &SigningKeyRegistry{pool: pool, box: box}, nil
}

// Reconcile registers configuredKeyPEM as a candidate. The first key becomes
// active automatically. Later candidates activate only when activate is true,
// which makes rolling deployment a two-phase operation and prevents replicas
// with stale configuration from flipping the active key back.
func (r *SigningKeyRegistry) Reconcile(ctx context.Context, configuredKeyPEM, legacyRetiredPEM string, activate bool, retireGrace time.Duration) error {
	if retireGrace <= 0 {
		retireGrace = DefaultSigningKeyRetireGrace
	}
	kid, publicPEM, err := signingKeyMaterial(configuredKeyPEM)
	if err != nil {
		return err
	}
	ciphertext, nonce, err := r.box.Seal(signingKeyEncryptionNamespace, "jwt-signing-key", kid, []byte(configuredKeyPEM))
	if err != nil {
		return err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, signingKeyAdvisoryLock); err != nil {
		return err
	}

	var configuredState string
	err = tx.QueryRow(ctx, `SELECT state FROM platform.jwt_signing_keys WHERE kid = $1`, kid).Scan(&configuredState)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		configuredState = "candidate"
		if _, err := tx.Exec(ctx, `
			INSERT INTO platform.jwt_signing_keys
			    (kid, algorithm, state, public_key_pem, private_key_ct, private_key_nonce)
			VALUES ($1, 'ES256', 'candidate', $2, $3, $4)
		`, kid, publicPEM, ciphertext, nonce); err != nil {
			return err
		}
	case err != nil:
		return err
	case configuredState == "candidate" || configuredState == "active":
		if _, err := tx.Exec(ctx, `
			UPDATE platform.jwt_signing_keys
			SET public_key_pem = $2, private_key_ct = $3, private_key_nonce = $4,
			    encryption_version = 1, updated_at = NOW()
			WHERE kid = $1
		`, kid, publicPEM, ciphertext, nonce); err != nil {
			return err
		}
	}

	if err := registerLegacyRetiredKeys(ctx, tx, legacyRetiredPEM, time.Now().UTC().Add(retireGrace)); err != nil {
		return err
	}

	var activeKID string
	err = tx.QueryRow(ctx, `SELECT kid FROM platform.jwt_signing_keys WHERE state = 'active'`).Scan(&activeKID)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := promoteSigningKey(ctx, tx, kid, publicPEM, ciphertext, nonce); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if activeKID != kid && activate {
		retireAt := time.Now().UTC().Add(retireGrace)
		if _, err := tx.Exec(ctx, `
			UPDATE platform.jwt_signing_keys
			SET state = 'retired', retire_at = $2, private_key_ct = NULL,
			    private_key_nonce = NULL, updated_at = NOW()
			WHERE kid = $1 AND state = 'active'
		`, activeKID, retireAt); err != nil {
			return err
		}
		if err := promoteSigningKey(ctx, tx, kid, publicPEM, ciphertext, nonce); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// EnsureDevelopmentKey gives a dev instance without JWT_SIGNING_KEY a stable key:
// it keeps the database's active key if this instance's vault key opens it, and
// otherwise creates the first one; generated reports a new key. An active key it
// can't open returns ErrActiveKeySealedElsewhere and changes nothing.
func (r *SigningKeyRegistry) EnsureDevelopmentKey(ctx context.Context) (generated bool, err error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, signingKeyAdvisoryLock); err != nil {
		return false, err
	}
	var activeKID string
	var ciphertext, nonce []byte
	err = tx.QueryRow(ctx, `
		SELECT kid, private_key_ct, private_key_nonce
		FROM platform.jwt_signing_keys WHERE state = 'active'
	`).Scan(&activeKID, &ciphertext, &nonce)
	switch {
	case err == nil:
		if _, err := r.box.Open(signingKeyEncryptionNamespace, "jwt-signing-key", activeKID, ciphertext, nonce); err != nil {
			return false, fmt.Errorf("%w: kid %s", ErrActiveKeySealedElsewhere, activeKID)
		}
		return false, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return false, err
	}
	keyPEM, err := GenerateES256KeyPEM()
	if err != nil {
		return false, err
	}
	kid, publicPEM, err := signingKeyMaterial(keyPEM)
	if err != nil {
		return false, err
	}
	ciphertext, nonce, err = r.box.Seal(signingKeyEncryptionNamespace, "jwt-signing-key", kid, []byte(keyPEM))
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO platform.jwt_signing_keys
		    (kid, algorithm, state, public_key_pem, private_key_ct, private_key_nonce, activated_at)
		VALUES ($1, 'ES256', 'active', $2, $3, $4, NOW())
	`, kid, publicPEM, ciphertext, nonce); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func promoteSigningKey(ctx context.Context, tx pgx.Tx, kid, publicPEM string, ciphertext, nonce []byte) error {
	tag, err := tx.Exec(ctx, `
		UPDATE platform.jwt_signing_keys
		SET state = 'active', public_key_pem = $2, private_key_ct = $3,
		    private_key_nonce = $4, encryption_version = 1,
		    activated_at = NOW(), retire_at = NULL, updated_at = NOW()
		WHERE kid = $1
	`, kid, publicPEM, ciphertext, nonce)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("configured signing key was not registered")
	}
	return nil
}

func registerLegacyRetiredKeys(ctx context.Context, tx pgx.Tx, raw string, retireAt time.Time) error {
	rest := []byte(raw)
	for len(bytes.TrimSpace(rest)) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return errors.New("invalid JWT_RETIRED_KEYS PEM")
		}
		rest = remaining
		publicKey, err := publicKeyFromBlock(block)
		if err != nil {
			return fmt.Errorf("parse retired signing key: %w", err)
		}
		ec, ok := publicKey.(*ecdsa.PublicKey)
		if !ok || ec.Curve != elliptic.P256() {
			return errors.New("retired signing keys must use P-256")
		}
		kid, publicPEM, err := publicSigningKeyMaterial(ec)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO platform.jwt_signing_keys
			    (kid, algorithm, state, public_key_pem, retire_at)
			VALUES ($1, 'ES256', 'retired', $2, $3)
			ON CONFLICT (kid) DO NOTHING
		`, kid, publicPEM, retireAt); err != nil {
			return err
		}
	}
	return nil
}

func signingKeyMaterial(privatePEM string) (string, string, error) {
	privateKey, err := parseECPrivateKey(privatePEM)
	if err != nil {
		return "", "", fmt.Errorf("parse configured signing key: %w", err)
	}
	if privateKey.Curve != elliptic.P256() {
		return "", "", errors.New("configured signing key must use P-256")
	}
	return publicSigningKeyMaterial(&privateKey.PublicKey)
}

func publicSigningKeyMaterial(publicKey *ecdsa.PublicKey) (string, string, error) {
	kid, err := thumbprint(publicKey)
	if err != nil {
		return "", "", err
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", err
	}
	return kid, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func (r *SigningKeyRegistry) loadSnapshot(ctx context.Context) (string, []verificationKeyPEM, error) {
	var activeKID string
	var ciphertext, nonce []byte
	if err := r.pool.QueryRow(ctx, `
		SELECT kid, private_key_ct, private_key_nonce
		FROM platform.jwt_signing_keys
		WHERE state = 'active'
	`).Scan(&activeKID, &ciphertext, &nonce); err != nil {
		return "", nil, err
	}
	plaintext, err := r.box.Open(signingKeyEncryptionNamespace, "jwt-signing-key", activeKID, ciphertext, nonce)
	if err != nil {
		return "", nil, fmt.Errorf("decrypt active signing key: %w", err)
	}
	loadedKID, _, err := signingKeyMaterial(string(plaintext))
	if err != nil {
		return "", nil, err
	}
	if loadedKID != activeKID {
		return "", nil, errors.New("active signing key ciphertext does not match its kid")
	}

	rows, err := r.pool.Query(ctx, `
		SELECT kid, public_key_pem, state, retire_at
		FROM platform.jwt_signing_keys
		WHERE state IN ('active', 'candidate')
		   OR (state = 'retired' AND retire_at > NOW())
		ORDER BY created_at, kid
	`)
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()
	var keys []verificationKeyPEM
	for rows.Next() {
		var entry verificationKeyPEM
		if err := rows.Scan(&entry.KID, &entry.PEM, &entry.Status, &entry.RetireAt); err != nil {
			return "", nil, err
		}
		keys = append(keys, entry)
	}
	if err := rows.Err(); err != nil {
		return "", nil, err
	}
	return string(plaintext), keys, nil
}

// NewIssuer returns an Issuer loaded with the registry's current keyring.
func (r *SigningKeyRegistry) NewIssuer(ctx context.Context, issuer, audience string, accessTTL, refreshTTL time.Duration) (*Issuer, error) {
	activePEM, keys, err := r.loadSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	result, err := NewIssuer(activePEM, issuer, audience, accessTTL, refreshTTL)
	if err != nil {
		return nil, err
	}
	if err := result.replaceKeyring(activePEM, keys); err != nil {
		return nil, err
	}
	r.recordSync(result.KID(), nil)
	return result, nil
}

// Sync reloads the keyring from the database into issuer, and records how it
// went (see Ready).
func (r *SigningKeyRegistry) Sync(ctx context.Context, issuer *Issuer) error {
	err := r.sync(ctx, issuer)
	r.recordSync(issuer.KID(), err)
	return err
}

func (r *SigningKeyRegistry) sync(ctx context.Context, issuer *Issuer) error {
	activePEM, keys, err := r.loadSnapshot(ctx)
	if err != nil {
		return err
	}
	return issuer.replaceKeyring(activePEM, keys)
}

// recordSync notes a refresh's outcome for readiness and the metrics.
func (r *SigningKeyRegistry) recordSync(kid string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.failedInARow++
		r.lastErr = err
		syncFailures.Inc()
		return
	}
	r.failedInARow, r.lastErr = 0, nil
	snapshotTimestamp.SetToCurrentTime()
	if kid != r.activeKID {
		if r.activeKID != "" {
			activeKeyInfo.DeleteLabelValues(r.activeKID)
		}
		r.activeKID = kid
		activeKeyInfo.WithLabelValues(kid).Set(1)
	}
}

// Ready is the keyring's readiness check: an instance whose last
// SyncFailuresUntilNotReady refreshes all failed is not ready, since it may be
// signing with a key the others have retired, or unable to verify theirs.
func (r *SigningKeyRegistry) Ready(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failedInARow >= SyncFailuresUntilNotReady {
		return fmt.Errorf("the last %d keyring refreshes failed: %w", r.failedInARow, r.lastErr)
	}
	return nil
}

// Run syncs issuer every interval (default 5s) until ctx is done, logging
// failures.
func (r *SigningKeyRegistry) Run(ctx context.Context, issuer *Issuer, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.Sync(ctx, issuer); err != nil {
				slog.Error("JWT signing key registry sync failed", "err", err)
			}
		}
	}
}
