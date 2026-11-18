// Package secret is a per-organization secrets vault. Values are encrypted at rest with
// AES-256-GCM and never returned except via an explicit, audited reveal. The
// data-encryption key comes from a KeyProvider (keyprovider.go), unwrapped once at
// startup — independent of the JWT secret and swappable for a KMS-backed provider.
package secret

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/secret/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Secret is the metadata view — the plaintext value is never included.
type Secret struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Scope     string    `json:"scope"`
	Last4     string    `json:"last4"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// ValueChangedAt is when the value was last set; a scope change leaves it.
	ValueChangedAt time.Time  `json:"value_changed_at"`
	LastRevealedAt *time.Time `json:"last_revealed_at"`
	// LastRevealedBy is the person who last revealed the secret; nil when no
	// one has, or when a machine credential did (LastRevealedCredential).
	LastRevealedBy         *Revealer `json:"last_revealed_by"`
	LastRevealedCredential string    `json:"last_revealed_credential,omitempty"`
	// RotationDueAt is RotationIntervalDays after the value last changed; nil
	// without an interval. RotationOverdue is set once it has passed.
	RotationIntervalDays *int32     `json:"rotation_interval_days"`
	RotationDueAt        *time.Time `json:"rotation_due_at"`
	RotationOverdue      bool       `json:"rotation_overdue"`
}

// Revealer is the person who last revealed a secret. Email is empty once the
// person no longer exists.
type Revealer struct {
	ID          uuid.UUID `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
}

// Rotation intervals a secret accepts, in days.
const (
	minRotationDays = 1
	maxRotationDays = 3650
)

// Service stores each organization's secrets, encrypted at rest.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
	box  *envelope.Cipher
}

// NewService builds the vault, sealing values with box, the deployment's cipher
// over the data key from the KeyProvider.
func NewService(pool *pgxpool.Pool, box *envelope.Cipher) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), box: box}
}

// Caller is who uses the vault: their audit Actor and, for a machine
// credential (an API key, a service principal, an agent), its id. The audit
// rows and a secret's last reveal name the credential, never the person whose
// id it carries.
type Caller struct {
	audit.Actor
	Credential string
}

// CallerOf returns who made r.
func CallerOf(r *http.Request) Caller {
	c := Caller{Actor: audit.ActorOf(r)}
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil && p.ActorType != "" && p.ActorType != "user" {
		c.Credential = p.Subject
	}
	return c
}

// event is the audit Event of action on secret id by c.
func (c Caller) event(organizationID, id uuid.UUID, action string, metadata map[string]any) audit.Event {
	if c.Credential != "" {
		if metadata == nil {
			metadata = map[string]any{}
		}
		metadata["credential_id"] = c.Credential
	}
	return c.Event(organizationID, action, "secret", id, metadata)
}

func (s *Service) encrypt(organizationID uuid.UUID, name, plaintext string) (ciphertext, nonce []byte, err error) {
	return s.box.Seal(organizationID, "secret", name, []byte(plaintext))
}

func (s *Service) decrypt(organizationID uuid.UUID, name string, ciphertext, nonce []byte) (string, error) {
	pt, err := s.box.Open(organizationID, "secret", name, ciphertext, nonce)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// hint returns the last 4 characters, but only for secrets long enough that
// doing so doesn't reveal most of the value.
func hint(value string) string {
	if len([]rune(value)) < 8 {
		return ""
	}
	r := []rune(value)
	return string(r[len(r)-4:])
}

// toSecret maps a secret row to Secret, working out its rotation due date
// against now.
func toSecret(row dbgen.ListSecretsRow, now time.Time) *Secret {
	sec := &Secret{
		ID: row.ID, Name: row.Name, Scope: row.Scope, Last4: row.Last4,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, ValueChangedAt: row.ValueChangedAt,
		RotationIntervalDays: row.RotationIntervalDays,
	}
	sec.LastRevealedAt = row.LastRevealedAt
	if row.LastRevealedBy != nil {
		sec.LastRevealedBy = &Revealer{ID: *row.LastRevealedBy}
		if row.RevealedByEmail != nil {
			sec.LastRevealedBy.Email = *row.RevealedByEmail
		}
		if row.RevealedByName != nil {
			sec.LastRevealedBy.DisplayName = *row.RevealedByName
		}
	}
	if row.LastRevealedCredential != nil {
		sec.LastRevealedCredential = *row.LastRevealedCredential
	}
	if days := row.RotationIntervalDays; days != nil {
		due := row.ValueChangedAt.AddDate(0, 0, int(*days))
		sec.RotationDueAt = &due
		sec.RotationOverdue = !now.Before(due)
	}
	return sec
}

// get returns one of the organization's secrets, read through q.
func get(ctx context.Context, q *dbgen.Queries, organizationID, id uuid.UUID) (*Secret, error) {
	row, err := q.GetSecret(ctx, dbgen.GetSecretParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrSecretNotFound
	}
	if err != nil {
		return nil, err
	}
	return toSecret(dbgen.ListSecretsRow(row), time.Now()), nil
}

// List returns the organization's secrets.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Secret, error) {
	rows, err := s.q.ListSecrets(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := []Secret{}
	for _, row := range rows {
		out = append(out, *toSecret(row, now))
	}
	return out, nil
}

// checkRotationDays refuses a rotation interval outside the accepted range;
// nil, no interval, is accepted.
func checkRotationDays(days *int32) error {
	if days != nil && (*days < minRotationDays || *days > maxRotationDays) {
		return ErrRotationIntervalOutOfRange.WithMetadata(map[string]any{
			"min_days": minRotationDays, "max_days": maxRotationDays,
		})
	}
	return nil
}

// Create stores a secret for the organization, with an optional rotation interval
// in days, recorded as by's.
func (s *Service) Create(ctx context.Context, organizationID uuid.UUID, name, scope, value string, rotationDays *int32, by Caller) (*Secret, error) {
	name = strings.TrimSpace(name)
	if name == "" || value == "" {
		return nil, ErrNameValueRequired
	}
	if err := checkRotationDays(rotationDays); err != nil {
		return nil, err
	}
	ct, nonce, err := s.encrypt(organizationID, name, value)
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	id, err := q.CreateSecret(ctx, dbgen.CreateSecretParams{
		OrganizationID:       organizationID,
		Name:                 name,
		Scope:                scope,
		Ciphertext:           ct,
		Nonce:                nonce,
		Last4:                hint(value),
		RotationIntervalDays: rotationDays,
	})
	if err != nil {
		if strings.Contains(err.Error(), "secrets_organization_id_name_key") || strings.Contains(err.Error(), "duplicate") {
			return nil, ErrNameExists
		}
		return nil, err
	}
	return s.recorded(ctx, tx, organizationID, id, "secret.created", by)
}

// recorded returns secret id as it is in tx, after recording action on it as
// by's and committing tx.
func (s *Service) recorded(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID, action string, by Caller) (*Secret, error) {
	sec, err := get(ctx, s.q.WithTx(tx), organizationID, id)
	if err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, by.event(organizationID, id, action, map[string]any{"name": sec.Name})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return sec, nil
}

// UpdateInput is what Update takes. RotationIntervalDays left out keeps the
// interval; null removes it.
type UpdateInput struct {
	Scope                *string      `json:"scope"`
	Value                *string      `json:"value"`
	RotationIntervalDays OptionalDays `json:"rotation_interval_days"`
}

// OptionalDays is a JSON field that can be left out, null, or a number of
// days. Set reports whether the request named it at all; Days is nil for null.
type OptionalDays struct {
	Set  bool
	Days *int32
}

// UnmarshalJSON implements json.Unmarshaler.
func (o *OptionalDays) UnmarshalJSON(b []byte) error {
	o.Set = true
	return json.Unmarshal(b, &o.Days)
}

// Update changes a secret's value, scope and/or rotation interval, each kept
// when left out, recorded as by's: a new value as a rotation.
func (s *Service) Update(ctx context.Context, organizationID, id uuid.UUID, in UpdateInput, by Caller) (*Secret, error) {
	if err := checkRotationDays(in.RotationIntervalDays.Days); err != nil {
		return nil, err
	}
	if in.Value != nil && *in.Value == "" {
		return nil, ErrValueRequired
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	action, n := "secret.updated", int64(0)
	if in.Value != nil {
		action = "secret.rotated"
		current, err := q.RevealSecret(ctx, dbgen.RevealSecretParams{ID: id, OrganizationID: organizationID})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrSecretNotFound
		}
		if err != nil {
			return nil, err
		}
		ct, nonce, err := s.encrypt(organizationID, current.Name, *in.Value)
		if err != nil {
			return nil, err
		}
		n, err = q.UpdateSecretValue(ctx, dbgen.UpdateSecretValueParams{
			Ciphertext: ct, Nonce: nonce, Last4: hint(*in.Value), Scope: in.Scope,
			SetRotation: in.RotationIntervalDays.Set, RotationIntervalDays: in.RotationIntervalDays.Days,
			ID: id, OrganizationID: organizationID,
		})
		if err != nil {
			return nil, err
		}
	} else {
		n, err = q.UpdateSecretSettings(ctx, dbgen.UpdateSecretSettingsParams{
			Scope: in.Scope, SetRotation: in.RotationIntervalDays.Set, RotationIntervalDays: in.RotationIntervalDays.Days,
			ID: id, OrganizationID: organizationID,
		})
		if err != nil {
			return nil, err
		}
	}
	if n == 0 {
		return nil, errs.ErrSecretNotFound
	}
	return s.recorded(ctx, tx, organizationID, id, action, by)
}

// Reveal returns one of the organization's secrets, its name and decrypted
// value, once the reveal is recorded as by's, in the audit and on the secret.
// A reveal that can't be recorded is refused: no value leaves unaudited.
func (s *Service) Reveal(ctx context.Context, organizationID, id uuid.UUID, by Caller) (string, string, error) {
	row, err := s.q.RevealSecret(ctx, dbgen.RevealSecretParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", errs.ErrSecretNotFound
	}
	if err != nil {
		return "", "", err
	}
	val, err := s.decrypt(organizationID, row.Name, row.Ciphertext, row.Nonce)
	if err != nil {
		return "", "", ErrDecryptFailed.Wrap(err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback(ctx)
	if err := audit.Record(ctx, tx, by.event(organizationID, id, "secret.revealed", map[string]any{"name": row.Name})); err != nil {
		return "", "", err
	}
	revealed := dbgen.MarkSecretRevealedParams{ID: id, OrganizationID: organizationID}
	if by.Credential != "" {
		revealed.Credential = &by.Credential
	} else {
		revealed.UserID = by.UserID
	}
	if err := s.q.WithTx(tx).MarkSecretRevealed(ctx, revealed); err != nil {
		return "", "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", err
	}
	return row.Name, val, nil
}

// GetByName decrypts a secret by its name, for a credential reading it through
// the scoped vault endpoint, and returns its id and value once the read is
// recorded as by's. A read that can't be recorded is refused.
func (s *Service) GetByName(ctx context.Context, organizationID uuid.UUID, name string, by Caller) (uuid.UUID, string, error) {
	row, err := s.q.GetSecretByName(ctx, dbgen.GetSecretByNameParams{OrganizationID: organizationID, Name: name})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", errs.ErrSecretNotFound
	}
	if err != nil {
		return uuid.Nil, "", err
	}
	val, err := s.decrypt(organizationID, name, row.Ciphertext, row.Nonce)
	if err != nil {
		return uuid.Nil, "", ErrDecryptFailed.Wrap(err)
	}
	if err := audit.RecordAlone(ctx, s.pool, by.event(organizationID, row.ID, "vault.accessed", map[string]any{"name": name})); err != nil {
		return uuid.Nil, "", err
	}
	return row.ID, val, nil
}

// Delete removes one of the organization's secrets, recorded as by's.
func (s *Service) Delete(ctx context.Context, organizationID, id uuid.UUID, by Caller) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).DeleteSecret(ctx, dbgen.DeleteSecretParams{ID: id, OrganizationID: organizationID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrSecretNotFound
	}
	if err := audit.Record(ctx, tx, by.event(organizationID, id, "secret.deleted", nil)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// hasVaultScope reports whether a principal's scopes permit reading the named
// vault secret: a specific "vault:<name>" (least-privilege) or a blanket
// "vault:read".
func hasVaultScope(scopes []string, name string) bool {
	for _, s := range scopes {
		if s == "vault:read" || s == "vault:"+name {
			return true
		}
	}
	return false
}
