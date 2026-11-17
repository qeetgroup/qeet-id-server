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

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/secrets/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
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

// Pool returns the connection pool, for handlers that run their own transaction.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

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
	if row.LastRevealedAt.Valid {
		at := row.LastRevealedAt.Time
		sec.LastRevealedAt = &at
	}
	if row.LastRevealedBy.Valid {
		sec.LastRevealedBy = &Revealer{ID: row.LastRevealedBy.Bytes}
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

// get returns one of the organization's secrets.
func (s *Service) get(ctx context.Context, organizationID, id uuid.UUID) (*Secret, error) {
	row, err := s.q.GetSecret(ctx, dbgen.GetSecretParams{ID: id, OrganizationID: organizationID})
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
		return errs.ErrSecretRotationIntervalOutOfRange.WithMetadata(map[string]any{
			"min_days": minRotationDays, "max_days": maxRotationDays,
		})
	}
	return nil
}

// Create stores a secret for the organization, with an optional rotation interval
// in days.
func (s *Service) Create(ctx context.Context, organizationID uuid.UUID, name, scope, value string, rotationDays *int32) (*Secret, error) {
	name = strings.TrimSpace(name)
	if name == "" || value == "" {
		return nil, errs.ErrSecretNameValueRequired
	}
	if err := checkRotationDays(rotationDays); err != nil {
		return nil, err
	}
	ct, nonce, err := s.encrypt(organizationID, name, value)
	if err != nil {
		return nil, err
	}
	id, err := s.q.CreateSecret(ctx, dbgen.CreateSecretParams{
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
			return nil, errs.ErrSecretNameExists
		}
		return nil, err
	}
	return s.get(ctx, organizationID, id)
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

// Update changes a secret's value, scope and/or rotation interval; a field
// left out is kept. It is hand-written because sqlc reads the NOT NULL scope
// column as a plain string, so nil couldn't mean "no change".
func (s *Service) Update(ctx context.Context, organizationID, id uuid.UUID, in UpdateInput) (*Secret, error) {
	if err := checkRotationDays(in.RotationIntervalDays.Days); err != nil {
		return nil, err
	}
	// Rotate the encrypted value only when a new one is supplied.
	if in.Value != nil {
		if *in.Value == "" {
			return nil, errs.ErrSecretValueRequired
		}
		current, err := s.q.RevealSecret(ctx, dbgen.RevealSecretParams{ID: id, OrganizationID: organizationID})
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
		tag, err := s.pool.Exec(ctx, `
			UPDATE organization.secrets
			SET ciphertext = $3, nonce = $4, last4 = $5, scope = COALESCE($6, scope),
			    rotation_interval_days = CASE WHEN $7 THEN $8 ELSE rotation_interval_days END,
			    value_changed_at = NOW(), updated_at = NOW()
			WHERE id = $1 AND organization_id = $2`,
			id, organizationID, ct, nonce, hint(*in.Value), in.Scope, in.RotationIntervalDays.Set, in.RotationIntervalDays.Days)
		return s.updated(ctx, organizationID, id, tag, err)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE organization.secrets
		SET scope = COALESCE($3, scope),
		    rotation_interval_days = CASE WHEN $4 THEN $5 ELSE rotation_interval_days END,
		    updated_at = NOW()
		WHERE id = $1 AND organization_id = $2`,
		id, organizationID, in.Scope, in.RotationIntervalDays.Set, in.RotationIntervalDays.Days)
	return s.updated(ctx, organizationID, id, tag, err)
}

// updated returns the secret an UPDATE changed; no row is ErrSecretNotFound.
func (s *Service) updated(ctx context.Context, organizationID, id uuid.UUID, tag pgconn.CommandTag, err error) (*Secret, error) {
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, errs.ErrSecretNotFound
	}
	return s.get(ctx, organizationID, id)
}

// MarkRevealed records on the secret who revealed it, in the transaction that
// audits the reveal: a person, or a machine credential by its id.
func (s *Service) MarkRevealed(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID, userID *uuid.UUID, credential string) error {
	arg := dbgen.MarkSecretRevealedParams{ID: id, OrganizationID: organizationID}
	if credential != "" {
		arg.Credential = &credential
	} else if userID != nil {
		arg.UserID = pgtype.UUID{Bytes: *userID, Valid: true}
	}
	return s.q.WithTx(tx).MarkSecretRevealed(ctx, arg)
}

// Reveal returns one of the organization's secrets: its name and decrypted value.
func (s *Service) Reveal(ctx context.Context, organizationID, id uuid.UUID) (string, string, error) {
	row, err := s.q.RevealSecret(ctx, dbgen.RevealSecretParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", errs.ErrSecretNotFound
	}
	if err != nil {
		return "", "", err
	}
	val, err := s.decrypt(organizationID, row.Name, row.Ciphertext, row.Nonce)
	if err != nil {
		return "", "", errs.ErrSecretDecryptFailed.Wrap(err)
	}
	return row.Name, val, nil
}

// GetByName decrypts a secret by its name (for agent/credential retrieval via
// the scoped vault endpoint). Returns the secret id (for auditing) + value.
func (s *Service) GetByName(ctx context.Context, organizationID uuid.UUID, name string) (uuid.UUID, string, error) {
	row, err := s.q.GetSecretByName(ctx, dbgen.GetSecretByNameParams{OrganizationID: organizationID, Name: name})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", errs.ErrSecretNotFound
	}
	if err != nil {
		return uuid.Nil, "", err
	}
	val, err := s.decrypt(organizationID, name, row.Ciphertext, row.Nonce)
	if err != nil {
		return uuid.Nil, "", errs.ErrSecretDecryptFailed.Wrap(err)
	}
	return row.ID, val, nil
}

// Delete removes one of the organization's secrets.
func (s *Service) Delete(ctx context.Context, organizationID, id uuid.UUID) error {
	n, err := s.q.DeleteSecret(ctx, dbgen.DeleteSecretParams{ID: id, OrganizationID: organizationID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrSecretNotFound
	}
	return nil
}

// Handler serves the secrets vault HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the secrets vault routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/secrets", h.list)
	r.Post("/tenants/{tenantID}/secrets", h.create)
	r.Patch("/tenants/{tenantID}/secrets/{id}", h.update)
	r.Post("/tenants/{tenantID}/secrets/{id}/reveal", h.reveal)
	r.Delete("/tenants/{tenantID}/secrets/{id}", h.del)
	// Token vaulting: a scoped principal (e.g. an AI agent) fetches a vault
	// secret by name. Gated by a vault:<name> (or vault:read) scope; audited.
	r.Get("/vault/{name}", h.vaultGet)
}

func (h *Handler) recordAudit(ctx context.Context, tx pgx.Tx, r *http.Request, organizationID, resourceID uuid.UUID, action string, meta map[string]any) error {
	var actorID *uuid.UUID
	actorType := "system"
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		actorID = p.UserID
		if p.ActorType != "" {
			actorType = p.ActorType
		}
		// A machine credential is named by its own id, so a key's access is
		// never mistaken for the person whose id the key carries.
		if p.ActorType != "" && p.ActorType != "user" && p.Subject != "" {
			if meta == nil {
				meta = map[string]any{}
			}
			meta["credential_id"] = p.Subject
		}
	}
	tid := organizationID
	rid := resourceID
	return audit.Record(ctx, tx, audit.Event{
		OrganizationID: &tid, ActorUserID: actorID, ActorType: actorType,
		Action: action, ResourceType: "secret", ResourceID: &rid,
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
		Metadata: meta,
	})
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.List(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		Name                 string `json:"name"`
		Scope                string `json:"scope"`
		Value                string `json:"value"`
		RotationIntervalDays *int32 `json:"rotation_interval_days"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	sec, err := h.Service.Create(ctx, organizationID, in.Name, in.Scope, in.Value, in.RotationIntervalDays)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tx, err := h.Service.Pool().Begin(ctx)
	if err == nil {
		defer tx.Rollback(ctx)
		if aerr := h.recordAudit(ctx, tx, r, organizationID, sec.ID, "secret.created", map[string]any{"name": sec.Name}); aerr == nil {
			_ = tx.Commit(ctx)
		}
	}
	httpx.WriteJSON(w, http.StatusCreated, sec)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	var in UpdateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	sec, err := h.Service.Update(ctx, organizationID, id, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tx, err := h.Service.Pool().Begin(ctx)
	if err == nil {
		defer tx.Rollback(ctx)
		action := "secret.updated"
		if in.Value != nil {
			action = "secret.rotated"
		}
		if aerr := h.recordAudit(ctx, tx, r, organizationID, sec.ID, action, map[string]any{"name": sec.Name}); aerr == nil {
			_ = tx.Commit(ctx)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, sec)
}

func (h *Handler) reveal(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	ctx := r.Context()
	name, value, err := h.Service.Reveal(ctx, organizationID, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Revealing a secret is sensitive — always audit it, and note it on the
	// secret.
	tx, err := h.Service.Pool().Begin(ctx)
	if err == nil {
		defer tx.Rollback(ctx)
		var userID *uuid.UUID
		credential := ""
		if p := httpx.PrincipalFromCtx(ctx); p != nil {
			userID = p.UserID
			if p.ActorType != "" && p.ActorType != "user" {
				credential = p.Subject
			}
		}
		aerr := h.recordAudit(ctx, tx, r, organizationID, id, "secret.revealed", map[string]any{"name": name})
		if aerr == nil {
			aerr = h.Service.MarkRevealed(ctx, tx, organizationID, id, userID, credential)
		}
		if aerr == nil {
			_ = tx.Commit(ctx)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"value": value})
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

// vaultGet returns a vault secret's value to a scoped principal (e.g. an AI
// agent fetching a credential at runtime). Organization comes from the caller's
// token; access requires a matching vault scope and is always audited.
func (h *Handler) vaultGet(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	name := chi.URLParam(r, "name")
	if !hasVaultScope(p.Scopes, name) {
		httpx.WriteError(w, r, errs.ErrSecretScopeRequired)
		return
	}
	ctx := r.Context()
	id, value, err := h.Service.GetByName(ctx, organizationID, name)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Credential access is sensitive — always audit it.
	tx, terr := h.Service.Pool().Begin(ctx)
	if terr == nil {
		defer tx.Rollback(ctx)
		if aerr := h.recordAudit(ctx, tx, r, organizationID, id, "vault.accessed", map[string]any{"name": name}); aerr == nil {
			_ = tx.Commit(ctx)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"name": name, "value": value})
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	ctx := r.Context()
	if err := h.Service.Delete(ctx, organizationID, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tx, err := h.Service.Pool().Begin(ctx)
	if err == nil {
		defer tx.Rollback(ctx)
		if aerr := h.recordAudit(ctx, tx, r, organizationID, id, "secret.deleted", nil); aerr == nil {
			_ = tx.Commit(ctx)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
