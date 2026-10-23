// Package secret is a per-tenant secrets vault. Values are encrypted at rest with
// AES-256-GCM and never returned except via an explicit, audited reveal. The
// data-encryption key comes from a KeyProvider (keyprovider.go), unwrapped once at
// startup — independent of the JWT secret and swappable for a KMS-backed provider.
package secret

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
}

// Service stores each tenant's secrets, encrypted at rest.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
	box  *envelope.Cipher
}

// NewService builds the vault, unwrapping the data key from the provider once.
// The key must be 16, 24, or 32 bytes (AES-128/192/256).
func NewService(ctx context.Context, pool *pgxpool.Pool, kp KeyProvider) (*Service, error) {
	key, err := kp.DataKey(ctx)
	if err != nil {
		return nil, err
	}
	box, err := envelope.New(key)
	if err != nil {
		return nil, err
	}
	return &Service{pool: pool, q: dbgen.New(pool), box: box}, nil
}

// Pool returns the connection pool, for handlers that run their own transaction.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

func (s *Service) encrypt(tenantID uuid.UUID, name, plaintext string) (ciphertext, nonce []byte, err error) {
	return s.box.Seal(tenantID, "secret", name, []byte(plaintext))
}

func (s *Service) decrypt(tenantID uuid.UUID, name string, ciphertext, nonce []byte) (string, error) {
	pt, err := s.box.Open(tenantID, "secret", name, ciphertext, nonce)
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

// rowToSecret maps a sqlc result row (id, name, scope, last4, created_at, updated_at) to Secret.
func rowToSecret(id uuid.UUID, name, scope, last4 string, createdAt, updatedAt time.Time) *Secret {
	return &Secret{ID: id, Name: name, Scope: scope, Last4: last4, CreatedAt: createdAt, UpdatedAt: updatedAt}
}

// metaCols is the column list the hand-written Update queries return, in the
// order scanSecret reads.
const metaCols = `id, name, scope, last4, created_at, updated_at`

// List returns the tenant's secrets.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Secret, error) {
	rows, err := s.q.ListSecrets(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := []Secret{}
	for _, row := range rows {
		out = append(out, *rowToSecret(row.ID, row.Name, row.Scope, row.Last4, row.CreatedAt, row.UpdatedAt))
	}
	return out, nil
}

// Create stores a secret for the tenant.
func (s *Service) Create(ctx context.Context, tenantID uuid.UUID, name, scope, value string) (*Secret, error) {
	name = strings.TrimSpace(name)
	if name == "" || value == "" {
		return nil, errs.ErrSecretNameValueRequired
	}
	ct, nonce, err := s.encrypt(tenantID, name, value)
	if err != nil {
		return nil, err
	}
	row, err := s.q.CreateSecret(ctx, dbgen.CreateSecretParams{
		TenantID:   tenantID,
		Name:       name,
		Scope:      scope,
		Ciphertext: ct,
		Nonce:      nonce,
		Last4:      hint(value),
	})
	if err != nil {
		if strings.Contains(err.Error(), "secrets_tenant_id_name_key") || strings.Contains(err.Error(), "duplicate") {
			return nil, errs.ErrSecretNameExists
		}
		return nil, err
	}
	return rowToSecret(row.ID, row.Name, row.Scope, row.Last4, row.CreatedAt, row.UpdatedAt), nil
}

// UpdateInput is what Update takes.
type UpdateInput struct {
	Scope *string `json:"scope"`
	Value *string `json:"value"`
}

// Update changes a secret's value and/or scope; a nil field is kept. It is
// hand-written because sqlc reads the NOT NULL scope column as a plain string,
// so nil couldn't mean "no change".
func (s *Service) Update(ctx context.Context, tenantID, id uuid.UUID, in UpdateInput) (*Secret, error) {
	// Rotate the encrypted value only when a new one is supplied.
	if in.Value != nil {
		if *in.Value == "" {
			return nil, errs.ErrSecretValueRequired
		}
		current, err := s.q.RevealSecret(ctx, dbgen.RevealSecretParams{ID: id, TenantID: tenantID})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrSecretNotFound
		}
		if err != nil {
			return nil, err
		}
		ct, nonce, err := s.encrypt(tenantID, current.Name, *in.Value)
		if err != nil {
			return nil, err
		}
		row := s.pool.QueryRow(ctx, `
			UPDATE tenant.secrets
			SET ciphertext = $3, nonce = $4, last4 = $5, scope = COALESCE($6, scope), updated_at = NOW()
			WHERE id = $1 AND tenant_id = $2
			RETURNING `+metaCols,
			id, tenantID, ct, nonce, hint(*in.Value), in.Scope)
		return scanSecret(row)
	}
	row := s.pool.QueryRow(ctx, `
		UPDATE tenant.secrets SET scope = COALESCE($3, scope), updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2
		RETURNING `+metaCols,
		id, tenantID, in.Scope)
	return scanSecret(row)
}

// scanSecret scans a row of metaCols into a Secret; no row is ErrSecretNotFound.
func scanSecret(row pgx.Row) (*Secret, error) {
	var sec Secret
	if err := row.Scan(&sec.ID, &sec.Name, &sec.Scope, &sec.Last4, &sec.CreatedAt, &sec.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrSecretNotFound
		}
		return nil, err
	}
	return &sec, nil
}

// Reveal returns one of the tenant's secrets: its name and decrypted value.
func (s *Service) Reveal(ctx context.Context, tenantID, id uuid.UUID) (string, string, error) {
	row, err := s.q.RevealSecret(ctx, dbgen.RevealSecretParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", errs.ErrSecretNotFound
	}
	if err != nil {
		return "", "", err
	}
	val, err := s.decrypt(tenantID, row.Name, row.Ciphertext, row.Nonce)
	if err != nil {
		return "", "", errs.ErrSecretDecryptFailed.Wrap(err)
	}
	return row.Name, val, nil
}

// GetByName decrypts a secret by its name (for agent/credential retrieval via
// the scoped vault endpoint). Returns the secret id (for auditing) + value.
func (s *Service) GetByName(ctx context.Context, tenantID uuid.UUID, name string) (uuid.UUID, string, error) {
	row, err := s.q.GetSecretByName(ctx, dbgen.GetSecretByNameParams{TenantID: tenantID, Name: name})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", errs.ErrSecretNotFound
	}
	if err != nil {
		return uuid.Nil, "", err
	}
	val, err := s.decrypt(tenantID, name, row.Ciphertext, row.Nonce)
	if err != nil {
		return uuid.Nil, "", errs.ErrSecretDecryptFailed.Wrap(err)
	}
	return row.ID, val, nil
}

// Delete removes one of the tenant's secrets.
func (s *Service) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	n, err := s.q.DeleteSecret(ctx, dbgen.DeleteSecretParams{ID: id, TenantID: tenantID})
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

func (h *Handler) recordAudit(ctx context.Context, tx pgx.Tx, r *http.Request, tenantID, resourceID uuid.UUID, action string, meta map[string]any) error {
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
	tid := tenantID
	rid := resourceID
	return audit.Record(ctx, tx, audit.Event{
		TenantID: &tid, ActorUserID: actorID, ActorType: actorType,
		Action: action, ResourceType: "secret", ResourceID: &rid,
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
		Metadata: meta,
	})
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.List(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		Name  string `json:"name"`
		Scope string `json:"scope"`
		Value string `json:"value"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	sec, err := h.Service.Create(ctx, tenantID, in.Name, in.Scope, in.Value)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tx, err := h.Service.Pool().Begin(ctx)
	if err == nil {
		defer tx.Rollback(ctx)
		if aerr := h.recordAudit(ctx, tx, r, tenantID, sec.ID, "secret.created", map[string]any{"name": sec.Name}); aerr == nil {
			_ = tx.Commit(ctx)
		}
	}
	httpx.WriteJSON(w, http.StatusCreated, sec)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
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
	sec, err := h.Service.Update(ctx, tenantID, id, in)
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
		if aerr := h.recordAudit(ctx, tx, r, tenantID, sec.ID, action, map[string]any{"name": sec.Name}); aerr == nil {
			_ = tx.Commit(ctx)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, sec)
}

func (h *Handler) reveal(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
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
	name, value, err := h.Service.Reveal(ctx, tenantID, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Revealing a secret is sensitive — always audit it.
	tx, err := h.Service.Pool().Begin(ctx)
	if err == nil {
		defer tx.Rollback(ctx)
		if aerr := h.recordAudit(ctx, tx, r, tenantID, id, "secret.revealed", map[string]any{"name": name}); aerr == nil {
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
// agent fetching a credential at runtime). Tenant comes from the caller's
// token; access requires a matching vault scope and is always audited.
func (h *Handler) vaultGet(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	tenantID, err := httpx.RequireTenant(r)
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
	id, value, err := h.Service.GetByName(ctx, tenantID, name)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Credential access is sensitive — always audit it.
	tx, terr := h.Service.Pool().Begin(ctx)
	if terr == nil {
		defer tx.Rollback(ctx)
		if aerr := h.recordAudit(ctx, tx, r, tenantID, id, "vault.accessed", map[string]any{"name": name}); aerr == nil {
			_ = tx.Commit(ctx)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"name": name, "value": value})
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
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
	if err := h.Service.Delete(ctx, tenantID, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tx, err := h.Service.Pool().Begin(ctx)
	if err == nil {
		defer tx.Rollback(ctx)
		if aerr := h.recordAudit(ctx, tx, r, tenantID, id, "secret.deleted", nil); aerr == nil {
			_ = tx.Commit(ctx)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
