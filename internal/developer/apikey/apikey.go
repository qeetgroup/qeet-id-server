// Package apikey issues long-lived bearer tokens for programmatic access.
// A key is `<prefix>.<secret>`; we store the prefix (for lookup) and the
// SHA-256 hash of the secret. The plaintext is shown to the caller exactly
// once at creation.
package apikey

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/developer/apikey/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Key is an API key, without its secret.
type Key struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	UserID         *uuid.UUID `json:"user_id"`
	Name           string     `json:"name"`
	Prefix         string     `json:"prefix"`
	Scopes         []string   `json:"scopes"`
	ExpiresAt      *time.Time `json:"expires_at"`
	LastUsedAt     *time.Time `json:"last_used_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
	CreatedAt      time.Time  `json:"created_at"`
	// CreatedBy is who created it, and RotatedFrom the key it replaced.
	CreatedBy   *uuid.UUID `json:"created_by"`
	RotatedFrom *uuid.UUID `json:"rotated_from"`
}

// Service manages the API keys.
type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	limits entitlements.PlanLimiter
}

// NewService returns the API key service, which caps an organization's keys
// at its plan's api_keys limit from limits. It refuses a nil limits.
func NewService(pool *pgxpool.Pool, limits entitlements.PlanLimiter) (*Service, error) {
	if limits == nil {
		return nil, errors.New("apikey: a plan limiter is required to cap an organization's keys")
	}
	return &Service{pool: pool, q: dbgen.New(pool), limits: limits}, nil
}

// CountActive returns the organization's number of non-revoked API keys — the
// "api_keys" limit value, surfaced as usage in billing.
func (s *Service) CountActive(ctx context.Context, organizationID uuid.UUID) (int, error) {
	n, err := s.q.CountActiveAPIKeys(ctx, organizationID)
	return int(n), err
}

func generateRaw() (prefix, secret, full string, err error) {
	pb := make([]byte, 6)
	sb := make([]byte, 24)
	if _, err = rand.Read(pb); err != nil {
		return
	}
	if _, err = rand.Read(sb); err != nil {
		return
	}
	prefix = "qk_" + base64.RawURLEncoding.EncodeToString(pb)
	secret = base64.RawURLEncoding.EncodeToString(sb)
	full = prefix + "." + secret
	return
}

// rowToKey maps a generated row to the domain Key.
func rowToKey(id uuid.UUID, organizationID uuid.UUID, userID *uuid.UUID, name, prefix string,
	scopes []string, expiresAt, lastUsedAt, revokedAt *time.Time, createdAt time.Time) Key {
	return Key{
		ID:             id,
		OrganizationID: organizationID,
		UserID:         userID,
		Name:           name,
		Prefix:         prefix,
		Scopes:         scopes,
		ExpiresAt:      expiresAt,
		LastUsedAt:     lastUsedAt,
		RevokedAt:      revokedAt,
		CreatedAt:      createdAt,
	}
}

// maxNameLength is the most characters a key's name may have.
const maxNameLength = 200

// CreateInput is what Create takes. OrganizationID is set from the caller's
// token; one sent in the body is ignored.
type CreateInput struct {
	OrganizationID uuid.UUID  `json:"organization_id"`
	UserID         *uuid.UUID `json:"user_id"`
	Name           string     `json:"name"`
	Scopes         []string   `json:"scopes"`
	ExpiresAt      *time.Time `json:"expires_at"`
	// Actor is who is creating the key, set by the handler from the caller and
	// never from the body. A key may act only for Actor.UserID, or for no one.
	Actor audit.Actor `json:"-"`
}

// Create issues an API key and returns it with its plaintext secret, shown
// only now.
func (s *Service) Create(ctx context.Context, in CreateInput) (*Key, string, error) {
	if in.Name == "" {
		return nil, "", ErrNameRequired
	}
	if utf8.RuneCountInString(in.Name) > maxNameLength {
		return nil, "", errs.ErrValidationFailed.WithFields([]errs.FieldError{{
			Field: "name", Code: "too_long", Message: fmt.Sprintf("Must be at most %d characters.", maxNameLength),
		}})
	}
	// A key presents itself as its user on every call, so it may act only for
	// the person creating it. Naming anyone else, a colleague or someone in
	// another organization, would let the creator act as them.
	if in.UserID != nil && (in.Actor.UserID == nil || *in.UserID != *in.Actor.UserID) {
		return nil, "", ErrUserNotSelf
	}
	if err := rbac.ValidateMachineScopes(in.Scopes); err != nil {
		return nil, "", err
	}
	// Plan gate: refuse once the organization's plan cap for API keys is reached. The
	// resource key ("api_keys") matches the entitlements catalog.
	lim, err := s.limits.Limit(ctx, in.OrganizationID, "api_keys")
	if err != nil {
		return nil, "", err
	}
	if lim >= 0 {
		n, err := s.q.CountActiveAPIKeys(ctx, in.OrganizationID)
		if err != nil {
			return nil, "", err
		}
		if int(n) >= lim {
			return nil, "", errs.ErrPlanLimit.WithMetadata(map[string]any{"resource": "api_keys", "limit": lim})
		}
	}
	prefix, secret, full, err := generateRaw()
	if err != nil {
		return nil, "", err
	}
	secretHash := password.HashSecret(secret)
	// scopes is NOT NULL DEFAULT '{}'; a nil Go slice encodes as SQL NULL, so
	// coalesce to empty for callers that omit it.
	if in.Scopes == nil {
		in.Scopes = []string{}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).CreateAPIKey(ctx, dbgen.CreateAPIKeyParams{
		OrganizationID: in.OrganizationID,
		UserID:         in.UserID,
		Name:           in.Name,
		Prefix:         prefix,
		KeyHash:        secretHash,
		Scopes:         in.Scopes,
		ExpiresAt:      in.ExpiresAt,
		CreatedBy:      in.Actor.UserID,
	})
	if err != nil {
		return nil, "", err
	}
	k := rowToKey(row.ID, row.OrganizationID, row.UserID, row.Name, row.Prefix,
		row.Scopes, row.ExpiresAt, row.LastUsedAt, row.RevokedAt, row.CreatedAt)
	k.CreatedBy, k.RotatedFrom = row.CreatedBy, row.RotatedFrom
	meta := map[string]any{"name": k.Name, "scopes": k.Scopes}
	if k.UserID != nil {
		meta["user_id"] = k.UserID.String()
	}
	if err := audit.Record(ctx, tx, in.Actor.Event(in.OrganizationID, "apikey.created", "api_key", k.ID, meta)); err != nil {
		return nil, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return &k, full, nil
}

// List returns the organization's API keys.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Key, error) {
	rows, err := s.q.ListAPIKeys(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Key, 0, len(rows))
	for _, row := range rows {
		k := rowToKey(row.ID, row.OrganizationID, row.UserID, row.Name, row.Prefix,
			row.Scopes, row.ExpiresAt, row.LastUsedAt, row.RevokedAt, row.CreatedAt)
		k.CreatedBy, k.RotatedFrom = row.CreatedBy, row.RotatedFrom
		out = append(out, k)
	}
	return out, nil
}

// Revoke revokes one of the organization's API keys, recorded as actor's.
func (s *Service) Revoke(ctx context.Context, organizationID, id uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).RevokeAPIKey(ctx, dbgen.RevokeAPIKeyParams{ID: id, OrganizationID: organizationID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrAPIKeyNotFound
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "apikey.revoked", "api_key", id, map[string]any{})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Verify resolves a presented `<prefix>.<secret>` to its organization + scopes,
// or returns an error if the key is unknown, expired, or revoked.
func (s *Service) Verify(ctx context.Context, raw string) (*Key, error) {
	parts := strings.SplitN(raw, ".", 2)
	if len(parts) != 2 {
		return nil, ErrInvalid
	}
	prefix, secret := parts[0], parts[1]

	row, err := s.q.VerifyAPIKey(ctx, prefix)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalid
	}
	if err != nil {
		return nil, err
	}
	if !password.VerifySecret(row.KeyHash, secret) {
		return nil, ErrInvalid
	}
	k := rowToKey(row.ID, row.OrganizationID, row.UserID, row.Name, row.Prefix,
		row.Scopes, row.ExpiresAt, row.LastUsedAt, row.RevokedAt, row.CreatedAt)
	if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
		return nil, ErrExpired
	}
	// Best-effort, detached from the request but time-bounded so it can't leak.
	go func(id uuid.UUID) { // #nosec G118 -- detached on purpose, with its own timeout
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.q.TouchAPIKeyLastUsed(ctx, id); err != nil {
			slog.Warn("apikey last_used_at update failed", "err", err, "api_key_id", id)
		}
	}(k.ID)
	return &k, nil
}

// Live reports whether organizationID's key id would still authenticate a request:
// it isn't revoked or expired, and the person it acts for, if any, is active.
func (s *Service) Live(ctx context.Context, organizationID, id uuid.UUID) (bool, error) {
	return s.q.APIKeyLive(ctx, dbgen.APIKeyLiveParams{ID: id, OrganizationID: organizationID})
}

// Middleware authenticates the request if it carries `Authorization:
// ApiKey <raw>`. On success the principal is attached and ActorType is
// "api_key"; on failure we fall through so the next middleware can try.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "ApiKey ") {
			raw := strings.TrimSpace(auth[len("ApiKey "):])
			k, err := s.Verify(r.Context(), raw)
			if err != nil {
				httpx.WriteError(w, r, err)
				return
			}
			p := &httpx.Principal{
				ActorType: "api_key",
				Subject:   k.ID.String(),
				Scopes:    k.Scopes,
				ExpiresAt: k.ExpiresAt,
			}
			organization := k.OrganizationID
			p.OrganizationID = &organization
			if k.UserID != nil {
				uid := *k.UserID
				p.UserID = &uid
			}
			next.ServeHTTP(w, r.WithContext(httpx.WithPrincipal(r.Context(), p)))
			return
		}
		next.ServeHTTP(w, r)
	})
}
