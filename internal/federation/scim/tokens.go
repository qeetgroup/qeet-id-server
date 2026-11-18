package scim

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/scim/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

const (
	defaultTokenName    = "SCIM token" // the name of a token issued without one
	maxTokenNameLen     = 200          // the longest token name, in characters
	maxLiveTokens       = 10           // working, unrotated tokens an organization may hold
	defaultOverlapHours = 7 * 24       // how long a rotated token keeps working by default
	maxOverlapHours     = 30 * 24      // the longest a rotated token may keep working
	lastUsedEvery       = time.Minute  // how often a token's last use is written; TouchScimTokenUsed agrees
)

// A token's status.
const (
	TokenActive  = "active"  // works and hasn't been rotated
	TokenRotated = "rotated" // replaced, and works until its overlap ends
	TokenExpired = "expired" // past its expiry
	TokenRevoked = "revoked" // revoked
)

// Token is a SCIM bearer token as an administrator sees it. The token itself
// is shown only when it is issued.
type Token struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	TokenPrefix string     `json:"token_prefix"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
	ReplacedBy  *uuid.UUID `json:"replaced_by"`
}

// Works reports whether an identity provider can present the token.
func (t *Token) Works() bool { return t.Status == TokenActive || t.Status == TokenRotated }

// toToken is a token row as seen at now. Every token query returns the same
// columns, so each row converts to ListScimTokensRow.
func toToken(r dbgen.ListScimTokensRow, now time.Time) Token {
	t := Token{
		ID: r.ID, Name: r.Name, TokenPrefix: r.TokenPrefix, CreatedAt: r.CreatedAt,
		ExpiresAt: r.ExpiresAt, LastUsedAt: r.LastUsedAt, RevokedAt: r.RevokedAt,
	}
	t.ReplacedBy = r.ReplacedBy
	switch {
	case t.RevokedAt != nil:
		t.Status = TokenRevoked
	case t.ExpiresAt != nil && !now.Before(*t.ExpiresAt):
		t.Status = TokenExpired
	case t.ReplacedBy != nil:
		t.Status = TokenRotated
	default:
		t.Status = TokenActive
	}
	return t
}

// ConfigView is the admin-facing status of an organization's SCIM endpoint, from the
// tokens that work: the newest one's prefix and creation, the latest use of
// any, and how many there are. The token itself is never returned here.
type ConfigView struct {
	TokenSet         bool       `json:"token_set"`
	TokenPrefix      string     `json:"token_prefix,omitempty"`
	CreatedAt        *time.Time `json:"created_at"`
	LastUsedAt       *time.Time `json:"last_used_at"`
	TokenCount       int        `json:"token_count"`
	ProvisionedCount int        `json:"provisioned_count"`
	// LastRequest is the last change the identity provider sent, nil before
	// the first.
	LastRequest *LastRequest `json:"last_request"`
}

// LastRequest is how a change the identity provider sent was answered: Status
// is success, warning or failed, ErrorCode the directory's (DIR-409, say) and
// Reason the SCIM error type, when the answer gave one.
type LastRequest struct {
	At         time.Time `json:"at"`
	Operation  string    `json:"operation"`
	Resource   string    `json:"resource"`
	HTTPStatus int       `json:"http_status"`
	Status     string    `json:"status"`
	ErrorCode  string    `json:"error_code,omitempty"`
	Reason     string    `json:"reason,omitempty"`
}

// Config returns the organization's SCIM settings, without its tokens.
func (s *Service) Config(ctx context.Context, organizationID uuid.UUID) (*ConfigView, error) {
	tokens, err := s.Tokens(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	v := &ConfigView{}
	for i := range tokens {
		t := &tokens[i]
		if !t.Works() {
			continue
		}
		v.TokenCount++
		if !v.TokenSet { // newest first
			v.TokenSet, v.TokenPrefix = true, t.TokenPrefix
			created := t.CreatedAt
			v.CreatedAt = &created
		}
		if t.LastUsedAt != nil && (v.LastUsedAt == nil || t.LastUsedAt.After(*v.LastUsedAt)) {
			v.LastUsedAt = t.LastUsedAt
		}
	}
	count, err := s.q.CountProvisionedUsers(ctx, &organizationID)
	if err != nil {
		return nil, err
	}
	v.ProvisionedCount = int(count)
	last, err := s.q.LastSCIMOperation(ctx, dbgen.LastSCIMOperationParams{OrganizationID: organizationID, ConnectionID: "scim:" + organizationID.String()})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		v.LastRequest = &LastRequest{At: last.StartedAt, Operation: last.Operation, Resource: last.ResourceType,
			HTTPStatus: int(last.HttpStatus), Status: last.Status, ErrorCode: last.ErrorCode, Reason: last.Reason}
	}
	return v, nil
}

// Tokens lists the organization's SCIM tokens, newest first, including the
// revoked and expired ones.
func (s *Service) Tokens(ctx context.Context, organizationID uuid.UUID) ([]Token, error) {
	rows, err := s.q.ListScimTokens(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := make([]Token, 0, len(rows))
	for _, r := range rows {
		out = append(out, toToken(r, now))
	}
	return out, nil
}

// requirePlan refuses an organization whose plan doesn't include SCIM.
func (s *Service) requirePlan(ctx context.Context, organizationID uuid.UUID) error {
	ok, err := s.gate.FeatureAllowed(ctx, organizationID, "scim")
	if err != nil {
		return err
	}
	if !ok {
		return errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "scim"})
	}
	return nil
}

// issue stores a new token and returns it with its plaintext. Only the
// token's SHA-256 is kept, with a short prefix to recognise it by.
func (s *Service) issue(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, name string, expiresAt *time.Time) (*Token, string, error) {
	raw, _, err := codes.URLToken()
	if err != nil {
		return nil, "", err
	}
	full := tokenPrefix + raw
	row, err := s.q.WithTx(tx).InsertScimToken(ctx, dbgen.InsertScimTokenParams{
		OrganizationID: organizationID,
		Name:           name,
		TokenHash:      codes.Hash(full),
		TokenPrefix:    tokenPrefix + raw[:6],
		ExpiresAt:      expiresAt,
		CreatedBy:      httpx.PrincipalUserID(ctx),
	})
	if err != nil {
		return nil, "", err
	}
	t := toToken(dbgen.ListScimTokensRow(row), time.Now())
	return &t, full, nil
}

// Rotate issues a token in place of every one the organization holds, which
// stop at once, recorded as actor's, and returns it with its plaintext, shown
// only now.
func (s *Service) Rotate(ctx context.Context, organizationID uuid.UUID, actor audit.Actor) (*Token, string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)
	t, full, err := s.replaceAll(ctx, tx, organizationID)
	if err != nil {
		return nil, "", err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "scim.token_rotated", "scim_token", t.ID,
		map[string]any{"name": t.Name, "replaced": "all"})); err != nil {
		return nil, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return t, full, nil
}

func (s *Service) replaceAll(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID) (*Token, string, error) {
	if err := s.requirePlan(ctx, organizationID); err != nil {
		return nil, "", err
	}
	t, full, err := s.issue(ctx, tx, organizationID, defaultTokenName, nil)
	if err != nil {
		return nil, "", err
	}
	if _, err := s.q.WithTx(tx).RevokeLiveScimTokens(ctx, dbgen.RevokeLiveScimTokensParams{
		Replacement:    &t.ID,
		OrganizationID: organizationID,
	}); err != nil {
		return nil, "", err
	}
	return t, full, nil
}

// Revoke stops every token of the organization, which ends provisioning,
// recorded as actor's.
func (s *Service) Revoke(ctx context.Context, organizationID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).RevokeLiveScimTokens(ctx, dbgen.RevokeLiveScimTokensParams{OrganizationID: organizationID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "scim.token_revoked", "scim_token", uuid.Nil, nil)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// TokenInput is what CreateToken takes. A token without an expiry works
// until it is revoked or rotated.
type TokenInput struct {
	Name      string     `json:"name"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// RotateInput is what RotateToken takes. Without OverlapHours the old token
// keeps working for a week; 0 stops it at once. ExpiresAt is the new token's.
type RotateInput struct {
	OverlapHours *int32     `json:"overlap_hours"`
	ExpiresAt    *time.Time `json:"expires_at"`
}

func checkExpiry(expiresAt *time.Time) error {
	if expiresAt != nil && !expiresAt.After(time.Now()) {
		return ErrTokenExpiryInvalid
	}
	return nil
}

// CreateToken issues a named token for the organization, recorded as actor's,
// and returns it with its plaintext, shown only now.
func (s *Service) CreateToken(ctx context.Context, organizationID uuid.UUID, in TokenInput, actor audit.Actor) (*Token, string, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" || utf8.RuneCountInString(name) > maxTokenNameLen {
		return nil, "", ErrTokenNameInvalid
	}
	if err := checkExpiry(in.ExpiresAt); err != nil {
		return nil, "", err
	}
	if err := s.requirePlan(ctx, organizationID); err != nil {
		return nil, "", err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)
	live, err := s.q.WithTx(tx).CountLiveScimTokens(ctx, organizationID)
	if err != nil {
		return nil, "", err
	}
	if live >= maxLiveTokens {
		return nil, "", ErrTokenLimit.WithMetadata(map[string]any{"limit": maxLiveTokens})
	}
	t, full, err := s.issue(ctx, tx, organizationID, name, in.ExpiresAt)
	if err != nil {
		return nil, "", err
	}
	meta := map[string]any{"name": t.Name}
	if t.ExpiresAt != nil {
		meta["expires_at"] = t.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "scim.token_created", "scim_token", t.ID, meta)); err != nil {
		return nil, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return t, full, nil
}

// RotateToken issues a token in place of one of the organization's, under its
// name, recorded as actor's. The old token keeps working until the overlap
// ends, so the identity provider can switch without a gap. It returns the new
// token with its plaintext, shown only now, and the old one.
func (s *Service) RotateToken(ctx context.Context, organizationID, id uuid.UUID, in RotateInput, actor audit.Actor) (fresh, old *Token, full string, err error) {
	overlap := int32(defaultOverlapHours)
	if in.OverlapHours != nil {
		overlap = *in.OverlapHours
	}
	if overlap < 0 || overlap > maxOverlapHours {
		return nil, nil, "", ErrTokenOverlapInvalid
	}
	if err := checkExpiry(in.ExpiresAt); err != nil {
		return nil, nil, "", err
	}
	if err := s.requirePlan(ctx, organizationID); err != nil {
		return nil, nil, "", err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	row, err := q.LockScimToken(ctx, dbgen.LockScimTokenParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, "", ErrTokenNotFound
	}
	if err != nil {
		return nil, nil, "", err
	}
	if current := toToken(dbgen.ListScimTokensRow(row), time.Now()); current.Status != TokenActive {
		return nil, nil, "", ErrTokenInactive
	}
	fresh, full, err = s.issue(ctx, tx, organizationID, row.Name, in.ExpiresAt)
	if err != nil {
		return nil, nil, "", err
	}
	replaced, err := q.ReplaceScimToken(ctx, dbgen.ReplaceScimTokenParams{
		ReplacedBy:     &fresh.ID,
		OverlapHours:   overlap,
		ID:             id,
		OrganizationID: organizationID,
	})
	if err != nil {
		return nil, nil, "", err
	}
	o := toToken(dbgen.ListScimTokensRow(replaced), time.Now())
	meta := map[string]any{"name": o.Name, "replaced_by": fresh.ID.String(), "overlap_hours": overlap}
	if o.ExpiresAt != nil {
		meta["works_until"] = o.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "scim.token_rotated", "scim_token", id, meta)); err != nil {
		return nil, nil, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, "", err
	}
	return fresh, &o, full, nil
}

// RevokeToken stops one of the organization's tokens at once, recorded as
// actor's.
func (s *Service) RevokeToken(ctx context.Context, organizationID, id uuid.UUID, actor audit.Actor) (*Token, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).RevokeScimToken(ctx, dbgen.RevokeScimTokenParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTokenNotFound
	}
	if err != nil {
		return nil, err
	}
	t := toToken(dbgen.ListScimTokensRow(row), time.Now())
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "scim.token_revoked", "scim_token", id, map[string]any{"name": t.Name})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &t, nil
}

// resolveToken maps a presented bearer token to its organization. It refuses
// a token that is revoked or expired, and every token of an organization that
// is suspended or due for deletion, and records the token's use at most once
// a minute.
func (s *Service) resolveToken(ctx context.Context, raw string) (uuid.UUID, error) {
	row, err := s.q.ResolveScimToken(ctx, codes.Hash(raw))
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, errs.ErrUnauthorized
	}
	if err != nil {
		return uuid.Nil, err
	}
	if row.LastUsedAt == nil || time.Since(*row.LastUsedAt) >= lastUsedEvery {
		// Best-effort; never block the request on it.
		_ = s.q.TouchScimTokenUsed(ctx, dbgen.TouchScimTokenUsedParams{ID: row.ID, OrganizationID: row.OrganizationID})
	}
	return row.OrganizationID, nil
}
