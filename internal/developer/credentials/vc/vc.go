// Package vc issues and verifies W3C Verifiable Credentials in the JWT
// serialization (JWT-VC): signed by the platform issuer (verifiable via the
// same JWKS), tracked in auth.credentials for listing/revocation. Verification
// checks signature + issuer + expiry, then the revocation registry.
package vc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/vc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

const vcContext = "https://www.w3.org/ns/credentials/v2"

// Service issues, verifies and revokes verifiable credentials.
type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	issuer *tokens.Issuer
}

// NewService returns the verifiable credential service.
func NewService(pool *pgxpool.Pool, issuer *tokens.Issuer) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), issuer: issuer}
}

// Credential is an issued verifiable credential, as recorded. User is the
// person it was issued to, when the issuer named one.
type Credential struct {
	ID        uuid.UUID  `json:"id"`
	Subject   string     `json:"subject"`
	Type      string     `json:"type"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Revoked   bool       `json:"revoked"`
	User      *Holder    `json:"user"`
}

// Holder is the person a credential was issued to.
type Holder struct {
	ID          uuid.UUID `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
}

// IssueInput is a credential to issue. TTLSeconds <= 0 issues one that never
// expires. UserID, optional, is the person it is for, a member of the
// organization; the signed credential doesn't carry it.
type IssueInput struct {
	Subject    string         `json:"subject"`
	Type       string         `json:"type"`
	Claims     map[string]any `json:"claims"`
	TTLSeconds int            `json:"ttl_seconds"`
	UserID     *uuid.UUID     `json:"user_id"`
}

// IssueResult is an issued credential and its signed JWT-VC.
type IssueResult struct {
	CredentialID uuid.UUID  `json:"credential_id"`
	JWT          string     `json:"jwt"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

// Issue records a credential and returns its signed JWT-VC, recorded as
// actor's.
func (s *Service) Issue(ctx context.Context, organizationID uuid.UUID, in IssueInput, actor audit.Actor) (*IssueResult, error) {
	subject := strings.TrimSpace(in.Subject)
	credType := strings.TrimSpace(in.Type)
	claims, ttlSeconds := in.Claims, in.TTLSeconds
	if subject == "" || credType == "" {
		return nil, ErrSubjectTypeRequired
	}
	var holder *uuid.UUID
	if in.UserID != nil {
		member, err := s.q.IsOrganizationMember(ctx, dbgen.IsOrganizationMemberParams{UserID: *in.UserID, OrganizationID: organizationID})
		if err != nil {
			return nil, err
		}
		if !member {
			return nil, ErrUserNotMember
		}
		holder = in.UserID
	}
	if claims == nil {
		claims = map[string]any{}
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, ErrClaimsInvalid
	}
	now := time.Now().UTC()
	var expiresAt *time.Time
	if ttlSeconds > 0 {
		e := now.Add(time.Duration(ttlSeconds) * time.Second)
		expiresAt = &e
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).CreateCredential(ctx, dbgen.CreateCredentialParams{
		OrganizationID: organizationID,
		Subject:        subject,
		Type:           credType,
		Claims:         claimsJSON,
		ExpiresAt:      expiresAt,
		UserID:         holder,
	})
	if err != nil {
		return nil, err
	}
	id, issuedAt := row.ID, row.IssuedAt

	// credentialSubject = { id: <subject>, ...claims }.
	subjectObj := map[string]any{"id": subject}
	for k, v := range claims {
		if k != "id" {
			subjectObj[k] = v
		}
	}
	reg := jwt.RegisteredClaims{
		Issuer:    s.issuer.JWTIssuer(),
		Subject:   subject,
		ID:        id.String(), // jti — the revocation key
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		NotBefore: jwt.NewNumericDate(issuedAt),
	}
	if expiresAt != nil {
		reg.ExpiresAt = jwt.NewNumericDate(*expiresAt)
	}
	type vcClaims struct {
		VC map[string]any `json:"vc"`
		jwt.RegisteredClaims
	}
	signed, err := s.issuer.Sign(vcClaims{
		VC: map[string]any{
			"@context":          []string{vcContext},
			"type":              []string{"VerifiableCredential", credType},
			"issuer":            s.issuer.JWTIssuer(),
			"credentialSubject": subjectObj,
		},
		RegisteredClaims: reg,
	})
	if err != nil {
		return nil, err
	}
	result := &IssueResult{CredentialID: id, JWT: signed, ExpiresAt: expiresAt}
	metadata := map[string]any{"subject": subject, "type": credType, "expires_at": expiresAt}
	if in.UserID != nil {
		metadata["user_id"] = *in.UserID
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "credential.issued", "credential", id, metadata)); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "credential.events", EventType: "credential.issued", Payload: map[string]any{"credential_id": id, "organization_id": organizationID, "subject": subject, "type": credType, "expires_at": expiresAt}}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

// VerifyResult is whether a presented credential is valid and, if not, why:
// ReasonCode is one of the Reason* codes, Reason the same in English.
type VerifyResult struct {
	Valid      bool           `json:"valid"`
	Reason     string         `json:"reason,omitempty"`
	ReasonCode string         `json:"reason_code,omitempty"`
	Subject    string         `json:"subject,omitempty"`
	Issuer     string         `json:"issuer,omitempty"`
	VC         map[string]any `json:"vc,omitempty"`
}

// Why a presented credential is invalid.
const (
	ReasonNotVC            = "vc.not_credential"    // not a JWT-VC
	ReasonSignatureInvalid = "vc.signature_invalid" // a bad signature, or expired
	ReasonUnknown          = "vc.unknown"           // not one this server issued
	ReasonRevoked          = "vc.revoked"           // revoked by its issuer
)

// invalid is the result for a credential refused with code.
func invalid(code string) *VerifyResult {
	reason := map[string]string{
		ReasonNotVC:            "not a verifiable credential",
		ReasonSignatureInvalid: "signature or expiry invalid",
		ReasonUnknown:          "unknown credential",
		ReasonRevoked:          "credential revoked",
	}[code]
	return &VerifyResult{Valid: false, Reason: reason, ReasonCode: code}
}

// Verify checks a presented JWT-VC: signature + issuer + expiry (cryptographic)
// then the revocation registry. Only verifies credentials this server issued.
func (s *Service) Verify(ctx context.Context, raw string) (*VerifyResult, error) {
	claims, err := s.issuer.VerifyVC(raw)
	if errors.Is(err, tokens.ErrNotCredential) {
		return invalid(ReasonNotVC), nil
	}
	if err != nil {
		return invalid(ReasonSignatureInvalid), nil //nolint:nilerr // an invalid credential is a result, not an error
	}
	res := &VerifyResult{Valid: true}
	if sub, _ := claims["sub"].(string); sub != "" {
		res.Subject = sub
	}
	if iss, _ := claims["iss"].(string); iss != "" {
		res.Issuer = iss
	}
	if vcObj, ok := claims["vc"].(map[string]any); ok {
		res.VC = vcObj
	}
	// jti is the credential's id in the registry. Every credential this server
	// issues has a record, so one without is not ours to vouch for.
	jti, _ := claims["jti"].(string)
	id, err := uuid.Parse(jti)
	if err != nil {
		return invalid(ReasonUnknown), nil //nolint:nilerr // an invalid credential is a result, not an error
	}
	revokedAt, err := s.q.GetCredentialRevocation(ctx, id)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return invalid(ReasonUnknown), nil
	case err != nil:
		return nil, err
	case revokedAt != nil:
		return invalid(ReasonRevoked), nil
	}
	return res, nil
}

// List returns the organization's credentials.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Credential, error) {
	rows, err := s.q.ListCredentials(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Credential, 0, len(rows))
	for _, row := range rows {
		out = append(out, Credential{
			ID:        row.ID,
			Subject:   row.Subject,
			Type:      row.Type,
			IssuedAt:  row.IssuedAt,
			ExpiresAt: row.ExpiresAt,
			Revoked:   row.RevokedAt != nil,
			User:      holderOf(row),
		})
	}
	return out, nil
}

// holderOf is the person row's credential was issued to, or nil.
func holderOf(row dbgen.ListCredentialsRow) *Holder {
	if row.UserID == nil {
		return nil
	}
	h := &Holder{ID: *row.UserID}
	if row.UserEmail != nil {
		h.Email = *row.UserEmail
	}
	if row.UserDisplayName != nil {
		h.DisplayName = *row.UserDisplayName
	}
	return h
}

// Revoke marks one of the organization's credentials revoked, so Verify refuses it,
// recorded as actor's.
func (s *Service) Revoke(ctx context.Context, id, organizationID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).RevokeCredential(ctx, dbgen.RevokeCredentialParams{ID: id, OrganizationID: organizationID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrVCCredentialNotFound
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "credential.revoked", "credential", id, nil)); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "credential.events", EventType: "credential.revoked", Payload: map[string]any{"credential_id": id, "organization_id": organizationID}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
