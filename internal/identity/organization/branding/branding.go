// Package branding stores per-organization theming, custom-domain and email-sender
// settings.
package branding

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/organization/branding/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Branding is an organization's theming, custom domain and email sender.
type Branding struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	LogoURL        *string   `json:"logo_url"`
	PrimaryColor   *string   `json:"primary_color"`
	SecondaryColor *string   `json:"secondary_color"`
	CustomDomain   *string   `json:"custom_domain"`
	EmailFromName  *string   `json:"email_from_name"`
	// Deprecated: accepted and ignored, never returned. Email goes out from
	// the platform's address; settings.email_reply_to takes replies.
	EmailFromAddress *string        `json:"email_from_address,omitempty"`
	Settings         map[string]any `json:"settings"`
}

// Repository reads and writes organization branding.
type Repository struct {
	pool       *pgxpool.Pool
	q          *dbgen.Queries
	gate       entitlements.PlanGate
	publicBase string // this API's public origin, for links to an uploaded logo
}

// NewRepository returns a Repository over pool.
func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool, q: dbgen.New(pool)}
}

// SetPlanGate sets the plan-feature gate (nil allows all features).
func (r *Repository) SetPlanGate(g entitlements.PlanGate) { r.gate = g }

// brandingAllowed reports whether the organization's plan includes custom branding;
// a gate that can't answer counts as no, so the default look is shown.
func (r *Repository) brandingAllowed(ctx context.Context, organizationID uuid.UUID) bool {
	if r.gate == nil {
		return true
	}
	ok, err := r.gate.FeatureAllowed(ctx, organizationID, "custom_branding")
	return err == nil && ok
}

func toDomain(organizationID uuid.UUID, row dbgen.GetBrandingRow) *Branding {
	return &Branding{
		OrganizationID: row.OrganizationID,
		LogoURL:        row.LogoUrl,
		PrimaryColor:   row.PrimaryColor,
		SecondaryColor: row.SecondaryColor,
		CustomDomain:   row.CustomDomain,
		EmailFromName:  row.EmailFromName,
		Settings:       postgres.Metadata(row.Settings),
	}
}

// Get returns the organization's branding.
func (r *Repository) Get(ctx context.Context, organizationID uuid.UUID) (*Branding, error) {
	row, err := r.q.GetBranding(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return &Branding{OrganizationID: organizationID, Settings: map[string]any{}}, nil
	}
	if err != nil {
		return nil, err
	}
	return toDomain(organizationID, row), nil
}

// LoginBrandingReader returns an organization's hosted-login logo and colors.
// Satisfied by *Repository.
type LoginBrandingReader interface {
	LoginBranding(ctx context.Context, organizationID uuid.UUID) (logoURL, primaryColor, secondaryColor, backgroundColor string)
}

// LoginBranding returns the organization's hosted-login logo and colors as plain
// strings, empty when unset, on error, or when its plan lacks custom branding
// (the stored values are kept for an upgrade).
func (r *Repository) LoginBranding(ctx context.Context, organizationID uuid.UUID) (logoURL, primaryColor, secondaryColor, backgroundColor string) {
	if !r.brandingAllowed(ctx, organizationID) {
		return "", "", "", ""
	}
	b, err := r.Get(ctx, organizationID)
	if err != nil || b == nil {
		return "", "", "", ""
	}
	logoURL, primaryColor, secondaryColor, backgroundColor = loginAppearance(b)
	return r.publicLogo(organizationID, logoURL), primaryColor, secondaryColor, backgroundColor
}

func loginAppearance(b *Branding) (logoURL, primaryColor, secondaryColor, backgroundColor string) {
	if b.LogoURL != nil {
		logoURL = *b.LogoURL
	}
	if b.PrimaryColor != nil {
		primaryColor = *b.PrimaryColor
	}
	if b.SecondaryColor != nil {
		secondaryColor = *b.SecondaryColor
	}
	if value, ok := b.Settings["background_color"].(string); ok && colorPattern.MatchString(value) {
		backgroundColor = value
	}
	return logoURL, primaryColor, secondaryColor, backgroundColor
}

var colorPattern = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

const maxBrandingBodyBytes = int64(3 << 20)

func decodeBranding(r *http.Request) (Branding, error) {
	var in Branding
	if err := httpx.DecodeJSONLimit(r, &in, maxBrandingBodyBytes); err != nil {
		return Branding{}, err
	}
	return in, normalizeAppearance(&in)
}

func normalizeAppearance(b *Branding) error {
	if b.LogoURL != nil && strings.HasPrefix(*b.LogoURL, "data:") {
		header, content, found := strings.Cut(*b.LogoURL, ",")
		if _, known := logoTypes[header]; !found || !known {
			return errs.ErrBadRequest.WithDetail("logo must be a PNG, JPEG, WEBP or SVG image")
		}
		if len(content) > base64.StdEncoding.EncodedLen(2<<20) {
			return errs.ErrRequestBodyTooLarge
		}
		decoded, err := base64.StdEncoding.DecodeString(content)
		if err != nil || len(decoded) == 0 {
			return errs.ErrBadRequest.WithDetail("logo data is invalid")
		}
		if len(decoded) > 2<<20 {
			return errs.ErrRequestBodyTooLarge
		}
	}
	if value, exists := b.Settings["email_reply_to"]; exists {
		address, ok := value.(string)
		if !ok {
			return errs.ErrBadRequest.WithDetail("email_reply_to must be an email address")
		}
		address = strings.TrimSpace(address)
		if address != "" {
			parsed, err := mail.ParseAddress(address)
			if err != nil || parsed.Address != address || strings.ContainsAny(address, "\r\n") {
				return errs.ErrBadRequest.WithDetail("email_reply_to must be a single email address")
			}
		}
		b.Settings["email_reply_to"] = address
	}
	if b.EmailFromName != nil && strings.ContainsAny(*b.EmailFromName, "\r\n") {
		return errs.ErrBadRequest.WithDetail("email_from_name must not contain line breaks")
	}
	if value, exists := b.Settings["background_color"]; exists {
		color, ok := value.(string)
		if !ok {
			return errs.ErrBadRequest.WithDetail("background_color must be a hex color")
		}
		color = strings.ToLower(strings.TrimSpace(color))
		if color != "" && !colorPattern.MatchString(color) {
			return errs.ErrBadRequest.WithDetail("background_color must be a six-digit hex color")
		}
		b.Settings["background_color"] = color
	}
	return nil
}

// Save stores the organization's branding as actor's, with its
// branding.updated audit row, in one transaction.
func (r *Repository) Save(ctx context.Context, b Branding, actor audit.Actor) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := r.upsert(ctx, tx, b); err != nil {
		return err
	}
	meta := map[string]any{}
	if b.CustomDomain != nil {
		meta["custom_domain"] = *b.CustomDomain
	}
	if b.PrimaryColor != nil {
		meta["primary_color"] = *b.PrimaryColor
	}
	if err := audit.Record(ctx, tx, actor.Event(b.OrganizationID, "branding.updated", "organization", b.OrganizationID, meta)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// upsert stores branding in tx, refused while the organization's plan lacks
// custom branding.
func (r *Repository) upsert(ctx context.Context, tx pgx.Tx, b Branding) error {
	if err := normalizeAppearance(&b); err != nil {
		return err
	}
	// Plan gate: custom branding (logo, colors, custom email sender) is a paid feature.
	if r.gate != nil {
		ok, err := r.gate.FeatureAllowed(ctx, b.OrganizationID, "custom_branding")
		if err != nil {
			return err
		}
		if !ok {
			return errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "custom_branding"})
		}
	}
	settings, err := json.Marshal(b.Settings)
	if err != nil {
		return err
	}
	return r.q.WithTx(tx).UpsertBranding(ctx, dbgen.UpsertBrandingParams{
		OrganizationID: b.OrganizationID, LogoUrl: b.LogoURL, PrimaryColor: b.PrimaryColor,
		SecondaryColor: b.SecondaryColor, CustomDomain: b.CustomDomain, EmailFromName: b.EmailFromName,
		Settings: settings,
	})
}
