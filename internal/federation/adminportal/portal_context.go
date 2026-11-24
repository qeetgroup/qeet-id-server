package adminportal

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

func (s *Service) organizationName(ctx context.Context, organizationID uuid.UUID) (string, error) {
	return s.q.GetOrganizationNameByID(ctx, organizationID)
}

// PortalBranding is the subset of branding.Branding a hosted, unauthenticated
// page needs to render on first paint — mirrors oidc's login-context shape.
type PortalBranding struct {
	LogoURL         string `json:"logo_url,omitempty"`
	PrimaryColor    string `json:"primary_color,omitempty"`
	SecondaryColor  string `json:"secondary_color,omitempty"`
	BackgroundColor string `json:"background_color,omitempty"`
}

// PortalContext is what the hosted admin-portal page fetches before rendering
// the SAML/SCIM forms: who it's configuring for, what it may touch, and how
// long it has left. SCIMBaseURL, where the IdP provisions to, is set only for
// a link that may set up SCIM.
type PortalContext struct {
	OrganizationName string          `json:"organization_name"`
	Capabilities     []string        `json:"capabilities"`
	ExpiresAt        time.Time       `json:"expires_at"`
	Branding         *PortalBranding `json:"branding,omitempty"`
	SCIMBaseURL      string          `json:"scim_base_url,omitempty"`
}

// Context returns what the portal shows for a link: the organization's name, the
// link's capabilities and when it expires.
func (s *Service) Context(ctx context.Context, l *Link) (*PortalContext, error) {
	name, err := s.organizationName(ctx, l.OrganizationID)
	if err != nil {
		return nil, err
	}
	pc := &PortalContext{OrganizationName: name, Capabilities: l.Capabilities, ExpiresAt: l.ExpiresAt}
	logo, primary, secondary, background := s.brandingRepo.LoginBranding(ctx, l.OrganizationID)
	if logo != "" || primary != "" || secondary != "" || background != "" {
		pc.Branding = &PortalBranding{LogoURL: logo, PrimaryColor: primary, SecondaryColor: secondary, BackgroundColor: background}
	}
	return pc, nil
}

func (h *Handler) context(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, "")
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pc, err := h.portalContext(r, l)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pc)
}

// portalContext returns link l's context, with the SCIM base URL when l may
// set up SCIM.
func (h *Handler) portalContext(r *http.Request, l *Link) (*PortalContext, error) {
	pc, err := h.Service.Context(r.Context(), l)
	if err != nil {
		return nil, err
	}
	if l.Has(CapabilitySCIM) {
		pc.SCIMBaseURL = scim.BaseURL(h.origin(r))
	}
	return pc, nil
}

// origin returns the API's public origin, which the SAML and SCIM addresses
// are built on.
func (h *Handler) origin(r *http.Request) string {
	return httpx.PublicOrigin(r, h.PublicBaseURL)
}

// portalActor is who acts through link l in an audit event: the portal, on
// behalf of the link's creator.
func portalActor(l *Link, r *http.Request) audit.Actor {
	return audit.Actor{UserID: l.CreatedBy, Type: "admin_portal", IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
}
