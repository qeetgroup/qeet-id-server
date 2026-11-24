package branding

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// logoTypes are the image types an uploaded logo may be, by data URL header.
var logoTypes = map[string]string{
	"data:image/png;base64":     "image/png",
	"data:image/jpeg;base64":    "image/jpeg",
	"data:image/webp;base64":    "image/webp",
	"data:image/svg+xml;base64": "image/svg+xml",
}

// publicLogo is the address emails and hosted pages show for stored: a URL as
// stored, or for an uploaded logo (a data URL) this API's link to it, carrying
// a hash of the image so a new upload isn't served from a cache.
func (r *Repository) publicLogo(organizationID uuid.UUID, stored string) string {
	if !strings.HasPrefix(stored, "data:") || r.publicBase == "" {
		return stored
	}
	sum := sha256.Sum256([]byte(stored))
	return r.publicBase + "/v1/branding/" + organizationID.String() + "/logo?v=" + hex.EncodeToString(sum[:6])
}

// UploadedLogo returns the image the organization uploaded as its logo and its type,
// or false when it uploaded none or its plan lacks custom branding.
func (r *Repository) UploadedLogo(ctx context.Context, organizationID uuid.UUID) (contentType string, image []byte, ok bool) {
	if !r.brandingAllowed(ctx, organizationID) {
		return "", nil, false
	}
	b, err := r.Get(ctx, organizationID)
	if err != nil || b == nil || b.LogoURL == nil {
		return "", nil, false
	}
	header, content, found := strings.Cut(*b.LogoURL, ",")
	contentType, known := logoTypes[header]
	if !found || !known {
		return "", nil, false
	}
	image, err = base64.StdEncoding.DecodeString(content)
	if err != nil || len(image) == 0 {
		return "", nil, false
	}
	return contentType, image, true
}

// logo serves GET /v1/branding/{organizationID}/logo. The image is only ever shown,
// never run: an SVG's scripts stay sandboxed on this origin.
func (h *Handler) logo(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathUUID(r, "organizationID", errs.ErrNotFound)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	contentType, image, ok := h.Repo.UploadedLogo(r.Context(), organizationID)
	if !ok {
		httpx.WriteError(w, r, errs.ErrNotFound)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	_, _ = w.Write(image) // #nosec G705 -- an image the organization uploaded, served with its validated type, nosniff and a sandboxing CSP
}
