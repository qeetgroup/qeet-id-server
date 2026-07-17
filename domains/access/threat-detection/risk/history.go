package risk

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id/domains/access/threat-detection/risk/dbgen"
)

// deviceKey normalizes a User-Agent string to a coarse browser+OS pair (e.g.
// "chrome-macos"). It's a proxy for "device identity" — this codebase has no
// fingerprinting library on the frontend and adding one is a separate,
// larger, privacy-sensitive undertaking — but browser+OS is already more
// specific than the raw bot.Score(ua) heuristic and is enough to tell "a
// completely new device" from "the same one as always."
func deviceKey(ua string) string {
	u := strings.ToLower(ua)

	browser := "other"
	switch {
	case strings.Contains(u, "edg/"):
		browser = "edge"
	case strings.Contains(u, "chrome/"):
		browser = "chrome"
	case strings.Contains(u, "firefox/"):
		browser = "firefox"
	case strings.Contains(u, "safari/"):
		browser = "safari"
	}

	// iOS UAs contain "like Mac OS X" (e.g. "CPU iPhone OS 17_0 like Mac OS
	// X"), so the iphone/ipad check must come before the "mac os" substring
	// match or every iOS device misclassifies as macOS.
	os := "other"
	switch {
	case strings.Contains(u, "windows"):
		os = "windows"
	case strings.Contains(u, "iphone"), strings.Contains(u, "ipad"):
		os = "ios"
	case strings.Contains(u, "mac os"):
		os = "macos"
	case strings.Contains(u, "android"):
		os = "android"
	case strings.Contains(u, "linux"):
		os = "linux"
	}

	return browser + "-" + os
}

// lastCountry returns the most recent country recorded for this user (across
// any device), and whether one was found at all. Rows with no country ("")
// are skipped — they carry no geo signal to compare against.
func (s *Service) lastCountry(ctx context.Context, tenantID, userID uuid.UUID) (country string, seenAt time.Time, ok bool) {
	row, err := s.q.GetLastCountry(ctx, dbgen.GetLastCountryParams{
		TenantID: tenantID,
		UserID:   userID,
	})
	if err != nil {
		if err != pgx.ErrNoRows {
			slog.Warn("risk: lookup last country", "err", err)
		}
		return "", time.Time{}, false
	}
	if row.Country == nil {
		return "", time.Time{}, false
	}
	return *row.Country, row.SeenAt, true
}

// deviceSeenBefore reports whether this exact device key has ever been
// recorded for this user, at any point in the (unbounded) history — device
// reputation, once earned, doesn't expire the way a trusted-device cookie
// does.
func (s *Service) deviceSeenBefore(ctx context.Context, tenantID, userID uuid.UUID, dk string) (bool, error) {
	return s.q.DeviceSeenBefore(ctx, dbgen.DeviceSeenBeforeParams{
		TenantID:  tenantID,
		UserID:    userID,
		DeviceKey: dk,
	})
}

// recordLogin appends this login's device/country to the user's history.
// Best-effort: a failure here shouldn't fail the login it's describing, so
// errors are logged, not returned.
func (s *Service) recordLogin(ctx context.Context, tenantID, userID uuid.UUID, dk, country string) {
	var c *string
	if country != "" {
		c = &country
	}
	if err := s.q.InsertLoginContext(ctx, dbgen.InsertLoginContextParams{
		TenantID:  tenantID,
		UserID:    userID,
		DeviceKey: dk,
		Country:   c,
	}); err != nil {
		slog.Warn("risk: record login context", "err", err)
	}
}
