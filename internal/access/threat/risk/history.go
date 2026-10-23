package risk

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/threat/risk/dbgen"
)

// deviceKey reduces a User-Agent to a coarse browser-OS pair such as
// "chrome-macos": a stand-in for device identity, without fingerprinting, that
// is enough to tell a new device from a familiar one.
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
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Warn("risk: lookup last country", "err", err)
		}
		return "", time.Time{}, false
	}
	if row.Country == nil {
		return "", time.Time{}, false
	}
	return *row.Country, row.SeenAt, true
}

// deviceSeenBefore reports whether device key dk is in the user's sign-in
// history, which keeps entries for SignInHistoryRetention.
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

// SignInHistoryRetention is how long a sign-in's country and device are kept
// for later sign-ins to be compared against. Older entries can't matter for
// impossible travel (hours), and a device unused this long counts as new again.
const SignInHistoryRetention = 90 * 24 * time.Hour

// PurgeSignInHistory deletes sign-in history older than retention and returns
// how many entries. Run on a schedule; a person's or organisation's history
// also goes when they are deleted.
func PurgeSignInHistory(ctx context.Context, pool *pgxpool.Pool, retention time.Duration) (int64, error) {
	tag, err := pool.Exec(ctx, `DELETE FROM auth.login_context_history WHERE seen_at < $1`, time.Now().UTC().Add(-retention))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
