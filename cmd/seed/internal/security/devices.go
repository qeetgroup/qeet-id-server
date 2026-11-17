package security

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
)

// Remembered devices are written as the hosted login writes them after a
// second factor: the hash of a random cookie value, labelled with the
// browser's user agent, trusted for the organization's remember_device_days.

// rememberDefault is where devices are remembered when an organization has no
// authentication policy yet (the settings step writes them).
var rememberDefault = map[string]bool{"qeet": true, "lumen": true, "northwind": true}

// rememberDevices remembers a browser or two for some of the people with a
// second factor, in organizations that remember devices.
func rememberDevices(w *world.World) {
	for _, o := range w.Orgs {
		days, ok := rememberPolicy(w, o)
		if !ok {
			continue
		}
		ttl := time.Duration(days) * 24 * time.Hour
		count := 0
		for _, p := range o.People {
			if len(p.MFA) == 0 || p.Status != world.StatusActive || p.Unverified {
				continue
			}
			if p.Login == "" && !w.Chance(0.25) {
				continue
			}
			devices := []world.Device{p.Device}
			if w.Chance(0.35) {
				devices = append(devices, p.Mobile)
			}
			for _, d := range devices {
				remember(w, o, p, d, ttl)
				count++
			}
		}
		if count > 0 {
			fact(o, "%d remembered devices", count)
		}
	}
}

// rememberPolicy reports whether o remembers devices, and for how many days.
func rememberPolicy(w *world.World, o *world.Org) (int, bool) {
	var enabled bool
	var days int
	err := w.Admin.QueryRow(w.Ctx, `SELECT remember_device_enabled, remember_device_days FROM organization.auth_policy WHERE organization_id = $1`,
		o.ID).Scan(&enabled, &days)
	if errors.Is(err, pgx.ErrNoRows) {
		return 30, rememberDefault[o.Spec.Slug]
	}
	w.Check(err, "read the authentication policy of "+o.Spec.Slug)
	return days, enabled
}

// remember trusts d for p in o: remembered after a second factor some time in
// the device's lifetime, and used since.
func remember(w *world.World, o *world.Org, p *world.Person, d world.Device, ttl time.Duration) {
	from := maxTime(p.MFASince, w.Now.Add(-ttl+24*time.Hour))
	if !from.Before(w.Now.Add(-2 * time.Hour)) {
		return
	}
	created := w.WorkHours(w.Between(from, w.Now.Add(-2*time.Hour)), p.Loc)
	if created.Before(from) || created.After(w.Now) {
		created = from
	}
	expires := created.Add(ttl)
	var used *time.Time
	if span := w.Now.Sub(created); span > 6*time.Hour && w.Chance(0.8) {
		used = ptr(created.Add(time.Duration(w.Rand.Int64N(int64(span - time.Hour)))))
	}
	raw, _, err := tokens.NewRefreshToken()
	w.Check(err, "mint a device token")
	var id uuid.UUID
	w.Check(w.Admin.QueryRow(w.Ctx, `
		INSERT INTO auth.trusted_devices (user_id, organization_id, token_hash, label, expires_at, created_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		p.ID, o.ID, tokens.HashRefresh(raw), d.UserAgent, expires, created, used).Scan(&id), "remember a device")
	w.Audit(created, audit.Event{OrganizationID: &o.ID, ActorUserID: &p.ID, Action: "auth.trusted_device_added",
		ResourceType: "trusted_device", ResourceID: &id, UserAgent: d.UserAgent,
		Metadata: map[string]any{"expires_at": expires}})
}
