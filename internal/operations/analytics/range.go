package analytics

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// rangeMaxDays bounds a chosen range, so a trend never scans unbounded history.
const rangeMaxDays = 366

// SignInRange is the organization's sign-ins day by day over a chosen range:
// how many, by how many people, and how many failed, by one method when
// Method is set. Organization switches and creations aren't sign-ins.
type SignInRange struct {
	From   time.Time    `json:"from"`
	To     time.Time    `json:"to"`
	Method string       `json:"method,omitempty"`
	Days   []DayOfLogin `json:"days"`
}

// DayOfLogin is one UTC day of a SignInRange.
type DayOfLogin struct {
	Date    string `json:"date"`
	SignIns int    `json:"sign_ins"`
	People  int    `json:"people"`
	Failed  int    `json:"failed"`
}

// Range returns organizationID's sign-ins by UTC day from the day of from to the day
// of to, of method when not "".
func (r *Reader) Range(ctx context.Context, organizationID uuid.UUID, from, to time.Time, method string) (*SignInRange, error) {
	out := &SignInRange{From: from, To: to, Method: method, Days: []DayOfLogin{}}
	rows, err := r.pool.Query(ctx, `
		SELECT to_char(d, 'YYYY-MM-DD'),
		       count(e.id) FILTER (WHERE e.action = 'auth.login_succeeded'),
		       count(DISTINCT e.actor_user_id) FILTER (WHERE e.action = 'auth.login_succeeded'),
		       count(e.id) FILTER (WHERE e.action = 'auth.sign_in_failed')
		FROM generate_series(date_trunc('day', $2::timestamptz AT TIME ZONE 'UTC'),
		                     date_trunc('day', $3::timestamptz AT TIME ZONE 'UTC'), INTERVAL '1 day') AS d
		LEFT JOIN audit.events e
		  ON e.organization_id = $1
		 AND e.created_at >= d AT TIME ZONE 'UTC' AND e.created_at < (d + INTERVAL '1 day') AT TIME ZONE 'UTC'
		 AND e.created_at >= $2 AND e.created_at <= $3
		 AND e.action IN ('auth.login_succeeded', 'auth.sign_in_failed')
		 AND COALESCE(e.metadata->>'method', '') NOT IN ('tenant_switch', 'tenant_create', 'invite_accept')
		 AND ($4 = '' OR e.metadata->>'method' = $4)
		GROUP BY d ORDER BY d`, organizationID, from, to, method)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var d DayOfLogin
		if err := rows.Scan(&d.Date, &d.SignIns, &d.People, &d.Failed); err != nil {
			return nil, err
		}
		out.Days = append(out.Days, d)
	}
	return out, rows.Err()
}

// parseRange reads a chosen range from r: from and to (RFC 3339), or days
// back from to (or now). It reports false when r asks for none.
func parseRange(r *http.Request) (from, to time.Time, asked bool, err error) {
	q := r.URL.Query()
	if q.Get("from") == "" && q.Get("to") == "" && q.Get("days") == "" {
		return time.Time{}, time.Time{}, false, nil
	}
	to = time.Now().UTC()
	if raw := q.Get("to"); raw != "" {
		if to, err = time.Parse(time.RFC3339, raw); err != nil {
			return time.Time{}, time.Time{}, true, errs.ErrBadRequest.WithDetail("invalid to")
		}
	}
	days := 30
	if raw := q.Get("days"); raw != "" {
		if days, err = strconv.Atoi(raw); err != nil || days < 1 || days > rangeMaxDays {
			return time.Time{}, time.Time{}, true, errs.ErrBadRequest.WithDetail("days must be 1 to 366")
		}
	}
	from = to.AddDate(0, 0, -days)
	if raw := q.Get("from"); raw != "" {
		if from, err = time.Parse(time.RFC3339, raw); err != nil {
			return time.Time{}, time.Time{}, true, errs.ErrBadRequest.WithDetail("invalid from")
		}
	}
	if !from.Before(to) || to.Sub(from) > rangeMaxDays*24*time.Hour {
		return time.Time{}, time.Time{}, true, errs.ErrBadRequest.WithDetail("from must be before to, at most 366 days")
	}
	return from.UTC(), to.UTC(), true, nil
}
