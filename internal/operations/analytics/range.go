package analytics

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/analytics/dbgen"
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
	rows, err := r.q.CountSignInsByDay(ctx, dbgen.CountSignInsByDayParams{
		Tid: &organizationID, FromAt: from, ToAt: to, Method: method,
	})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out.Days = append(out.Days, DayOfLogin{Date: row.Day, SignIns: int(row.SignIns), People: int(row.People), Failed: int(row.Failed)})
	}
	return out, nil
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
