package user

import (
	"cmp"
	"context"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/useragent"
)

// Sign-in summary bounds: 30 days unless asked, at most a year and a day.
const (
	signInDefaultDays = 30
	signInMaxDays     = 366
	signInTopAddrs    = 20
)

// SignInSummary is how a member signed in to an organisation over a period:
// by method, and how many of those met a second step; by address and by
// browser; and the failed attempts by reason.
type SignInSummary struct {
	From           time.Time       `json:"from"`
	To             time.Time       `json:"to"`
	SignIns        int             `json:"sign_ins"`
	WithSecondStep int             `json:"with_second_step"`
	ByMethod       []MethodCount   `json:"by_method"`
	ByAddress      []AddressCount  `json:"by_address"`
	ByBrowser      []BrowserCount  `json:"by_browser"`
	Failures       int             `json:"failures"`
	FailuresBy     []FailureReason `json:"failures_by_reason"`
}

// MethodCount is the sign-ins by one first method, and how many met a second
// step.
type MethodCount struct {
	Method         string `json:"method"`
	Count          int    `json:"count"`
	WithSecondStep int    `json:"with_second_step"`
}

// AddressCount is the sign-ins from one address, and the last.
type AddressCount struct {
	IP     string    `json:"ip"`
	Count  int       `json:"count"`
	LastAt time.Time `json:"last_at"`
}

// BrowserCount is the sign-ins with one browser on one platform.
type BrowserCount struct {
	Device string `json:"device"`
	Kind   string `json:"kind"`
	Count  int    `json:"count"`
}

// FailureReason is the failed sign-ins of one reason.
type FailureReason struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

// signInEvents is the member's ($2) sign-in events of action ($3) in the
// organisation ($1) over [from, to) ($4, $5).
const signInEvents = `FROM audit.events
	WHERE tenant_id = $1 AND actor_user_id = $2 AND action = $3 AND created_at >= $4 AND created_at < $5`

// SignInSummary summarises id's sign-ins to tenantID over [from, to).
func (r *Repository) SignInSummary(ctx context.Context, tenantID, id uuid.UUID, from, to time.Time) (*SignInSummary, error) {
	out := &SignInSummary{From: from, To: to, ByMethod: []MethodCount{}, ByAddress: []AddressCount{},
		ByBrowser: []BrowserCount{}, FailuresBy: []FailureReason{}}
	args := []any{tenantID, id, "auth.login_succeeded", from, to}
	rows, err := r.pool.Query(ctx, `SELECT COALESCE(metadata->>'method', 'unknown'), count(*),
		count(*) FILTER (WHERE COALESCE(metadata->>'second_factor', '') <> '' OR metadata->>'method' LIKE '%\_mfa')
		`+signInEvents+` GROUP BY 1 ORDER BY 2 DESC, 1`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var m MethodCount
		if err := rows.Scan(&m.Method, &m.Count, &m.WithSecondStep); err != nil {
			rows.Close()
			return nil, err
		}
		out.ByMethod = append(out.ByMethod, m)
		out.SignIns += m.Count
		out.WithSecondStep += m.WithSecondStep
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = r.pool.Query(ctx, `SELECT host(ip), count(*), max(created_at) `+signInEvents+` AND ip IS NOT NULL
		GROUP BY 1 ORDER BY 2 DESC, 3 DESC LIMIT `+strconv.Itoa(signInTopAddrs), args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var a AddressCount
		if err := rows.Scan(&a.IP, &a.Count, &a.LastAt); err != nil {
			rows.Close()
			return nil, err
		}
		out.ByAddress = append(out.ByAddress, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Grouped by user agent, then by what it says, which several share.
	rows, err = r.pool.Query(ctx, `SELECT COALESCE(user_agent, ''), count(*) `+signInEvents+` GROUP BY 1`, args...)
	if err != nil {
		return nil, err
	}
	byDevice := map[string]*BrowserCount{}
	for rows.Next() {
		var ua string
		var n int
		if err := rows.Scan(&ua, &n); err != nil {
			rows.Close()
			return nil, err
		}
		d := useragent.Parse(ua)
		label := d.Label()
		if byDevice[label] == nil {
			byDevice[label] = &BrowserCount{Device: label, Kind: d.Kind}
		}
		byDevice[label].Count += n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, b := range byDevice {
		out.ByBrowser = append(out.ByBrowser, *b)
	}
	slices.SortFunc(out.ByBrowser, func(a, b BrowserCount) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Device, b.Device))
	})

	args[2] = "auth.sign_in_failed"
	rows, err = r.pool.Query(ctx, `SELECT COALESCE(metadata->>'reason', 'unknown'), count(*) `+signInEvents+`
		GROUP BY 1 ORDER BY 2 DESC, 1`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var f FailureReason
		if err := rows.Scan(&f.Reason, &f.Count); err != nil {
			rows.Close()
			return nil, err
		}
		out.FailuresBy = append(out.FailuresBy, f)
		out.Failures += f.Count
	}
	rows.Close()
	return out, rows.Err()
}

// signInRange reads a summary's period: from and to (RFC 3339), or days back
// from now; 30 days by default, at most 366.
func signInRange(r *http.Request) (time.Time, time.Time, error) {
	q := r.URL.Query()
	to := time.Now().UTC()
	if raw := q.Get("to"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return time.Time{}, time.Time{}, errs.ErrBadRequest.WithDetail("invalid to")
		}
		to = t.UTC()
	}
	days := signInDefaultDays
	if raw := q.Get("days"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > signInMaxDays {
			return time.Time{}, time.Time{}, errs.ErrBadRequest.WithDetail("days must be 1 to 366")
		}
		days = n
	}
	from := to.AddDate(0, 0, -days)
	if raw := q.Get("from"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return time.Time{}, time.Time{}, errs.ErrBadRequest.WithDetail("invalid from")
		}
		from = t.UTC()
	}
	if !from.Before(to) || to.Sub(from) > signInMaxDays*24*time.Hour {
		return time.Time{}, time.Time{}, errs.ErrBadRequest.WithDetail("from must be before to, at most 366 days")
	}
	return from, to, nil
}

// signIns handles GET /v1/tenants/{tenantID}/users/{id}/sign-ins: how the
// member signed in to the organisation over a period.
func (h *Handler) signIns(w http.ResponseWriter, r *http.Request) {
	if _, err := httpx.PathTenant(r); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, tenantID, err := h.memberID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	from, to, err := signInRange(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Repo.SignInSummary(r.Context(), tenantID, id, from, to)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
