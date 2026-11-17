// Package bot scores sign-in requests for bot-likeness with an offline
// User-Agent heuristic and records suspicious verdicts for the admin
// "Threats → Bots" screen. It only detects: a "blocked" verdict means "would
// block", and no sign-in is refused on it.
package bot

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/threat/bot/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// recordFloor is the minimum score worth logging: clean human clients score 0
// and are skipped so the bot log only holds genuinely suspicious attempts.
const recordFloor = 0.30

// challengeFloor is the score at/above which a verdict is "challenged" (below
// the organization's block threshold). Below it the verdict is "allowed".
const challengeFloor = 0.50

// botSignatures are case-insensitive User-Agent substrings typical of scripts,
// scrapers, and headless automation. Each contributes to the score.
var botSignatures = []string{
	"curl/", "wget/", "python-requests", "python-urllib", "go-http-client",
	"java/", "okhttp", "libwww-perl", "scrapy", "httpclient", "axios/",
	"headlesschrome", "phantomjs", "selenium", "playwright", "puppeteer",
	"bot", "spider", "crawler",
}

// Score returns a bot-likeness score in [0,1] for a User-Agent. An empty UA is
// strongly bot-like; a known script/automation signature is conclusive; an
// otherwise ordinary browser UA scores 0.
func Score(ua string) float64 {
	u := strings.ToLower(strings.TrimSpace(ua))
	if u == "" {
		return 0.9
	}
	for _, sig := range botSignatures {
		if strings.Contains(u, sig) {
			return 0.95
		}
	}
	// A UA that doesn't even claim to be a Mozilla-family browser is mildly
	// suspicious (most real browsers send "Mozilla/5.0 …").
	if !strings.Contains(u, "mozilla/") {
		return 0.55
	}
	return 0
}

// Settings is an organization's bot-detection config. Only UACheck and ScoreThreshold
// affect Evaluate; Honeypot, Captcha and Signature are stored but not enforced.
type Settings struct {
	UACheck        bool    `json:"ua_check"`
	Honeypot       bool    `json:"honeypot"`
	Captcha        bool    `json:"captcha"`
	Signature      bool    `json:"signature"`
	ScoreThreshold float64 `json:"score_threshold"`
}

// DefaultSettings mirrors the column defaults — used when an organization has no row.
func DefaultSettings() Settings {
	return Settings{UACheck: true, Honeypot: true, Captcha: false, Signature: false, ScoreThreshold: 0.70}
}

// Event is one scored sign-in request and its verdict.
// UserID and UserEmail are the account the sign-in attempt was for; Outcome
// is how that account's next sign-in from the address, within
// outcomeWindow, ended: "signed_in", "failed", or "unknown".
type Event struct {
	ID        uuid.UUID  `json:"id"`
	IP        *string    `json:"ip,omitempty"`
	UserAgent string     `json:"user_agent"`
	Score     float64    `json:"score"`
	Verdict   string     `json:"verdict"`
	CreatedAt time.Time  `json:"created_at"`
	UserID    *uuid.UUID `json:"user_id,omitempty"`
	UserEmail *string    `json:"user_email,omitempty"`
	Outcome   string     `json:"outcome"`
}

// outcomeWindow is how soon after a detection the account's sign-in from the
// same address is taken as its outcome.
const outcomeWindow = 5 * time.Minute

// Page is a page of detections, newest first, with how many there are.
type Page struct {
	Items      []Event `json:"items"`
	NextCursor string  `json:"next_cursor,omitempty"`
	Total      int     `json:"total"`
}

// Stats counts the organization's blocked and challenged requests over the last
// day.
type Stats struct {
	Blocked24h    int     `json:"blocked_24h"`
	Challenged24h int     `json:"challenged_24h"`
	Threshold     float64 `json:"threshold"`
}

// Service scores sign-in requests for bot-likeness and records the verdicts.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

// NewService returns the bot detection service.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

// Evaluate scores a sign-in's User-Agent and, when it looks suspicious, records
// a verdict in the organization the email belongs to. Best effort: it never blocks or
// fails the sign-in.
func (s *Service) Evaluate(ctx context.Context, email, ip, ua string) {
	score := Score(ua)
	if score < recordFloor {
		return // clearly human — don't log
	}
	row, err := s.q.GetUserOrganizationByEmail(ctx, email)
	if err != nil {
		return // no organization to scope the verdict to
	}
	if !row.OrganizationID.Valid {
		return
	}
	organizationID, userID := uuid.UUID(row.OrganizationID.Bytes), row.ID
	settings, err := s.GetSettings(ctx, organizationID)
	if err != nil || !settings.UACheck {
		return // UA scoring disabled for this organization
	}
	verdict := "allowed"
	switch {
	case score >= settings.ScoreThreshold:
		verdict = "blocked"
	case score >= challengeFloor:
		verdict = "challenged"
	}
	// InsertBotEvent left raw: NULLIF($2,'')::inet causes sqlc parameter-type
	// ambiguity for the inet cast.
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO auth.bot_events (organization_id, ip, user_agent, score, verdict, user_id)
		VALUES ($1, NULLIF($2,'')::inet, $3, $4, $5, $6)
	`, organizationID, ip, ua, score, verdict, userID); err != nil {
		slog.Warn("record bot event", "err", err)
	}
}

// List returns a page of up to limit of the organization's detections (50 when not
// in 1..200), newest first, after cursor, of verdict when given, and how many
// there are.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID, limit int, cursor, verdict string) (*Page, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	page := &Page{Items: []Event{}}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM auth.bot_events WHERE organization_id = $1 AND ($2 = '' OR verdict = $2)`,
		organizationID, verdict).Scan(&page.Total); err != nil {
		return nil, err
	}
	afterTs, afterID := time.Now().Add(time.Hour), uuid.Max
	if cursor != "" {
		var err error
		if afterTs, afterID, err = paging.DecodeTimeUUID(cursor); err != nil {
			return nil, errs.ErrBadRequest.WithDetail("invalid cursor")
		}
	}
	rows, err := s.pool.Query(ctx, `
		SELECT b.id, host(b.ip), b.user_agent, b.score, b.verdict, b.created_at, b.user_id, u.email,
		       COALESCE((
				SELECT CASE e.action WHEN 'auth.login_succeeded' THEN 'signed_in' ELSE 'failed' END
				FROM audit.events e
				WHERE e.organization_id = b.organization_id AND e.actor_user_id = b.user_id
				  AND e.action IN ('auth.login_succeeded', 'auth.sign_in_failed')
				  AND e.ip IS NOT DISTINCT FROM b.ip
				  AND e.created_at >= b.created_at AND e.created_at < b.created_at + $5::interval
				ORDER BY e.created_at LIMIT 1), 'unknown') AS outcome
		FROM auth.bot_events b
		LEFT JOIN account.users u ON u.id = b.user_id
		WHERE b.organization_id = $1 AND ($2 = '' OR b.verdict = $2) AND (b.created_at, b.id) < ($3, $4)
		ORDER BY b.created_at DESC, b.id DESC LIMIT $6
	`, organizationID, verdict, afterTs, afterID, outcomeWindow.String(), limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.IP, &e.UserAgent, &e.Score, &e.Verdict, &e.CreatedAt, &e.UserID, &e.UserEmail, &e.Outcome); err != nil {
			return nil, err
		}
		page.Items = append(page.Items, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[limit-1]
		page.NextCursor = paging.EncodeTimeUUID(last.CreatedAt, last.ID)
	}
	return page, nil
}

// Stats returns the organization's bot-detection counts.
func (s *Service) Stats(ctx context.Context, organizationID uuid.UUID) (*Stats, error) {
	row, err := s.q.GetBotEventStats(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	settings, err := s.GetSettings(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	return &Stats{
		Blocked24h:    int(row.Blocked24h),
		Challenged24h: int(row.Challenged24h),
		Threshold:     settings.ScoreThreshold,
	}, nil
}

// GetSettings returns the organization's bot-detection settings.
func (s *Service) GetSettings(ctx context.Context, organizationID uuid.UUID) (Settings, error) {
	row, err := s.q.GetBotSettings(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultSettings(), nil
	}
	if err != nil {
		return Settings{}, err
	}
	return Settings{
		UACheck:        row.UaCheck,
		Honeypot:       row.Honeypot,
		Captcha:        row.Captcha,
		Signature:      row.Signature,
		ScoreThreshold: float64(row.ScoreThreshold),
	}, nil
}

// UpdateSettings stores the organization's bot-detection settings, recorded as
// actor's with each setting it changed.
func (s *Service) UpdateSettings(ctx context.Context, organizationID uuid.UUID, in Settings, actor audit.Actor) (Settings, error) {
	if in.ScoreThreshold < 0.1 {
		in.ScoreThreshold = 0.1
	}
	if in.ScoreThreshold > 1 {
		in.ScoreThreshold = 1
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Settings{}, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	before := DefaultSettings()
	row, err := q.LockBotSettings(ctx, organizationID)
	switch {
	case err == nil:
		before = Settings{UACheck: row.UaCheck, Honeypot: row.Honeypot, Captcha: row.Captcha,
			Signature: row.Signature, ScoreThreshold: float64(row.ScoreThreshold)}
	case !errors.Is(err, pgx.ErrNoRows):
		return Settings{}, err
	}
	if err := q.UpsertBotSettings(ctx, dbgen.UpsertBotSettingsParams{
		OrganizationID: organizationID,
		UaCheck:        in.UACheck,
		Honeypot:       in.Honeypot,
		Captcha:        in.Captcha,
		Signature:      in.Signature,
		ScoreThreshold: float32(in.ScoreThreshold),
	}); err != nil {
		return Settings{}, err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "bot.settings_updated", "tenant", organizationID,
		map[string]any{"changes": audit.Changes(before.audited(), in.audited()), "settings": in.audited()})); err != nil {
		return Settings{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Settings{}, err
	}
	return in, nil
}

// audited is the settings by name, as recorded. The threshold is kept at the
// precision it is stored with, so an unchanged one compares equal.
func (st Settings) audited() map[string]any {
	return map[string]any{
		"ua_check": st.UACheck, "honeypot": st.Honeypot, "captcha": st.Captcha,
		"signature": st.Signature, "score_threshold": float32(st.ScoreThreshold),
	}
}

// Handler serves the bot detection HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the bot detection routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/security/bots", h.overview)
	r.Get("/tenants/{tenantID}/security/bots/settings", h.getSettings)
	r.Put("/tenants/{tenantID}/security/bots/settings", h.putSettings)
}

func (h *Handler) overview(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	verdict := query.Get("verdict")
	if verdict != "" && verdict != "allowed" && verdict != "challenged" && verdict != "blocked" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid verdict"))
		return
	}
	page, err := h.Service.List(r.Context(), organizationID, limit, query.Get("cursor"), verdict)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	stats, err := h.Service.Stats(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"recent": page.Items, "next_cursor": page.NextCursor, "total": page.Total, "stats": stats,
	})
}

func (h *Handler) getSettings(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	st, err := h.Service.GetSettings(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (h *Handler) putSettings(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in Settings
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	st, err := h.Service.UpdateSettings(r.Context(), organizationID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}
