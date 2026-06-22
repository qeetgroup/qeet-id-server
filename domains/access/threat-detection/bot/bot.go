// Package bot scores incoming auth requests for bot-likeness and records the
// verdicts surfaced in the admin "Threats → Bots" screen. Scoring is a pure,
// offline User-Agent heuristic (no network, no third-party captcha needed for
// the baseline) so it works in dev/CI; honeypot/captcha toggles are stored for
// future enforcement.
//
// Detection is detect-only: a verdict of "blocked" means "would block" — the
// auth path is never hard-failed on a heuristic, so an unusual-but-legitimate
// client can't be locked out. Only clearly suspicious attempts are recorded;
// clean human user-agents are scored 0 and skipped to keep the log meaningful.
package bot

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
)

// recordFloor is the minimum score worth logging: clean human clients score 0
// and are skipped so the bot log only holds genuinely suspicious attempts.
const recordFloor = 0.30

// challengeFloor is the score at/above which a verdict is "challenged" (below
// the tenant's block threshold). Below it the verdict is "allowed".
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

// Settings is a tenant's bot-detection config. Only ua_check drives the
// baseline scorer today; honeypot/captcha/signature are stored for future
// enforcement layers.
type Settings struct {
	UACheck        bool    `json:"ua_check"`
	Honeypot       bool    `json:"honeypot"`
	Captcha        bool    `json:"captcha"`
	Signature      bool    `json:"signature"`
	ScoreThreshold float64 `json:"score_threshold"`
}

// DefaultSettings mirrors the column defaults — used when a tenant has no row.
func DefaultSettings() Settings {
	return Settings{UACheck: true, Honeypot: true, Captcha: false, Signature: false, ScoreThreshold: 0.70}
}

type Event struct {
	ID        uuid.UUID `json:"id"`
	IP        *string   `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent"`
	Score     float64   `json:"score"`
	Verdict   string    `json:"verdict"`
	CreatedAt time.Time `json:"created_at"`
}

type Stats struct {
	Blocked24h    int     `json:"blocked_24h"`
	Challenged24h int     `json:"challenged_24h"`
	Threshold     float64 `json:"threshold"`
}

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// Evaluate scores an auth attempt's User-Agent and, when suspicious, records a
// verdict scoped to the tenant the email belongs to. Best-effort: it never
// blocks or fails the auth path. Called from the auth HTTP handlers, which hold
// the UA + client IP.
func (s *Service) Evaluate(ctx context.Context, email, ip, ua string) {
	score := Score(ua)
	if score < recordFloor {
		return // clearly human — don't log
	}
	var tenantID uuid.UUID
	if err := s.pool.QueryRow(ctx, `
		SELECT tenant_id FROM "user".users
		WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL AND tenant_id IS NOT NULL
		LIMIT 1
	`, email).Scan(&tenantID); err != nil {
		return // no tenant to scope the verdict to
	}
	settings, err := s.GetSettings(ctx, tenantID)
	if err != nil || !settings.UACheck {
		return // UA scoring disabled for this tenant
	}
	verdict := "allowed"
	switch {
	case score >= settings.ScoreThreshold:
		verdict = "blocked"
	case score >= challengeFloor:
		verdict = "challenged"
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO auth.bot_events (tenant_id, ip, user_agent, score, verdict)
		VALUES ($1, NULLIF($2,'')::inet, $3, $4, $5)
	`, tenantID, ip, ua, score, verdict); err != nil {
		slog.Warn("record bot event", "err", err)
	}
}

func (s *Service) Recent(ctx context.Context, tenantID uuid.UUID, limit int) ([]Event, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, host(ip), user_agent, score, verdict, created_at
		FROM auth.bot_events WHERE tenant_id = $1
		ORDER BY created_at DESC LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Event, 0)
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.IP, &e.UserAgent, &e.Score, &e.Verdict, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Service) Stats(ctx context.Context, tenantID uuid.UUID) (*Stats, error) {
	st := Stats{}
	if err := s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE verdict = 'blocked' AND created_at >= NOW() - INTERVAL '24 hours'),
			COUNT(*) FILTER (WHERE verdict = 'challenged' AND created_at >= NOW() - INTERVAL '24 hours')
		FROM auth.bot_events WHERE tenant_id = $1
	`, tenantID).Scan(&st.Blocked24h, &st.Challenged24h); err != nil {
		return nil, err
	}
	settings, err := s.GetSettings(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	st.Threshold = settings.ScoreThreshold
	return &st, nil
}

func (s *Service) GetSettings(ctx context.Context, tenantID uuid.UUID) (Settings, error) {
	var st Settings
	err := s.pool.QueryRow(ctx, `
		SELECT ua_check, honeypot, captcha, signature, score_threshold
		FROM auth.bot_settings WHERE tenant_id = $1
	`, tenantID).Scan(&st.UACheck, &st.Honeypot, &st.Captcha, &st.Signature, &st.ScoreThreshold)
	if err == pgx.ErrNoRows {
		return DefaultSettings(), nil
	}
	if err != nil {
		return Settings{}, err
	}
	return st, nil
}

func (s *Service) UpdateSettings(ctx context.Context, tenantID uuid.UUID, in Settings) (Settings, error) {
	if in.ScoreThreshold < 0.1 {
		in.ScoreThreshold = 0.1
	}
	if in.ScoreThreshold > 1 {
		in.ScoreThreshold = 1
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO auth.bot_settings (tenant_id, ua_check, honeypot, captcha, signature, score_threshold, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			ua_check = EXCLUDED.ua_check,
			honeypot = EXCLUDED.honeypot,
			captcha = EXCLUDED.captcha,
			signature = EXCLUDED.signature,
			score_threshold = EXCLUDED.score_threshold,
			updated_at = NOW()
	`, tenantID, in.UACheck, in.Honeypot, in.Captcha, in.Signature, in.ScoreThreshold)
	if err != nil {
		return Settings{}, err
	}
	return in, nil
}

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/security/bots", h.overview)
	r.Get("/tenants/{tenantID}/security/bots/settings", h.getSettings)
	r.Put("/tenants/{tenantID}/security/bots/settings", h.putSettings)
}

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	pathTenant, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrBadRequest.WithDetail("invalid tenantID")
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if pathTenant != scope {
		return uuid.Nil, errs.ErrForbidden.WithDetail("tenant mismatch")
	}
	return scope, nil
}

func (h *Handler) overview(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	recent, err := h.Service.Recent(r.Context(), tenantID, 50)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	stats, err := h.Service.Stats(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"recent": recent, "stats": stats})
}

func (h *Handler) getSettings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	st, err := h.Service.GetSettings(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (h *Handler) putSettings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in Settings
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	st, err := h.Service.UpdateSettings(r.Context(), tenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}
