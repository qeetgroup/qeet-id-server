// Package bot scores sign-in requests for bot-likeness with an offline
// User-Agent heuristic and records suspicious verdicts for the admin
// "Threats → Bots" screen. It only detects: a "blocked" verdict means "would
// block", and no sign-in is refused on it.
package bot

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/threat/bot/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
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
	paging.Result[Event]
	Total int `json:"total"`
}

// Overview is the bot-detection screen's body: a page of detections and the
// counts above them.
type Overview struct {
	*Page
	Stats *Stats `json:"stats"`
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
	if row.OrganizationID == nil {
		return
	}
	organizationID, userID := *row.OrganizationID, row.ID
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
	if err := s.q.InsertBotEvent(ctx, dbgen.InsertBotEventParams{
		OrganizationID: organizationID, Ip: ip, UserAgent: ua, Score: float32(score), Verdict: verdict, UserID: &userID,
	}); err != nil {
		slog.Warn("record bot event", "err", err)
	}
}

// List returns a page of up to limit of the organization's detections (50 when
// unset, at most 200), newest first, after the cursor, of verdict when given,
// and how many there are.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID, limit int, after paging.Cursor, verdict string) (*Page, error) {
	limit = paging.Clamp(limit, 50, 200)
	total, err := s.q.CountBotEvents(ctx, dbgen.CountBotEventsParams{OrganizationID: organizationID, Verdict: verdict})
	if err != nil {
		return nil, err
	}
	params := dbgen.ListBotEventsParams{
		OrganizationID: organizationID, Verdict: verdict, OutcomeWindow: outcomeWindow.String(),
		Lim: int32(limit + 1), // #nosec G115 -- at most 201
	}
	params.BeforeTs, params.BeforeID = after.Before()
	rows, err := s.q.ListBotEvents(ctx, params)
	if err != nil {
		return nil, err
	}
	items := make([]Event, len(rows))
	for i, row := range rows {
		items[i] = Event{
			ID: row.ID, IP: postgres.NullIfZero(row.Ip), UserAgent: row.UserAgent, Score: float64(row.Score),
			Verdict: row.Verdict, CreatedAt: row.CreatedAt, UserID: row.UserID, UserEmail: row.UserEmail, Outcome: row.Outcome,
		}
	}
	return &Page{
		Result: paging.Page(paging.Next(items, limit, func(e Event) (time.Time, uuid.UUID) { return e.CreatedAt, e.ID })),
		Total:  int(total),
	}, nil
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
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "bot.settings_updated", "organization", organizationID,
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
