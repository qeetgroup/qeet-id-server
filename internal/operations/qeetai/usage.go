package qeetai

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/qeetai/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// RecordUsage adds one turn, with the tokens its provider said it used, to
// tenantID's month.
func (s *Service) RecordUsage(ctx context.Context, tenantID uuid.UUID, input, output int) error {
	return s.q.RecordUsage(ctx, dbgen.RecordUsageParams{TenantID: tenantID, InputTokens: int64(input), OutputTokens: int64(output)})
}

// MonthUsage is what an organisation's Qeet AI used in one UTC month: its
// turns (messages answered) and the tokens they took.
type MonthUsage struct {
	Month        string    `json:"month"`
	Messages     int       `json:"messages"`
	InputTokens  int64     `json:"input_tokens"`
	OutputTokens int64     `json:"output_tokens"`
	LastUsedAt   time.Time `json:"last_used_at"`
}

// Usage is the organisation's use this month, its last use, and its twelve
// most recent months.
type Usage struct {
	ThisMonth  MonthUsage   `json:"this_month"`
	LastUsedAt *time.Time   `json:"last_used_at"`
	Months     []MonthUsage `json:"months"`
}

// UsageOf returns tenantID's Usage.
func (s *Service) UsageOf(ctx context.Context, tenantID uuid.UUID) (*Usage, error) {
	rows, err := s.q.ListUsage(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	thisMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).Format("2006-01")
	out := &Usage{ThisMonth: MonthUsage{Month: thisMonth}, Months: make([]MonthUsage, len(rows))}
	for i, r := range rows {
		m := MonthUsage{Month: r.Month.Time.Format("2006-01"), Messages: int(r.Messages), InputTokens: r.InputTokens,
			OutputTokens: r.OutputTokens, LastUsedAt: r.LastUsedAt}
		out.Months[i] = m
		if m.Month == thisMonth {
			out.ThisMonth = m
		}
		if out.LastUsedAt == nil || m.LastUsedAt.After(*out.LastUsedAt) {
			at := m.LastUsedAt
			out.LastUsedAt = &at
		}
	}
	return out, nil
}

// Settings are an organisation's Qeet AI settings: how many days an
// untouched conversation is kept (nil: always), and their last change.
type Settings struct {
	ConversationRetentionDays *int       `json:"conversation_retention_days"`
	UpdatedAt                 *time.Time `json:"updated_at,omitempty"`
	UpdatedBy                 *uuid.UUID `json:"updated_by,omitempty"`
	UpdatedByEmail            *string    `json:"updated_by_email,omitempty"`
}

// SettingsOf returns tenantID's Settings.
func (s *Service) SettingsOf(ctx context.Context, tenantID uuid.UUID) (*Settings, error) {
	row, err := s.q.GetSettings(ctx, tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return &Settings{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := &Settings{UpdatedAt: &row.UpdatedAt, UpdatedByEmail: row.UpdatedByEmail}
	if row.ConversationRetentionDays != nil {
		d := int(*row.ConversationRetentionDays)
		out.ConversationRetentionDays = &d
	}
	if row.UpdatedBy.Valid {
		by := uuid.UUID(row.UpdatedBy.Bytes)
		out.UpdatedBy = &by
	}
	return out, nil
}

// SetSettings stores tenantID's settings, as actor's change: days from 1 to
// 3650, or nil to keep conversations.
func (s *Service) SetSettings(ctx context.Context, tenantID uuid.UUID, days *int, actor audit.Actor) (*Settings, error) {
	var stored *int32
	if days != nil {
		if *days < 1 || *days > 3650 {
			return nil, errs.ErrValidationFailed.WithFields([]errs.FieldError{{
				Field: "conversation_retention_days", Code: "out_of_range", Message: "Keep conversations for 1 to 3,650 days, or leave it empty to keep them.",
			}})
		}
		d := int32(*days) // #nosec G115 -- 1 to 3650
		stored = &d
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var by pgtype.UUID
	if actor.UserID != nil {
		by = pgtype.UUID{Bytes: *actor.UserID, Valid: true}
	}
	if err := s.q.WithTx(tx).UpsertSettings(ctx, dbgen.UpsertSettingsParams{TenantID: tenantID, ConversationRetentionDays: stored, UpdatedBy: by}); err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "qeetai.settings_updated", "qeetai_settings", tenantID,
		map[string]any{"conversation_retention_days": days})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.SettingsOf(ctx, tenantID)
}

// retentionBatch is how many conversations one delete removes.
const retentionBatch = 1000

// PurgeExpiredConversations deletes, with their messages, every
// organisation's conversations untouched for longer than it keeps them, and
// audits each organisation's deletion on its chain. It returns how many went.
func PurgeExpiredConversations(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	q := dbgen.New(pool)
	tenants, err := q.ListConversationRetention(ctx)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, t := range tenants {
		var deleted int64
		for {
			n, err := q.DeleteExpiredConversations(ctx, dbgen.DeleteExpiredConversationsParams{TenantID: t.TenantID, Days: t.Days, RowLimit: retentionBatch})
			if err != nil {
				return total, err
			}
			deleted += n
			if n < retentionBatch {
				break
			}
		}
		if deleted == 0 {
			continue
		}
		total += deleted
		if err := recordPurge(ctx, pool, t.TenantID, deleted, t.Days); err != nil {
			slog.Warn("qeetai: audit the conversation purge", "tenant_id", t.TenantID, "err", err)
		}
	}
	return total, nil
}

// recordPurge audits on tenantID's chain that deleted conversations older
// than days were removed.
func recordPurge(ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID, deleted int64, days int32) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := audit.Record(ctx, tx, audit.Actor{Type: "system"}.Event(tenantID, "qeetai.conversations_purged", "qeetai_settings", tenantID,
		map[string]any{"deleted": deleted, "days": days})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// usage handles GET /v1/tenants/{tenantID}/qeetai/usage.
func (h *Handler) usage(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Admin.UsageOf(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// settings handles GET /v1/tenants/{tenantID}/qeetai/settings.
func (h *Handler) settings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Admin.SettingsOf(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// putSettings handles PUT /v1/tenants/{tenantID}/qeetai/settings.
func (h *Handler) putSettings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		ConversationRetentionDays *int `json:"conversation_retention_days"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Admin.SetSettings(r.Context(), tenantID, in.ConversationRetentionDays, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
