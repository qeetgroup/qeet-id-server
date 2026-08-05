// Package sales captures in-app "Contact sales" leads (the Enterprise CTA that
// used to be a mailto: link). A lead is persisted for follow-up and, best-effort,
// emailed to the configured sales inbox. Available to any authenticated user —
// tenant/user are recorded when known, but a lead can be submitted during
// onboarding before an org exists.
package sales

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/sales/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// Lead is a contact-sales submission from the console.
type Lead struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Company  string `json:"company"`
	TeamSize string `json:"team_size"`
	Message  string `json:"message"`
	Source   string `json:"source"` // e.g. "onboarding" | "billing"
}

type Service struct {
	q          *dbgen.Queries
	sender     notifier.Sender
	salesInbox string
}

func NewService(pool *pgxpool.Pool, sender notifier.Sender, salesInbox string) *Service {
	return &Service{q: dbgen.New(pool), sender: sender, salesInbox: salesInbox}
}

func pgUUID(id *uuid.UUID) pgtype.UUID {
	if id == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: *id, Valid: true}
}

// Submit persists the lead and, best-effort, notifies the sales inbox.
func (s *Service) Submit(ctx context.Context, tenantID, userID *uuid.UUID, in Lead) error {
	email := strings.TrimSpace(in.Email)
	if email == "" {
		return errs.ErrBadRequest.WithMessage("A work email is required.")
	}
	if _, err := s.q.InsertSalesLead(ctx, dbgen.InsertSalesLeadParams{
		TenantID: pgUUID(tenantID),
		UserID:   pgUUID(userID),
		Name:     strings.TrimSpace(in.Name),
		Email:    email,
		Company:  strings.TrimSpace(in.Company),
		TeamSize: strings.TrimSpace(in.TeamSize),
		Message:  strings.TrimSpace(in.Message),
		Source:   strings.TrimSpace(in.Source),
	}); err != nil {
		return err
	}
	s.notify(ctx, in, email)
	return nil
}

// notify emails the sales inbox. Best-effort: a delivery failure must not fail
// the submission (the lead is already persisted).
func (s *Service) notify(ctx context.Context, in Lead, email string) {
	if s.sender == nil || s.salesInbox == "" {
		return
	}
	body := fmt.Sprintf(
		"New Enterprise lead\n\nName: %s\nEmail: %s\nCompany: %s\nTeam size: %s\nSource: %s\n\nMessage:\n%s",
		in.Name, email, in.Company, in.TeamSize, in.Source, in.Message,
	)
	subject := "New Enterprise lead"
	if c := strings.TrimSpace(in.Company); c != "" {
		subject = "New Enterprise lead — " + c
	}
	if err := s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      s.salesInbox,
		Subject: subject,
		Body:    body,
	}); err != nil {
		slog.Warn("sales lead notification failed", "err", err, "email", email)
	}
}

// Handler exposes the contact-sales endpoint.
type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/sales/leads", h.submit)
}

func (h *Handler) submit(w http.ResponseWriter, r *http.Request) {
	var in Lead
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var tenantID, userID *uuid.UUID
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil {
		tenantID, userID = p.TenantID, p.UserID
	}
	if err := h.Service.Submit(r.Context(), tenantID, userID, in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"status": "received"})
}
