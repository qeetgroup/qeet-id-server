// Package sales captures in-app "Contact sales" leads. A lead is saved for
// follow-up and, best-effort, emailed to the sales inbox. Any signed-in user may
// submit one: organization and user are recorded when known, since a lead can come
// before an organization exists.
package sales

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/sales/dbgen"
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
	Source   string `json:"source"`
}

// Service records sales leads.
type Service struct {
	q          *dbgen.Queries
	sender     notifier.Sender
	salesInbox string
}

// NewService returns a Service that emails leads to salesInbox through sender;
// with an empty salesInbox (none configured) it only saves them. It refuses a
// nil sender.
func NewService(pool *pgxpool.Pool, sender notifier.Sender, salesInbox string) (*Service, error) {
	if sender == nil {
		return nil, errors.New("sales: a sender is required to email the sales inbox")
	}
	return &Service{q: dbgen.New(pool), sender: sender, salesInbox: salesInbox}, nil
}

// Submit saves the lead and, best-effort, emails the sales inbox. The email
// address is required.
func (s *Service) Submit(ctx context.Context, organizationID, userID *uuid.UUID, in Lead) error {
	email := strings.TrimSpace(in.Email)
	if email == "" {
		return errs.ErrBadRequest.WithMessage("A work email is required.")
	}
	if _, err := s.q.InsertSalesLead(ctx, dbgen.InsertSalesLeadParams{
		OrganizationID: organizationID,
		UserID:         userID,
		Name:           strings.TrimSpace(in.Name),
		Email:          email,
		Company:        strings.TrimSpace(in.Company),
		TeamSize:       strings.TrimSpace(in.TeamSize),
		Message:        strings.TrimSpace(in.Message),
		Source:         strings.TrimSpace(in.Source),
	}); err != nil {
		return err
	}
	s.notify(ctx, in, email)
	return nil
}

// notify emails the lead to the sales inbox, if one is configured. A failure is
// only logged: the lead is already saved.
func (s *Service) notify(ctx context.Context, in Lead, email string) {
	if s.salesInbox == "" {
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
		slog.Warn("sales lead notification failed", "err", err, "email", httpx.SanitizeForLog(email))
	}
}
