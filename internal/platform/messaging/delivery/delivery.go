// Package delivery records what happened to each email the platform sends and
// keeps the list of addresses no mail goes to.
//
// Tracker wraps the email transport: an address on the suppression list is
// refused before any provider sees it (errs.ErrEmailSuppressed), and every
// send is recorded (sent, or failed with the reason). The provider's later
// reports — delivered, bounced, complained — arrive at the SES webhook
// (Webhook) and update the record. A hard bounce or a complaint suppresses
// the address, platform-wide; a soft bounce is only recorded.
//
// Addresses are stored as a SHA-256 of the trimmed, lower-cased address
// (HashAddress) for lookups, and a masked hint (Hint) for people; never in
// plain text.
package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/delivery/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// Message statuses, in the order a message moves through them.
const (
	StatusSent       = "sent"
	StatusDelivered  = "delivered"
	StatusBounced    = "bounced"
	StatusComplained = "complained"
	StatusSuppressed = "suppressed"
	StatusFailed     = "failed"
)

// rank orders the statuses a provider report can set, so a late or repeated
// report never moves a message back (a delivery after a complaint).
var rank = map[string]int{StatusSent: 0, StatusDelivered: 1, StatusBounced: 2, StatusFailed: 2, StatusComplained: 3}

var messagesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "email_messages_total",
	Help: "Emails by template and status: sent, failed and suppressed when sent; delivered, bounced and complained as the provider reports them.",
}, []string{"template", "status"})

func count(template, status string) {
	if template == "" {
		template = "none"
	}
	messagesTotal.WithLabelValues(template, status).Inc()
}

// HashAddress is the lookup key for an address: SHA-256 of it trimmed and
// lower-cased, hex.
func HashAddress(address string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(address))))
	return hex.EncodeToString(sum[:])
}

// Hint is an address masked for display: its first character and domain
// ("a***@example.com").
func Hint(address string) string {
	address = strings.ToLower(strings.TrimSpace(address))
	local, domain, ok := strings.Cut(address, "@")
	if !ok || local == "" {
		return "***"
	}
	return local[:1] + "***@" + domain
}

// Store reads and writes the delivery records.
type Store struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool, q: dbgen.New(pool)} }

// Suppression is an address no mail goes to.
type Suppression struct {
	ID          uuid.UUID  `json:"id"`
	AddressHint string     `json:"address,omitempty"`
	Reason      string     `json:"reason"`
	Detail      string     `json:"detail,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	TenantID    *uuid.UUID `json:"-"`
}

// Suppressed returns the active suppression of address, or nil.
func (s *Store) Suppressed(ctx context.Context, address string) (*Suppression, error) {
	row, err := s.q.ActiveSuppression(ctx, HashAddress(address))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sup := &Suppression{ID: row.ID, Reason: row.Reason, Detail: row.Detail, CreatedAt: row.CreatedAt}
	if row.TenantID.Valid {
		sup.TenantID = &row.TenantID.UUID
	}
	return sup, nil
}

// Record is one email as it left (or didn't leave) the platform.
type Record struct {
	TenantID          string // the message's organisation; "" for none
	To, Template      string
	Provider          string
	ProviderMessageID string
	Status, Reason    string
}

// RecordSend stores one send.
func (s *Store) RecordSend(ctx context.Context, r Record) (uuid.UUID, error) {
	var tenant uuid.NullUUID
	if id, err := uuid.Parse(r.TenantID); err == nil {
		tenant = uuid.NullUUID{UUID: id, Valid: true}
	}
	var providerID *string
	if r.ProviderMessageID != "" {
		providerID = &r.ProviderMessageID
	}
	return s.q.InsertMessage(ctx, dbgen.InsertMessageParams{
		TenantID: tenant, ToHash: HashAddress(r.To), ToHint: Hint(r.To), Template: r.Template,
		Provider: r.Provider, ProviderMessageID: providerID, Status: r.Status, StatusReason: r.Reason,
	})
}

// Event is one provider report about a message it accepted.
type Event struct {
	Provider, ProviderMessageID string
	// Status is delivered, bounced or complained.
	Status string
	Reason string
	// Suppress lists the addresses to stop mailing (a hard bounce's or a
	// complaint's recipients); a soft bounce suppresses nothing.
	Suppress []string
}

// Apply records ev against the message it reports on, and suppresses its
// addresses. A report about a message we have no record of (sent before
// records began, or by another system on the same account) still suppresses.
func (s *Store) Apply(ctx context.Context, ev Event) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	template := ""
	defer func() { count(template, ev.Status) }()

	var tenant, message uuid.NullUUID
	msg, err := q.MessageByProviderID(ctx, dbgen.MessageByProviderIDParams{Provider: ev.Provider, ProviderMessageID: &ev.ProviderMessageID})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return err
	default:
		tenant, message, template = msg.TenantID, uuid.NullUUID{UUID: msg.ID, Valid: true}, msg.Template
		if rank[ev.Status] > rank[msg.Status] {
			if err := q.SetMessageStatus(ctx, dbgen.SetMessageStatusParams{ID: msg.ID, Status: ev.Status, StatusReason: ev.Reason}); err != nil {
				return err
			}
		}
	}
	reason := "bounce"
	if ev.Status == StatusComplained {
		reason = "complaint"
	}
	for _, address := range ev.Suppress {
		if err := q.Suppress(ctx, dbgen.SuppressParams{
			TenantID: tenant, AddressHash: HashAddress(address), AddressHint: Hint(address),
			Reason: reason, Detail: ev.Reason, MessageID: message,
		}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// MessageView is one message as the console shows it.
type MessageView struct {
	ID        uuid.UUID `json:"id"`
	Template  string    `json:"template"`
	Status    string    `json:"status"`
	Reason    string    `json:"reason,omitempty"`
	SentAt    time.Time `json:"sent_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// MessagesTo lists the organisation's most recent messages to address.
func (s *Store) MessagesTo(ctx context.Context, tenantID uuid.UUID, address string, limit int32) ([]MessageView, error) {
	rows, err := s.q.ListMessagesTo(ctx, dbgen.ListMessagesToParams{
		TenantID: uuid.NullUUID{UUID: tenantID, Valid: true}, ToHash: HashAddress(address), Lim: limit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]MessageView, len(rows))
	for i, r := range rows {
		out[i] = MessageView{ID: r.ID, Template: r.Template, Status: r.Status, Reason: r.StatusReason, SentAt: r.SentAt, UpdatedAt: r.UpdatedAt}
	}
	return out, nil
}

// Suppressions lists the active suppressions the organisation's mail caused.
func (s *Store) Suppressions(ctx context.Context, tenantID uuid.UUID, limit int32) ([]Suppression, error) {
	rows, err := s.q.ListSuppressions(ctx, dbgen.ListSuppressionsParams{TenantID: uuid.NullUUID{UUID: tenantID, Valid: true}, Lim: limit})
	if err != nil {
		return nil, err
	}
	out := make([]Suppression, len(rows))
	for i, r := range rows {
		out[i] = Suppression{ID: r.ID, AddressHint: r.AddressHint, Reason: r.Reason, Detail: r.Detail, CreatedAt: r.CreatedAt}
	}
	return out, nil
}

// ClearSuppression lifts suppression id in tx, if the organisation's mail
// caused it; errs.ErrNotFound otherwise. The caller audits it in the same tx.
func (s *Store) ClearSuppression(ctx context.Context, tx pgx.Tx, tenantID, id uuid.UUID, by *uuid.UUID) (*Suppression, error) {
	var clearedBy uuid.NullUUID
	if by != nil {
		clearedBy = uuid.NullUUID{UUID: *by, Valid: true}
	}
	row, err := s.q.WithTx(tx).ClearSuppression(ctx, dbgen.ClearSuppressionParams{
		ID: id, TenantID: uuid.NullUUID{UUID: tenantID, Valid: true}, ClearedBy: clearedBy,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &Suppression{ID: id, AddressHint: row.AddressHint, Reason: row.Reason}, nil
}

// Pool exposes the pool so a handler can wrap a change and its audit row.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Retention is how long a message record is kept (the daily
// email-delivery-cleanup job); suppressions are kept until cleared.
const Retention = 90 * 24 * time.Hour

// DeleteBefore removes message records sent before t (suppressions stay).
func (s *Store) DeleteBefore(ctx context.Context, t time.Time) (int64, error) {
	return s.q.DeleteMessagesBefore(ctx, t)
}

// idSender is a sender that reports the provider's id for what it accepted.
type idSender interface {
	SendID(ctx context.Context, m notifier.Message) (string, error)
}

// Tracker is the email transport with the suppression list in front and a
// record of every send behind. Other channels pass straight through.
type Tracker struct {
	Next  notifier.Sender
	Store *Store
	// Provider names the email transport in the records ("ses", "smtp";
	// "none" when there is none).
	Provider string
}

func (t Tracker) Send(ctx context.Context, m notifier.Message) error {
	if m.Channel != "" && m.Channel != "email" {
		return t.Next.Send(ctx, m)
	}
	rec := Record{TenantID: m.TenantID, To: m.To, Template: m.TemplateKey, Provider: t.Provider}

	// A failed look-up doesn't stop the mail: the list protects the sending
	// domain's reputation, not anyone's access.
	sup, err := t.Store.Suppressed(ctx, m.To)
	if err != nil {
		slog.Warn("email suppression check failed; sending anyway", "err", err)
	}
	if sup != nil {
		rec.Status, rec.Reason = StatusSuppressed, "address suppressed after a "+sup.Reason
		t.record(ctx, rec)
		return errs.ErrEmailSuppressed.WithDetail(fmt.Sprintf("this address was suppressed after a %s on %s", sup.Reason, sup.CreatedAt.Format("2 Jan 2006")))
	}

	if s, ok := t.Next.(idSender); ok {
		rec.ProviderMessageID, err = s.SendID(ctx, m)
	} else {
		err = t.Next.Send(ctx, m)
	}
	rec.Status = StatusSent
	if err != nil {
		rec.Status, rec.Reason = StatusFailed, failureReason(err)
	}
	t.record(ctx, rec)
	return err
}

func (t Tracker) record(ctx context.Context, rec Record) {
	count(rec.Template, rec.Status)
	if _, err := t.Store.RecordSend(ctx, rec); err != nil {
		slog.Error("email delivery record failed", "err", err, "status", rec.Status)
	}
}

// failureReason is what a failed send's record says: the error code when the
// platform refused it, else a bounded excerpt of the provider's error.
func failureReason(err error) string {
	var e *errs.Error
	if errors.As(err, &e) {
		return e.Code
	}
	msg := err.Error()
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}
