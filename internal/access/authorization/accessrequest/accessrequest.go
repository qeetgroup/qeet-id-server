// Package accessrequest lets a person ask their organization for a role, for a while or for good, and
// an administrator approve or deny it from the console or the phone. Approving grants the role through
// RBAC (seat, audit, token-change signal); a scheduled job takes back time-limited grants and lapses
// requests nobody answered.
package accessrequest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/accessrequest/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/notification"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
	"github.com/qeetgroup/qeet-id-server/internal/platform/strutil"
)

const (
	// PendingFor is how long a request waits for an answer before it lapses.
	PendingFor = 14 * 24 * time.Hour
	// MaxDurationHours is the longest a time-limited grant can last: 90 days.
	MaxDurationHours = 2160
	// maxText bounds a reason and a decision note, in characters.
	maxText = 500
	// ReviewPermission is what answering a request needs: the same as giving
	// someone a role directly.
	ReviewPermission = "role.write"
	// SweepInterval is how often lapsed requests and ended grants are handled.
	SweepInterval = 5 * time.Minute
)

// Statuses a request can have.
const (
	StatusPending   = "pending"
	StatusApproved  = "approved"
	StatusDenied    = "denied"
	StatusCancelled = "cancelled"
	StatusExpired   = "expired"
)

// Person names someone in a request.
type Person struct {
	ID    uuid.UUID `json:"id"`
	Email string    `json:"email"`
	Name  string    `json:"name,omitempty"`
}

// Role names the role asked for.
type Role struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
}

// AccessRequest is one request and, once answered, its answer.
type AccessRequest struct {
	ID        uuid.UUID `json:"id"`
	Requester Person    `json:"requester"`
	Role      Role      `json:"role"`
	Reason    string    `json:"reason"`
	// DurationHours is how long the role is asked for; absent means for good.
	DurationHours *int      `json:"duration_hours,omitempty"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	// ExpiresAt is when a pending request lapses.
	ExpiresAt    time.Time  `json:"expires_at"`
	DecidedBy    *Person    `json:"decided_by,omitempty"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
	DecisionNote string     `json:"decision_note,omitempty"`
	// AccessEndsAt is when an approved, time-limited grant is taken back.
	AccessEndsAt *time.Time `json:"access_ends_at,omitempty"`
	// EndedAt is when it was.
	EndedAt *time.Time `json:"ended_at,omitempty"`
}

// RequestableRole is a role a person may ask for, and whether they hold it.
type RequestableRole struct {
	Role
	Held bool `json:"held"`
}

// CreateInput is a person's request.
type CreateInput struct {
	RoleID        uuid.UUID `json:"role_id"`
	Reason        string    `json:"reason"`
	DurationHours *int      `json:"duration_hours,omitempty"`
}

// RoleGranter gives and takes back roles (rbac.Service): seats, audit and the
// token-change signal come with it. A role is given inside the approval's own
// transaction, so the grant and the answer are one.
type RoleGranter interface {
	SeatLimit(ctx context.Context, organizationID uuid.UUID) (int, error)
	AssignRoleInTx(ctx context.Context, tx pgx.Tx, limit int, userID, organizationID, roleID uuid.UUID, grantedBy *uuid.UUID, actor audit.Actor) (func(), error)
	UnassignRole(ctx context.Context, userID, organizationID, roleID uuid.UUID, actor audit.Actor) error
}

// Approvers lists who can answer a request (rbac.Repository).
type Approvers interface {
	UsersWithPermission(ctx context.Context, organizationID uuid.UUID, permKey string) ([]uuid.UUID, error)
}

// PhoneNotifier tells someone's linked phones (Qeet ID on the phone) about
// something waiting for them; NoPhones for a process that sends no push.
type PhoneNotifier interface {
	NotifyPhones(ctx context.Context, userID uuid.UUID, title, body string, data map[string]string)
}

// NoPhones is a PhoneNotifier that tells no phone.
type NoPhones struct{}

// NotifyPhones does nothing.
func (NoPhones) NotifyPhones(context.Context, uuid.UUID, string, string, map[string]string) {}

// Service answers for access requests.
type Service struct {
	pool      *pgxpool.Pool
	q         *dbgen.Queries
	roles     RoleGranter
	approvers Approvers
	notifier  notification.Notifier
	phones    PhoneNotifier
	now       func() time.Time
}

// NewService returns a Service over pool that grants through roles, finds
// who answers through approvers and tells people in the app through notifier
// and on their phones through phones.
func NewService(pool *pgxpool.Pool, roles RoleGranter, approvers Approvers, notifier notification.Notifier, phones PhoneNotifier) (*Service, error) {
	switch {
	case roles == nil:
		return nil, errors.New("accessrequest: the service needs a role granter")
	case approvers == nil:
		return nil, errors.New("accessrequest: the service needs approvers")
	case notifier == nil:
		return nil, errors.New("accessrequest: the service needs a notifier")
	case phones == nil:
		return nil, errors.New("accessrequest: the service needs a phone notifier")
	}
	return &Service{pool: pool, q: dbgen.New(pool), roles: roles, approvers: approvers, notifier: notifier, phones: phones, now: time.Now}, nil
}

// cleanText trims s and checks it is 1..maxText characters (or, when optional,
// empty).
func cleanText(s string, optional bool, field string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" && optional {
		return "", nil
	}
	if s == "" {
		return "", errs.ErrBadRequest.WithDetail(field + " is required")
	}
	if utf8.RuneCountInString(s) > maxText {
		return "", errs.ErrBadRequest.WithDetail(fmt.Sprintf("%s is longer than %d characters", field, maxText))
	}
	return s, nil
}

// Create records requester's request in organizationID and tells the people who can
// answer it. A role the requester already holds directly, or one they already
// asked for and is waiting, is refused.
func (s *Service) Create(ctx context.Context, organizationID, requesterID uuid.UUID, in CreateInput, actor audit.Actor) (*AccessRequest, error) {
	reason, err := cleanText(in.Reason, false, "reason")
	if err != nil {
		return nil, err
	}
	var hours *int32
	if in.DurationHours != nil {
		if *in.DurationHours < 1 || *in.DurationHours > MaxDurationHours {
			return nil, errs.ErrBadRequest.WithDetail(fmt.Sprintf("duration_hours must be 1 to %d", MaxDurationHours))
		}
		h := int32(*in.DurationHours)
		hours = &h
	}
	if _, err := s.q.RequestableRole(ctx, dbgen.RequestableRoleParams{RoleID: in.RoleID, OrganizationID: organizationID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound.WithDetail("no such role to ask for")
		}
		return nil, err
	}
	held, err := s.q.HoldsRole(ctx, dbgen.HoldsRoleParams{UserID: requesterID, OrganizationID: organizationID, RoleID: in.RoleID})
	if err != nil {
		return nil, err
	}
	if held {
		return nil, ErrRoleHeld
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	id, err := s.q.WithTx(tx).InsertAccessRequest(ctx, dbgen.InsertAccessRequestParams{
		OrganizationID: organizationID, RequesterID: requesterID, RoleID: in.RoleID,
		Reason: reason, DurationHours: hours, ExpiresAt: s.now().Add(PendingFor),
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrPending
		}
		return nil, err
	}
	meta := map[string]any{"role_id": in.RoleID, "reason": reason}
	if hours != nil {
		meta["duration_hours"] = *hours
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "access_request.created", "access_request", id, meta)); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	req, err := s.Get(ctx, organizationID, id)
	if err != nil {
		return nil, err
	}
	s.tellApprovers(ctx, organizationID, req)
	return req, nil
}

// tellApprovers tells everyone who can answer req, except its requester, in
// the app and on their linked phones. Best effort: a failure is logged.
func (s *Service) tellApprovers(ctx context.Context, organizationID uuid.UUID, req *AccessRequest) {
	ids, err := s.approvers.UsersWithPermission(ctx, organizationID, ReviewPermission)
	if err != nil {
		slog.WarnContext(ctx, "access request: listing approvers", "err", err)
		return
	}
	title := fmt.Sprintf("%s asks for %s", displayName(req.Requester), req.Role.Name)
	for _, id := range ids {
		if id == req.Requester.ID {
			continue
		}
		s.notify(ctx, organizationID, id, "info", title, req.Reason)
		s.phones.NotifyPhones(ctx, id, "Access request", title,
			map[string]string{"kind": "access_request", "access_request_id": req.ID.String(), "organization_id": organizationID.String()})
	}
}

func (s *Service) notify(ctx context.Context, organizationID, userID uuid.UUID, kind, title, description string) {
	if err := s.notifier.Notify(ctx, organizationID, userID, kind, title, description, ""); err != nil {
		slog.WarnContext(ctx, "access request: notifying", "err", err)
	}
}

func displayName(p Person) string {
	if p.Name != "" {
		return p.Name
	}
	return p.Email
}

// Get returns one of organizationID's requests.
func (s *Service) Get(ctx context.Context, organizationID, id uuid.UUID) (*AccessRequest, error) {
	row, err := s.q.GetAccessRequest(ctx, dbgen.GetAccessRequestParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toRequest(row), nil
}

// List returns up to limit of organizationID's requests, newest first; status, when
// not empty, keeps only those with it.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID, status string, limit int) ([]AccessRequest, error) {
	limit = paging.Clamp(limit, 100, 200)
	var st *string
	if status != "" {
		switch status {
		case StatusPending, StatusApproved, StatusDenied, StatusCancelled, StatusExpired:
		default:
			return nil, errs.ErrBadRequest.WithDetail("unknown status")
		}
		st = &status
	}
	rows, err := s.q.ListAccessRequests(ctx, dbgen.ListAccessRequestsParams{OrganizationID: organizationID, Status: st, RowLimit: int32(limit)}) // #nosec G115 -- clamped to at most 200
	if err != nil {
		return nil, err
	}
	out := make([]AccessRequest, 0, len(rows))
	for _, r := range rows {
		out = append(out, *toRequest(dbgen.GetAccessRequestRow(r)))
	}
	return out, nil
}

// ListMine returns requesterID's requests in organizationID, newest first.
func (s *Service) ListMine(ctx context.Context, organizationID, requesterID uuid.UUID) ([]AccessRequest, error) {
	rows, err := s.q.ListMyAccessRequests(ctx, dbgen.ListMyAccessRequestsParams{OrganizationID: organizationID, RequesterID: requesterID})
	if err != nil {
		return nil, err
	}
	out := make([]AccessRequest, 0, len(rows))
	for _, r := range rows {
		out = append(out, *toRequest(dbgen.GetAccessRequestRow(r)))
	}
	return out, nil
}

// PendingCount is how many of organizationID's requests are waiting.
func (s *Service) PendingCount(ctx context.Context, organizationID uuid.UUID) (int64, error) {
	return s.q.CountPendingAccessRequests(ctx, organizationID)
}

// RequestableRoles lists the roles userID may ask for in organizationID, marking the
// ones they already hold.
func (s *Service) RequestableRoles(ctx context.Context, organizationID, userID uuid.UUID) ([]RequestableRole, error) {
	rows, err := s.q.ListRequestableRoles(ctx, dbgen.ListRequestableRolesParams{OrganizationID: organizationID, UserID: userID})
	if err != nil {
		return nil, err
	}
	out := make([]RequestableRole, 0, len(rows))
	for _, r := range rows {
		out = append(out, RequestableRole{Role: Role{ID: r.ID, Name: r.Name, Description: r.Description}, Held: r.Held})
	}
	return out, nil
}

// Cancel withdraws requesterID's own pending request.
func (s *Service) Cancel(ctx context.Context, organizationID, requesterID, id uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).CancelAccessRequest(ctx, dbgen.CancelAccessRequestParams{ID: id, OrganizationID: organizationID, RequesterID: requesterID})
	if err != nil {
		return err
	}
	if n == 0 {
		// Someone else's request is as good as missing.
		row, gerr := s.q.WithTx(tx).GetAccessRequest(ctx, dbgen.GetAccessRequestParams{ID: id, OrganizationID: organizationID})
		if errors.Is(gerr, pgx.ErrNoRows) || (gerr == nil && row.RequesterID != requesterID) {
			return errs.ErrNotFound
		}
		if gerr != nil {
			return gerr
		}
		return ErrClosed
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "access_request.cancelled", "access_request", id, nil)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Approve gives the request's role to its requester, for its duration or for
// good, as approverID's decision with an optional note. The caller has checked
// that approverID may grant the role. Nobody approves their own request.
func (s *Service) Approve(ctx context.Context, organizationID, id, approverID uuid.UUID, note string, actor audit.Actor) (*AccessRequest, error) {
	note, err := cleanText(note, true, "note")
	if err != nil {
		return nil, err
	}
	limit, err := s.roles.SeatLimit(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)
	row, err := s.lockPending(ctx, qtx, organizationID, id)
	if err != nil {
		return nil, err
	}
	if row.RequesterID == approverID {
		return nil, ErrOwn
	}
	held, err := qtx.HoldsRole(ctx, dbgen.HoldsRoleParams{UserID: row.RequesterID, OrganizationID: organizationID, RoleID: row.RoleID})
	if err != nil {
		return nil, err
	}
	// The role, its seat and its audit row are given in this transaction, so
	// the grant and the answer commit together; the token-change signal goes
	// once they have.
	var signal func()
	if !held {
		if signal, err = s.roles.AssignRoleInTx(ctx, tx, limit, row.RequesterID, organizationID, row.RoleID, &approverID, actor); err != nil {
			return nil, err
		}
	}
	var ends *time.Time
	if row.DurationHours != nil && !held {
		ends = new(s.now().Add(time.Duration(*row.DurationHours) * time.Hour))
	}
	if err := qtx.ApproveAccessRequest(ctx, dbgen.ApproveAccessRequestParams{
		ID: id, OrganizationID: organizationID, DecidedBy: &approverID,
		DecisionNote: strutil.NilIfEmpty(note), Granted: !held, AccessEndsAt: ends,
	}); err != nil {
		return nil, err
	}
	meta := map[string]any{"role_id": row.RoleID, "requester_id": row.RequesterID, "already_held": held}
	if ends != nil {
		meta["access_ends_at"] = *ends
	}
	if note != "" {
		meta["note"] = note
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "access_request.approved", "access_request", id, meta)); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	if signal != nil {
		signal()
	}
	req, err := s.Get(ctx, organizationID, id)
	if err != nil {
		return nil, err
	}
	title := fmt.Sprintf("You have %s", req.Role.Name)
	if req.AccessEndsAt != nil {
		title += " until " + req.AccessEndsAt.UTC().Format("2 January 2006, 15:04 UTC")
	}
	s.notify(ctx, organizationID, req.Requester.ID, "success", title, note)
	return req, nil
}

// Deny refuses the request, with a note its requester sees.
func (s *Service) Deny(ctx context.Context, organizationID, id, approverID uuid.UUID, note string, actor audit.Actor) (*AccessRequest, error) {
	note, err := cleanText(note, true, "note")
	if err != nil {
		return nil, err
	}
	if note == "" {
		return nil, ErrNoteNeeded
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)
	row, err := s.lockPending(ctx, qtx, organizationID, id)
	if err != nil {
		return nil, err
	}
	if row.RequesterID == approverID {
		return nil, ErrOwn
	}
	if err := qtx.DenyAccessRequest(ctx, dbgen.DenyAccessRequestParams{
		ID: id, OrganizationID: organizationID, DecidedBy: &approverID, DecisionNote: &note,
	}); err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "access_request.denied", "access_request", id,
		map[string]any{"role_id": row.RoleID, "requester_id": row.RequesterID, "note": note})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	req, err := s.Get(ctx, organizationID, id)
	if err != nil {
		return nil, err
	}
	s.notify(ctx, organizationID, req.Requester.ID, "warning", fmt.Sprintf("Your request for %s was denied", req.Role.Name), note)
	return req, nil
}

// lockPending locks a pending, unexpired request of organizationID for an answer.
func (s *Service) lockPending(ctx context.Context, qtx *dbgen.Queries, organizationID, id uuid.UUID) (dbgen.LockPendingAccessRequestRow, error) {
	row, err := qtx.LockPendingAccessRequest(ctx, dbgen.LockPendingAccessRequestParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		if _, gerr := qtx.GetAccessRequest(ctx, dbgen.GetAccessRequestParams{ID: id, OrganizationID: organizationID}); errors.Is(gerr, pgx.ErrNoRows) {
			return row, errs.ErrNotFound
		}
		return row, ErrClosed
	}
	if err != nil {
		return row, err
	}
	if !s.now().Before(row.ExpiresAt) {
		return row, ErrClosed
	}
	return row, nil
}

// SweepResult counts what a Sweep did.
type SweepResult struct {
	Lapsed int
	Ended  int
	Failed int
}

// Sweep, run by the scheduler across every organization, lapses the requests
// nobody answered in time and takes back the time-limited roles whose time is
// up, telling each requester. A role is taken back only when its request gave
// it.
func (s *Service) Sweep(ctx context.Context) (SweepResult, error) {
	var res SweepResult
	lapsed, err := s.q.LapsePendingAccessRequests(ctx)
	if err != nil {
		return res, err
	}
	for _, l := range lapsed {
		res.Lapsed++
		s.recordSystem(ctx, l.OrganizationID, "access_request.expired", l.ID, map[string]any{"role_id": l.RoleID, "requester_id": l.RequesterID})
		s.notify(ctx, l.OrganizationID, l.RequesterID, "info", "Your access request expired without an answer", "")
	}
	ending, err := s.q.EndingAccess(ctx)
	if err != nil {
		return res, err
	}
	system := audit.Actor{Type: "system"}
	for _, e := range ending {
		if err := s.roles.UnassignRole(ctx, e.RequesterID, e.OrganizationID, e.RoleID, system); err != nil {
			res.Failed++
			slog.ErrorContext(ctx, "access request: taking back an ended role", "err", err, "request", e.ID)
			continue
		}
		if err := s.q.MarkAccessEnded(ctx, dbgen.MarkAccessEndedParams{ID: e.ID, OrganizationID: e.OrganizationID}); err != nil {
			res.Failed++
			slog.ErrorContext(ctx, "access request: marking ended", "err", err, "request", e.ID)
			continue
		}
		res.Ended++
		s.recordSystem(ctx, e.OrganizationID, "access_request.access_ended", e.ID, map[string]any{"role_id": e.RoleID, "requester_id": e.RequesterID})
		s.notify(ctx, e.OrganizationID, e.RequesterID, "info", "Your time-limited access has ended", "")
	}
	return res, nil
}

// recordSystem audits something the scheduler did, in its own transaction.
func (s *Service) recordSystem(ctx context.Context, organizationID uuid.UUID, action string, id uuid.UUID, meta map[string]any) {
	if err := audit.RecordAlone(ctx, s.pool, audit.Actor{Type: "system"}.Event(organizationID, action, "access_request", id, meta)); err != nil {
		slog.ErrorContext(ctx, "access request: audit", "err", err)
	}
}

func toRequest(r dbgen.GetAccessRequestRow) *AccessRequest {
	out := &AccessRequest{
		ID:           r.ID,
		Requester:    Person{ID: r.RequesterID, Email: r.RequesterEmail, Name: r.RequesterName},
		Role:         Role{ID: r.RoleID, Name: r.RoleName, Description: r.RoleDescription},
		Reason:       r.Reason,
		Status:       r.Status,
		CreatedAt:    r.CreatedAt,
		ExpiresAt:    r.ExpiresAt,
		DecidedAt:    r.DecidedAt,
		AccessEndsAt: r.AccessEndsAt,
		EndedAt:      r.EndedAt,
	}
	if r.DurationHours != nil {
		h := int(*r.DurationHours)
		out.DurationHours = &h
	}
	if r.DecidedBy != nil {
		out.DecidedBy = &Person{ID: *r.DecidedBy, Email: r.DeciderEmail, Name: r.DeciderName}
	}
	if r.DecisionNote != nil {
		out.DecisionNote = *r.DecisionNote
	}
	return out
}
