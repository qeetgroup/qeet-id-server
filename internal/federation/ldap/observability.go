package ldap

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Operation is one directory operation of a connection: a test or a sign-in.
// Reason is its failure's error code and Params the safe details of the
// directory it used; Subject is the login name a sign-in tried and UserID the
// person it was for, once known.
type Operation struct {
	OrganizationID uuid.UUID
	ConnectionID   uuid.UUID
	Operation      string
	Resource       string
	Status         int
	Started        time.Time
	Duration       time.Duration
	Reason         string
	Params         map[string]string
	Subject        string
	UserID         *uuid.UUID
}

// OperationObserver records each directory operation.
type OperationObserver interface {
	RecordLDAPOperation(context.Context, Operation) error
}

// SetOperationObserver sets where directory operations are recorded.
func (service *Service) SetOperationObserver(observer OperationObserver) { service.observer = observer }

// recordOperation records c's operation that began at started and ended in
// operationError, for subject and the person userID when a sign-in names them.
func (service *Service) recordOperation(ctx context.Context, c *connFull, operation, resource string, started time.Time, operationError error, subject string, userID *uuid.UUID) {
	if service.observer == nil {
		return
	}
	op := Operation{
		OrganizationID: c.OrganizationID, ConnectionID: c.ID, Operation: operation, Resource: resource,
		Status: operationStatus(operation, operationError), Started: started, Duration: time.Since(started),
		Subject: subject, UserID: userID,
	}
	if e := errs.As(operationError); e != nil && e.Code != errs.CodeInternal {
		op.Reason = string(e.Code)
	}
	if u, err := url.Parse(c.ServerURL); err == nil && u.Host != "" {
		op.Params = map[string]string{"host": u.Host}
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := service.observer.RecordLDAPOperation(ctx, op); err != nil {
		slog.Warn("LDAP operation telemetry unavailable", "organization_id", c.OrganizationID, "err", err)
	}
}

// operationStatus is how an operation's outcome is recorded: a person's own
// credentials refused (401) apart from the service account refused (403), the
// directory unreachable (502), and a sign-in this organization refuses (422).
func operationStatus(operation string, err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrInvalidCredentials), errors.Is(err, ErrCredentialsRequired):
		return http.StatusUnauthorized
	case errors.Is(err, ErrServiceBindFailed):
		return http.StatusForbidden
	case operation == "sign-in" && !errors.Is(err, ErrDialFailed) && !errors.Is(err, ErrDirectoryUnreachable):
		return http.StatusUnprocessableEntity
	default:
		return http.StatusBadGateway
	}
}

// TestConnection binds to one of the organization's LDAP connections and reports
// the error, if any.
func (service *Service) TestConnection(ctx context.Context, organizationID, connectionID uuid.UUID) (resultError error) {
	connection, err := service.getFull(ctx, connectionID, organizationID)
	if err != nil {
		return err
	}
	started := time.Now()
	defer func() {
		service.recordOperation(ctx, connection, "test", "connection", started, resultError, "", nil)
	}()
	return service.TestBind(ctx, connection)
}
