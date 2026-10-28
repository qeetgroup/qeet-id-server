package ldap

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// OperationObserver records each directory operation.
type OperationObserver interface {
	RecordOperation(context.Context, uuid.UUID, string, string, string, string, int, time.Time, time.Duration) error
}

// SetOperationObserver sets where directory operations are recorded.
func (service *Service) SetOperationObserver(observer OperationObserver) { service.observer = observer }

func (service *Service) recordOperation(ctx context.Context, tenantID, connectionID uuid.UUID, operation, resource string, started time.Time, operationError error) {
	if service.observer == nil {
		return
	}
	status := operationStatus(operation, operationError)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := service.observer.RecordOperation(ctx, tenantID, connectionID.String(), operation, resource, "", status, started, time.Since(started)); err != nil {
		slog.Warn("LDAP operation telemetry unavailable", "tenant_id", tenantID, "err", err)
	}
}

// operationStatus is how an operation's outcome is recorded: a person's own
// credentials refused (401) apart from the service account refused (403), the
// directory unreachable (502), and a sign-in this organisation refuses (422).
func operationStatus(operation string, err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, errs.ErrLDAPInvalidCredentials), errors.Is(err, errs.ErrLDAPCredentialsRequired):
		return http.StatusUnauthorized
	case errors.Is(err, errs.ErrLDAPServiceBindFailed):
		return http.StatusForbidden
	case operation == "sign-in" && !errors.Is(err, errs.ErrLDAPDialFailed) && !errors.Is(err, errs.ErrLDAPDirectoryUnreachable):
		return http.StatusUnprocessableEntity
	default:
		return http.StatusBadGateway
	}
}

// TestConnection binds to one of the tenant's LDAP connections and reports
// the error, if any.
func (service *Service) TestConnection(ctx context.Context, tenantID, connectionID uuid.UUID) (resultError error) {
	connection, err := service.getFull(ctx, connectionID, tenantID)
	if err != nil {
		return err
	}
	started := time.Now()
	defer func() {
		service.recordOperation(ctx, tenantID, connectionID, "test", "connection", started, resultError)
	}()
	return service.TestBind(ctx, connection)
}
