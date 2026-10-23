package ldap

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
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
	status := http.StatusOK
	if operationError != nil {
		status = http.StatusBadGateway
		if operation == "sign-in" {
			status = http.StatusUnauthorized
		}
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := service.observer.RecordOperation(ctx, tenantID, connectionID.String(), operation, resource, "", status, started, time.Since(started)); err != nil {
		slog.Warn("LDAP operation telemetry unavailable", "tenant_id", tenantID, "err", err)
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
