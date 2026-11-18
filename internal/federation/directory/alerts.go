package directory

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/directory/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Alert is a threshold on a connection's failures.
type Alert struct {
	ID           uuid.UUID `json:"id"`
	Name         string    `json:"name"`
	ConnectionID *string   `json:"connection_id"`
	Threshold    int       `json:"threshold"`
	Enabled      bool      `json:"enabled"`

	// Read-only: who the alert notifies, and when it was made and last sent.
	UserID         uuid.UUID  `json:"user_id"`
	CreatedAt      time.Time  `json:"created_at"`
	LastNotifiedAt *time.Time `json:"last_notified_at"`
}

// alertUpdate is a PATCH of an alert: each field given is changed. Enabled
// false pauses it; a connection_id of "" makes it cover every connection.
type alertUpdate struct {
	Name         *string `json:"name"`
	ConnectionID *string `json:"connection_id"`
	Threshold    *int    `json:"threshold"`
	Enabled      *bool   `json:"enabled"`
}

// toAlert is an alert as its queries return it.
func toAlert(r dbgen.ListDirectoryAlertsRow) Alert {
	return Alert{
		ID: r.ID, Name: r.Name, ConnectionID: r.ConnectionID, Threshold: int(r.Threshold), Enabled: r.Enabled,
		UserID: r.UserID, CreatedAt: r.CreatedAt, LastNotifiedAt: r.LastNotifiedAt,
	}
}

// Alerts returns every alert of the organization, newest first.
func (service *Service) Alerts(ctx context.Context, organizationID uuid.UUID) ([]Alert, error) {
	rows, err := service.q.ListDirectoryAlerts(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	items := make([]Alert, len(rows))
	for i, r := range rows {
		items[i] = toAlert(r)
	}
	return items, nil
}

// CreateAlert adds an alert notifying userID, recorded as actor's.
func (service *Service) CreateAlert(ctx context.Context, organizationID, userID uuid.UUID, alert Alert, actor audit.Actor) (Alert, error) {
	tx, err := service.pool.Begin(ctx)
	if err != nil {
		return Alert{}, err
	}
	defer tx.Rollback(ctx)
	row, err := service.q.WithTx(tx).InsertDirectoryAlert(ctx, dbgen.InsertDirectoryAlertParams{
		ID: uuid.New(), OrganizationID: organizationID, UserID: userID, Name: alert.Name,
		ConnectionID: alert.ConnectionID, Threshold: int32(alert.Threshold), // #nosec G115 -- the handler checked 1..100
	})
	if err != nil {
		return Alert{}, err
	}
	created := toAlert(dbgen.ListDirectoryAlertsRow(row))
	if err := recordAlertAudit(ctx, tx, actor, organizationID, created.ID, "directory.alert_created", map[string]any{
		"name": created.Name, "connection_id": created.ConnectionID, "threshold": created.Threshold,
	}); err != nil {
		return Alert{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Alert{}, err
	}
	return created, nil
}

// UpdateAlert changes the fields in gives of the organization's alert, recorded
// as actor's.
func (service *Service) UpdateAlert(ctx context.Context, organizationID, alertID uuid.UUID, in alertUpdate, actor audit.Actor) (Alert, error) {
	tx, err := service.pool.Begin(ctx)
	if err != nil {
		return Alert{}, err
	}
	defer tx.Rollback(ctx)
	var threshold *int32
	if in.Threshold != nil {
		threshold = new(int32(*in.Threshold)) // #nosec G115 -- the handler checked 1..100
	}
	row, err := service.q.WithTx(tx).UpdateDirectoryAlert(ctx, dbgen.UpdateDirectoryAlertParams{
		OrganizationID: organizationID, ID: alertID, Name: in.Name, SetConnectionID: in.ConnectionID != nil,
		ConnectionID: in.ConnectionID, Threshold: threshold, Enabled: in.Enabled,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Alert{}, errs.ErrNotFound
	}
	if err != nil {
		return Alert{}, err
	}
	alert := toAlert(dbgen.ListDirectoryAlertsRow(row))
	if err := recordAlertAudit(ctx, tx, actor, organizationID, alertID, "directory.alert_updated", map[string]any{
		"name": alert.Name, "connection_id": alert.ConnectionID, "threshold": alert.Threshold, "enabled": alert.Enabled,
	}); err != nil {
		return Alert{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Alert{}, err
	}
	return alert, nil
}

// DeleteAlert removes the organization's alert, recorded as actor's.
func (service *Service) DeleteAlert(ctx context.Context, organizationID, alertID uuid.UUID, actor audit.Actor) error {
	tx, err := service.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := service.q.WithTx(tx).DeleteDirectoryAlert(ctx, dbgen.DeleteDirectoryAlertParams{OrganizationID: organizationID, ID: alertID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	if err := recordAlertAudit(ctx, tx, actor, organizationID, alertID, "directory.alert_deleted", nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// knownConnection reports whether id is one of the organization's connections.
func (handler *Handler) knownConnection(ctx context.Context, organizationID uuid.UUID, id string) (bool, error) {
	connections, err := handler.Service.List(ctx, organizationID)
	if err != nil {
		return false, err
	}
	for _, connection := range connections {
		if connection.ID == id {
			return true, nil
		}
	}
	return false, nil
}

// recordAlertAudit records actor's alert change in the organization's audit log, on tx.
func recordAlertAudit(ctx context.Context, tx pgx.Tx, actor audit.Actor, organizationID, alertID uuid.UUID, action string, meta map[string]any) error {
	return audit.Record(ctx, tx, actor.Event(organizationID, action, "directory_alert", alertID, meta))
}

// listAlerts serves GET /organizations/{organizationID}/directory/alerts: every alert of
// the organization, newest first, with who it notifies.
func (handler *Handler) listAlerts(response http.ResponseWriter, request *http.Request) {
	organizationID, err := requireOrganization(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	items, err := handler.Service.Alerts(request.Context(), organizationID)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusOK, paging.List(items))
}

// updateAlert serves PATCH /organizations/{organizationID}/directory/alerts/{alertID}.
func (handler *Handler) updateAlert(response http.ResponseWriter, request *http.Request) {
	organizationID, err := requireOrganization(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	alertID, err := httpx.PathUUID(request, "alertID", errs.ErrBadRequest)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	var in alertUpdate
	if err := httpx.DecodeJSON(request, &in); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if in.Name != nil {
		trimmed := strings.TrimSpace(*in.Name)
		in.Name = &trimmed
	}
	if (in.Name != nil && (len(*in.Name) == 0 || len(*in.Name) > 100)) || (in.Threshold != nil && (*in.Threshold < 1 || *in.Threshold > 100)) {
		httpx.WriteError(response, request, errs.ErrBadRequest)
		return
	}
	ctx := request.Context()
	if in.ConnectionID != nil && *in.ConnectionID != "" {
		known, err := handler.knownConnection(ctx, organizationID, *in.ConnectionID)
		if err != nil {
			httpx.WriteError(response, request, err)
			return
		}
		if !known {
			httpx.WriteError(response, request, errs.ErrNotFound)
			return
		}
	}
	alert, err := handler.Service.UpdateAlert(ctx, organizationID, alertID, in, audit.ActorOf(request))
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusOK, alert)
}

// deleteAlert serves DELETE /organizations/{organizationID}/directory/alerts/{alertID}.
func (handler *Handler) deleteAlert(response http.ResponseWriter, request *http.Request) {
	organizationID, err := requireOrganization(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	alertID, err := httpx.PathUUID(request, "alertID", errs.ErrBadRequest)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	if err := handler.Service.DeleteAlert(request.Context(), organizationID, alertID, audit.ActorOf(request)); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (handler *Handler) createAlert(response http.ResponseWriter, request *http.Request) {
	organizationID, err := requireOrganization(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	userID, err := httpx.RequireUser(request)
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	var alert Alert
	if err := httpx.DecodeJSON(request, &alert); err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	alert.Name = strings.TrimSpace(alert.Name)
	if len(alert.Name) == 0 || len(alert.Name) > 100 || alert.Threshold < 1 || alert.Threshold > 100 {
		httpx.WriteError(response, request, errs.ErrBadRequest)
		return
	}
	ctx := request.Context()
	if alert.ConnectionID != nil {
		known, err := handler.knownConnection(ctx, organizationID, *alert.ConnectionID)
		if err != nil {
			httpx.WriteError(response, request, err)
			return
		}
		if !known {
			httpx.WriteError(response, request, errs.ErrNotFound)
			return
		}
	}
	created, err := handler.Service.CreateAlert(ctx, organizationID, userID, alert, audit.ActorOf(request))
	if err != nil {
		httpx.WriteError(response, request, err)
		return
	}
	httpx.WriteJSON(response, http.StatusCreated, created)
}

func (service *Service) notifyAlerts(ctx context.Context, organizationID uuid.UUID, connectionID string) error {
	return service.q.NotifyDirectoryAlerts(ctx, dbgen.NotifyDirectoryAlertsParams{
		OrganizationID: &organizationID, ConnectionID: connectionID,
		Description: "Directory failures reached your alert threshold in the last 15 minutes.",
	})
}
