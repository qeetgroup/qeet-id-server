package scim

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// Operation is one change an organization's identity provider sent. Reason is
// the SCIM error type the answer gave (scim.uniqueness, say), "" for none.
type Operation struct {
	OrganizationID uuid.UUID
	Operation      string
	Resource       string
	ResourceID     string
	Status         int
	Reason         string
	Started        time.Time
	Duration       time.Duration
}

// OperationObserver records each provisioning operation.
type OperationObserver interface {
	RecordSCIMOperation(context.Context, Operation) error
}

type outcomeWriter struct {
	http.ResponseWriter
	status int
	reason string
}

// noteReason keeps the SCIM error type a response gives, for its operation's
// record.
func noteReason(w http.ResponseWriter, scimType string) {
	for w != nil {
		if o, ok := w.(*outcomeWriter); ok {
			o.reason = "scim." + scimType
			return
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return
		}
		w = u.Unwrap()
	}
}

func (writer *outcomeWriter) WriteHeader(status int) {
	if writer.status != 0 {
		return
	}
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *outcomeWriter) Write(body []byte) (int, error) {
	if writer.status == 0 {
		writer.WriteHeader(http.StatusOK)
	}
	return writer.ResponseWriter.Write(body)
}

func (writer *outcomeWriter) Unwrap() http.ResponseWriter { return writer.ResponseWriter }

func (handler *Handler) observeMutations(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		organizationID, authenticated := organizationFromCtx(request.Context())
		resource := ""
		if strings.HasPrefix(request.URL.Path, "/scim/v2/Users") {
			resource = "user"
		}
		if strings.HasPrefix(request.URL.Path, "/scim/v2/Groups") {
			resource = "group"
		}
		mutation := request.Method == http.MethodPost || request.Method == http.MethodPut || request.Method == http.MethodPatch || request.Method == http.MethodDelete
		if !authenticated || resource == "" || !mutation {
			next.ServeHTTP(response, request)
			return
		}
		started := time.Now()
		writer := &outcomeWriter{ResponseWriter: response}
		next.ServeHTTP(writer, request)
		status := writer.status
		if status == 0 {
			status = http.StatusOK
		}
		resourceID := ""
		if id, err := uuid.Parse(chi.URLParam(request, "id")); err == nil {
			resourceID = id.String()
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(request.Context()), 2*time.Second)
		defer cancel()
		if err := handler.Service.observer.RecordSCIMOperation(ctx, Operation{
			OrganizationID: organizationID, Operation: strings.ToLower(request.Method), Resource: resource, ResourceID: resourceID,
			Status: status, Reason: writer.reason, Started: started, Duration: time.Since(started),
		}); err != nil {
			slog.Warn("SCIM operation telemetry unavailable", "organization_id", organizationID, "err", err)
		}
	})
}
