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

// OperationObserver records each provisioning operation.
type OperationObserver interface {
	RecordOperation(context.Context, uuid.UUID, string, string, string, string, int, time.Time, time.Duration) error
}

// SetOperationObserver sets where provisioning operations are recorded.
func (service *Service) SetOperationObserver(observer OperationObserver) {
	service.observer = observer
}

type outcomeWriter struct {
	http.ResponseWriter
	status int
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
		tenantID, authenticated := tenantFromCtx(request.Context())
		resource := ""
		if strings.HasPrefix(request.URL.Path, "/scim/v2/Users") {
			resource = "user"
		}
		if strings.HasPrefix(request.URL.Path, "/scim/v2/Groups") {
			resource = "group"
		}
		mutation := request.Method == http.MethodPost || request.Method == http.MethodPut || request.Method == http.MethodPatch || request.Method == http.MethodDelete
		if !authenticated || resource == "" || !mutation || handler.Service.observer == nil {
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
		if err := handler.Service.observer.RecordOperation(ctx, tenantID, "scim:"+tenantID.String(), strings.ToLower(request.Method), resource, resourceID, status, started, time.Since(started)); err != nil {
			slog.Warn("SCIM operation telemetry unavailable", "tenant_id", tenantID, "err", err)
		}
	})
}
