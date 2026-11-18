package scim

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestUnsupportedFiltersReturnSCIMInvalidFilter(t *testing.T) {
	handler := &Handler{}
	for _, test := range []struct {
		name string
		path string
		call func(http.ResponseWriter, *http.Request)
	}{
		{name: "users", path: `/scim/v2/Users?filter=emails.value+eq+%22x%40example.com%22`, call: handler.listUsers},
		{name: "groups", path: `/scim/v2/Groups?filter=displayName+co+%22Eng%22`, call: handler.listGroups},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			request = request.WithContext(context.WithValue(request.Context(), organizationCtxKey, uuid.New()))
			recorder := httptest.NewRecorder()
			test.call(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode SCIM error: %v", err)
			}
			if body["scimType"] != "invalidFilter" {
				t.Fatalf("scimType = %v, want invalidFilter", body["scimType"])
			}
		})
	}
}
