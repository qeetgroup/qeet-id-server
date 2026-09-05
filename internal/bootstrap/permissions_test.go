package bootstrap

import (
	"context"
	"net/http"
	"reflect"
	"sort"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type allowRouteInventoryChecker struct{}

func (allowRouteInventoryChecker) Check(context.Context, uuid.UUID, uuid.UUID, string) (bool, error) {
	return true, nil
}

func routeInventoryDeps(t *testing.T) Deps {
	t.Helper()
	var deps Deps
	value := reflect.ValueOf(&deps).Elem()
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if field.CanSet() && field.Kind() == reflect.Pointer && field.IsNil() {
			field.Set(reflect.New(field.Type().Elem()))
		}
	}
	deps.RBACChecker = allowRouteInventoryChecker{}

	// These handlers conditionally mount route families when an optional
	// collaborator is present. Populate those exported pointers so the inventory
	// includes the same feature-complete surface as production.
	for _, pair := range [][2]string{{"SAML", "IdP"}, {"GDPR", "Evidence"}} {
		outer := value.FieldByName(pair[0])
		if !outer.IsValid() || outer.IsNil() {
			t.Fatalf("missing handler field %s", pair[0])
		}
		inner := outer.Elem().FieldByName(pair[1])
		if !inner.IsValid() || !inner.CanSet() || inner.Kind() != reflect.Pointer {
			t.Fatalf("missing optional dependency %s.%s", pair[0], pair[1])
		}
		inner.Set(reflect.New(inner.Type().Elem()))
	}
	return deps
}

func TestAuthenticatedRoutesHaveExplicitPolicies(t *testing.T) {
	router := chi.NewRouter()
	router.Route("/v1", func(r chi.Router) {
		mountAuthenticatedRoutes(r, routeInventoryDeps(t))
	})

	mounted := map[string]struct{}{}
	if err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		mounted[method+" "+route] = struct{}{}
		return nil
	}); err != nil {
		t.Fatalf("walk authenticated router: %v", err)
	}

	policies := routePolicyMap()
	var missing, stale []string
	for route := range mounted {
		if _, ok := policies[route]; !ok {
			missing = append(missing, route)
		}
	}
	for route := range policies {
		if _, ok := mounted[route]; !ok {
			stale = append(stale, route)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 || len(stale) > 0 {
		t.Fatalf("route policy mismatch\nmissing policies: %v\nstale policies: %v", missing, stale)
	}
}
