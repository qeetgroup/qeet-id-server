package httpx_test

import (
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/platform/httpx"
)

func TestRequireTenant(t *testing.T) {
	tid := uuid.New()
	uid := uuid.New()
	cases := []struct {
		name    string
		p       *httpx.Principal
		want    uuid.UUID
		wantErr bool
	}{
		{"tenant present", &httpx.Principal{UserID: &uid, TenantID: &tid}, tid, false},
		{"tenant-less principal", &httpx.Principal{UserID: &uid}, uuid.Nil, true},
		{"no principal", nil, uuid.Nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if tc.p != nil {
				r = r.WithContext(httpx.WithPrincipal(r.Context(), tc.p))
			}
			got, err := httpx.RequireTenant(r)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got tenant %s", got)
			}
			if !tc.wantErr && (err != nil || got != tc.want) {
				t.Fatalf("got (%s, %v), want (%s, nil)", got, err, tc.want)
			}
		})
	}
}

func TestRequireUser(t *testing.T) {
	tid := uuid.New()
	uid := uuid.New()
	cases := []struct {
		name    string
		p       *httpx.Principal
		want    uuid.UUID
		wantErr bool
	}{
		{"user present", &httpx.Principal{UserID: &uid, TenantID: &tid}, uid, false},
		{"user-less principal", &httpx.Principal{TenantID: &tid}, uuid.Nil, true},
		{"no principal", nil, uuid.Nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if tc.p != nil {
				r = r.WithContext(httpx.WithPrincipal(r.Context(), tc.p))
			}
			got, err := httpx.RequireUser(r)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got user %s", got)
			}
			if !tc.wantErr && (err != nil || got != tc.want) {
				t.Fatalf("got (%s, %v), want (%s, nil)", got, err, tc.want)
			}
		})
	}
}
