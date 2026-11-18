package gdpr

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

type anyPassword struct{}

func (anyPassword) ReauthPassword(context.Context, uuid.UUID, string) (bool, bool, error) {
	return true, true, nil
}

// TestConstructorsNeedTheirChecks checks that the service is not built
// without the signals that announce the sessions an erasure ends, nor the
// handler without the password check before an account is deleted or the
// check that nobody erases someone who outranks them.
func TestConstructorsNeedTheirChecks(t *testing.T) {
	if _, err := NewService(new(pgxpool.Pool), 0, nil); err == nil {
		t.Error("service built without session signals")
	}
	signals := sessionsignal.New(func(context.Context, pgx.Tx, uuid.UUID, string, any) error { return nil })
	svc, err := NewService(new(pgxpool.Pool), 0, signals)
	if err != nil {
		t.Fatal(err)
	}
	actOn := func(context.Context, *httpx.Principal, uuid.UUID, uuid.UUID) error { return nil }
	if _, err := NewHandler(svc, nil, actOn); err == nil {
		t.Error("handler built without a password check")
	}
	if _, err := NewHandler(svc, anyPassword{}, nil); err == nil {
		t.Error("handler built without an act-on check")
	}
	if _, err := NewHandler(svc, anyPassword{}, actOn); err != nil {
		t.Errorf("handler built with both: %v", err)
	}
}
