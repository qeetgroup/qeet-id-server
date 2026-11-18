//go:build integration

package ldap

import (
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestDirectoryConnectionLimits checks that a plan without directory sign-in
// can't add a connection.
func TestDirectoryConnectionLimits(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	svc := directoryService(t, func(d *Deps) { d.Gate = noLDAP{} })
	_, err := svc.Create(ctx, organization, CreateInput{Name: "Directory", ServerURL: "ldap://127.0.0.1:1", BindDN: "cn=service,dc=example,dc=test", BindPassword: "x", BaseDN: "dc=example,dc=test"}, audit.Actor{Type: "system"})
	if !strings.Contains(errorCode(err), errs.CodeUpgradeRequired) {
		t.Errorf("create on a plan without directory sign-in: %v, want an upgrade", err)
	}
}

// errorCode is err's code, or its text when it has none.
func errorCode(err error) string {
	if e := errs.As(err); e != nil {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return err.Error()
}
