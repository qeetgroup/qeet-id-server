//go:build integration

// Package e2e runs whole journeys through the server as clients make them: signing up and in,
// renewing and signing out, organizations kept apart, and an application signing a person in with
// OpenID Connect. Every answer on the way is also checked against the API documents (apitest).
package e2e

import (
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }
