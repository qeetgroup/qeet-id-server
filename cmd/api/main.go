// Command api is the Qeet ID HTTP API server entrypoint; all wiring (the
// composition root) lives in internal/bootstrap.
//
// `qeet-id-server healthcheck` probes the running server's /readyz on loopback
// and exits 0 only on HTTP 200. The image is distroless (no shell, no curl), so
// this is what a container HEALTHCHECK runs.
//
// `qeet-id-server schema-check` reads DB_URL's migration and exits 0 only if
// this build can run on it: 1 when a later release has migrated the database
// past this build (or a migration is half-applied), with the recovery step;
// 2 when it can't tell. It changes nothing. The host runs it with the image it
// is about to switch to, before stopping anything (redeploy.sh).
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/migrations"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "schema-check" {
		os.Exit(schemaCheck(os.Getenv("DB_URL")))
	}
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		port := os.Getenv("HTTP_PORT")
		if port == "" {
			port = "4001"
		}
		client := &http.Client{
			Timeout:       3 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		if err := probe("http://127.0.0.1:"+port+"/readyz", client); err != nil {
			fmt.Fprintln(os.Stderr, "healthcheck:", err)
			os.Exit(1)
		}
		return
	}
	bootstrap.Run()
}

// probe succeeds only when url answers HTTP 200.
func probe(url string, client *http.Client) error {
	resp, err := client.Get(url) //nolint:noctx // bounded by the client timeout
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %d", url, resp.StatusCode)
	}
	return nil
}

// schemaCheck prints the schema state as one JSON line and returns the exit
// code (see the package comment).
func schemaCheck(dbURL string) int {
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "schema-check: DB_URL is not set")
		return 2
	}
	st, err := migrations.CheckCompatible(dbURL)
	var schemaErr *migrations.SchemaError
	if err != nil && !errors.As(err, &schemaErr) {
		fmt.Fprintln(os.Stderr, "schema-check:", err)
		return 2
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"migration": st.Database, "dirty": st.Dirty, "latest": st.Latest, "compatible": err == nil})
	if err != nil {
		fmt.Fprintln(os.Stderr, "schema-check:", err)
		return 1
	}
	return 0
}
