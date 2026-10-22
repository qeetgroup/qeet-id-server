// Command api runs the Qeet ID HTTP API server. With "healthcheck" it exits 0
// only if /readyz on loopback answers 200 (the distroless image has no curl).
// With "schema-check" it exits 0 if this build can run on DB_URL's schema, 1 if
// not (newer or half-applied migrations), or 2 if it can't tell.
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
