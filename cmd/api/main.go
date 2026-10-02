// Command api is the Qeet ID HTTP API server entrypoint; all wiring (the
// composition root) lives in internal/bootstrap.
//
// `qeet-id-server healthcheck` probes the running server's /readyz on loopback
// and exits 0 only on HTTP 200. The image is distroless (no shell, no curl), so
// this is what a container HEALTHCHECK runs.
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
)

func main() {
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
