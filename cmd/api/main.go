// Command api is the Qeet ID HTTP API server entrypoint.
//
// It holds no wiring of its own: the entire composition root — config, the
// pgx pool, dependency graph, chi router, background workers and graceful
// shutdown — lives in internal/bootstrap. This binary just invokes it.
package main

import "github.com/qeetgroup/qeet-id-server/internal/bootstrap"

func main() {
	bootstrap.Run()
}
