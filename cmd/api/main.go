// Command api is the Qeet ID HTTP API server entrypoint; all wiring (the
// composition root) lives in internal/bootstrap.
package main

import "github.com/qeetgroup/qeet-id-server/internal/bootstrap"

func main() {
	bootstrap.Run()
}
