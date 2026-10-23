// Command worker runs the Qeet ID background workers without the API, so the
// two can scale apart: run the API with EMBEDDED_WORKERS=false beside it. It
// runs the same workers the API embeds.
package main

import "github.com/qeetgroup/qeet-id-server/internal/bootstrap"

func main() { bootstrap.RunWorkers() }
