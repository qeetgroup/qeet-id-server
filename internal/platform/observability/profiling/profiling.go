// Package profiling serves Go's runtime profiles (net/http/pprof) on a listener of its own, never on
// the API's router, for a continuous profiler such as Grafana Alloy feeding Pyroscope to scrape.
// Config keeps it on a loopback address outside development, as profiles expose the process.
package profiling

import (
	"net"
	"net/http"
	"net/http/pprof" // #nosec G108 -- registered on this package's own mux and listener, never DefaultServeMux
	"time"
)

// Handler serves the profiles under /debug/pprof/: the index, cmdline, profile (CPU), symbol and
// trace, and through the index every runtime profile (heap, allocs, goroutine, block, mutex).
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

// Serve starts serving Handler on addr in the background and returns the address it listens on;
// an empty addr serves nothing. The listener ends with the process.
func Serve(addr string) (string, error) {
	if addr == "" {
		return "", nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	// A CPU profile streams for its seconds parameter (30 by default), so writes get a minute.
	srv := &http.Server{Handler: Handler(), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: time.Minute}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), nil
}
