package bootstrap

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/observability/health"
)

// TestShutdownBudgetFillsTheTimeout checks that the phases add up to the
// timeout, whatever the drain delay, and the split at the defaults.
func TestShutdownBudgetFillsTheTimeout(t *testing.T) {
	for _, tc := range []struct{ total, drainDelay time.Duration }{
		{20 * time.Second, 5 * time.Second},
		{20 * time.Second, 0},
		{20 * time.Second, 10 * time.Second},
		{5 * time.Second, 2500 * time.Millisecond},
		{2 * time.Minute, 30 * time.Second},
	} {
		b := newShutdownBudget(tc.total, tc.drainDelay)
		if b.total() != tc.total || b.httpDrain <= 0 || b.stop <= 0 || b.close <= 0 {
			t.Errorf("budget(%v, %v) = %+v, totalling %v", tc.total, tc.drainDelay, b, b.total())
		}
	}
	want := shutdownBudget{drainDelay: 5 * time.Second, httpDrain: 9 * time.Second, stop: 4 * time.Second, close: 2 * time.Second}
	if got := newShutdownBudget(20*time.Second, 5*time.Second); got != want {
		t.Errorf("default budget = %+v, want %+v", got, want)
	}
}

// stoppingServer serves /readyz, /stream (an event stream that ends when told
// to) and /stuck (a request that never finishes) on a loopback port.
type stoppingServer struct {
	url      string
	srv      *http.Server
	health   *health.Handler
	inFlight *httpx.InFlight
	end      chan struct{} // closed to end the streams
	release  chan struct{} // closed when the test ends, freeing what never stops
}

func newStoppingServer(t *testing.T) *stoppingServer {
	t.Helper()
	s := &stoppingServer{
		health:   health.New("qeet-id", "dev", time.Now()),
		inFlight: httpx.NewInFlight(),
		end:      make(chan struct{}),
		release:  make(chan struct{}),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", s.health.Readiness)
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-s.end:
			_, _ = io.WriteString(w, "retry: 3000\n\n")
		case <-r.Context().Done():
		}
	})
	mux.HandleFunc("/stuck", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.url = "http://" + ln.Addr().String()
	s.srv = &http.Server{Handler: s.inFlight.Middleware(mux), ReadHeaderTimeout: time.Second}
	go func() { _ = s.srv.Serve(ln) }()
	t.Cleanup(func() {
		close(s.release)
		_ = s.srv.Close()
	})
	return s
}

// open starts a GET of path and returns a channel that is closed once its body
// ends, by the server finishing it or cutting it.
func (s *stoppingServer) open(t *testing.T, path string) <-chan struct{} {
	t.Helper()
	resp, err := http.Get(s.url + path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	ended := make(chan struct{})
	go readToEnd(resp, ended)
	return ended
}

// readToEnd reads resp's body until it ends, closes it and then ended.
func readToEnd(resp *http.Response, ended chan<- struct{}) {
	defer close(ended)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
}

// shutdown returns the stop of s within budget, with workers and a database
// pool that never stop and a shutdown audit row it keeps.
func (s *stoppingServer) shutdown(budget shutdownBudget, recorded chan<- shutdownReport) shutdown {
	hang := func() { <-s.release }
	return shutdown{
		budget:     budget,
		server:     s.srv,
		notReady:   s.health.Drain,
		endStreams: []func(){func() { close(s.end) }},
		stop:       []func(){hang},
		flush:      func(context.Context) error { return nil },
		record:     func(_ context.Context, r shutdownReport) { recorded <- r },
		closePool:  hang,
		inFlight:   s.inFlight.Count,
	}
}

// TestShutdownEndsWithinItsBudget checks that a stop with an open event
// stream, a request that never finishes and workers and a pool that never stop
// still ends within its budget; that readiness answers 503 before the listener
// closes; and that the stream ends at once instead of holding up the drain.
func TestShutdownEndsWithinItsBudget(t *testing.T) {
	s := newStoppingServer(t)
	streamEnded := s.open(t, "/stream")
	stuckEnded := s.open(t, "/stuck")

	budget := newShutdownBudget(2*time.Second, 500*time.Millisecond)
	recorded := make(chan shutdownReport, 1)
	start := time.Now()
	done := make(chan shutdownReport, 1)
	go func() { done <- s.shutdown(budget, recorded).run() }()

	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	for {
		resp, err := client.Get(s.url + "/readyz")
		if err != nil {
			t.Fatalf("readiness never answered 503 before the listener closed: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusServiceUnavailable {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	select {
	case <-streamEnded:
		if since := time.Since(start); since >= budget.drainDelay {
			t.Errorf("the stream ended %v into the stop, after the drain delay", since)
		}
	case <-time.After(budget.drainDelay):
		t.Error("the stream did not end during the drain delay")
	}

	report := <-done
	elapsed := time.Since(start)
	if elapsed > budget.total()+500*time.Millisecond {
		t.Errorf("shutdown took %v, budget %v", elapsed, budget.total())
	}
	select {
	case <-stuckEnded:
	case <-time.After(time.Second):
		t.Error("the stuck request was not cut")
	}
	if report.inFlightAtSignal < 2 || report.dropped != 1 {
		t.Errorf("report = %+v, want the stream and the stuck request in flight at the signal and 1 dropped", report)
	}
	if r := <-recorded; r.dropped != 1 {
		t.Errorf("recorded %+v, want 1 dropped", r)
	}
}

// TestShutdownOfAnIdleServerTakesOnlyTheDrainDelay checks that the phases end
// as soon as their work is done rather than spending the whole budget.
func TestShutdownOfAnIdleServerTakesOnlyTheDrainDelay(t *testing.T) {
	s := newStoppingServer(t)
	streamEnded := s.open(t, "/stream")

	stop := s.shutdown(newShutdownBudget(20*time.Second, 200*time.Millisecond), make(chan shutdownReport, 1))
	stop.stop = []func(){func() {}}
	stop.closePool = func() {}
	start := time.Now()
	report := stop.run()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("an idle server took %v to stop", elapsed)
	}
	if report.dropped != 0 {
		t.Errorf("dropped %d requests, want none", report.dropped)
	}
	<-streamEnded
}
