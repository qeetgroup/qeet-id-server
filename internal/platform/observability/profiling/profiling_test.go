package profiling

import (
	"net/http"
	"testing"
)

// TestServe checks that an empty address serves nothing and that a set one serves the profile index
// and a runtime profile, on its own listener.
func TestServe(t *testing.T) {
	if addr, err := Serve(""); err != nil || addr != "" {
		t.Fatalf("Serve(\"\") = %q, %v; want nothing served", addr, err)
	}
	addr, err := Serve("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/debug/pprof/", "/debug/pprof/goroutine?debug=1"} {
		res, err := http.Get("http://" + addr + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, res.StatusCode)
		}
	}
}
