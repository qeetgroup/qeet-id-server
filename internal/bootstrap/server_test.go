package bootstrap

import (
	"net/http"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
)

func TestNewHTTPServerAppliesConnectionBounds(t *testing.T) {
	cfg := &config.Config{
		HTTPPort: "4001", HTTPReadTimeout: 15 * time.Second,
		HTTPReadHeaderTimeout: 5 * time.Second, HTTPWriteTimeout: 30 * time.Second,
		HTTPIdleTimeout: 60 * time.Second, HTTPMaxHeaderBytes: 65536,
	}
	server := newHTTPServer(cfg, http.NotFoundHandler())
	if server.ReadHeaderTimeout != cfg.HTTPReadHeaderTimeout || server.IdleTimeout != cfg.HTTPIdleTimeout {
		t.Fatalf("server timeouts: read_header=%v idle=%v", server.ReadHeaderTimeout, server.IdleTimeout)
	}
	if server.MaxHeaderBytes != cfg.HTTPMaxHeaderBytes {
		t.Fatalf("max header bytes = %d, want %d", server.MaxHeaderBytes, cfg.HTTPMaxHeaderBytes)
	}
}
