package bootstrap

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
)

// startHTTPServer constructs the API HTTP server and serves it on a background
// goroutine. A fatal serve error (anything other than the expected
// ErrServerClosed raised during graceful shutdown) triggers stop() to unwind
// the process.
func startHTTPServer(cfg *config.Config, router http.Handler, stop func()) *http.Server {
	srv := newHTTPServer(cfg, router)
	go func() {
		slog.Info("listening", "addr", srv.Addr, "service", cfg.ServiceName, "env", cfg.ServiceEnv, "profile", cfg.ServiceProfile)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server error", "err", err)
			stop()
		}
	}()
	return srv
}

func newHTTPServer(cfg *config.Config, router http.Handler) *http.Server {
	return &http.Server{
		Addr:              ":" + cfg.HTTPPort,
		Handler:           router,
		ReadTimeout:       cfg.HTTPReadTimeout,
		ReadHeaderTimeout: cfg.HTTPReadHeaderTimeout,
		WriteTimeout:      cfg.HTTPWriteTimeout,
		IdleTimeout:       cfg.HTTPIdleTimeout,
		MaxHeaderBytes:    cfg.HTTPMaxHeaderBytes,
	}
}
