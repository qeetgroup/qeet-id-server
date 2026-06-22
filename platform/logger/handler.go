// Package logger provides a coloured slog handler for local development.
// In non-dev environments callers should fall back to slog.NewJSONHandler.
package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Options struct {
	Level      slog.Leveler
	TimeFormat string
}

type JSONColorHandler struct {
	out    io.Writer
	mu     *sync.Mutex
	level  slog.Leveler
	tfmt   string
	attrs  []slog.Attr
	groups []string
}

func NewJSONColorHandler(w io.Writer, opts *Options) *JSONColorHandler {
	if opts == nil {
		opts = &Options{}
	}
	if opts.Level == nil {
		opts.Level = slog.LevelInfo
	}
	if opts.TimeFormat == "" {
		opts.TimeFormat = time.RFC3339
	}
	return &JSONColorHandler{
		out:   w,
		mu:    &sync.Mutex{},
		level: opts.Level,
		tfmt:  opts.TimeFormat,
	}
}

func (h *JSONColorHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level.Level()
}

func (h *JSONColorHandler) Handle(_ context.Context, r slog.Record) error {
	const (
		grey   = "\x1b[90m"
		blue   = "\x1b[34m"
		green  = "\x1b[32m"
		yellow = "\x1b[33m"
		red    = "\x1b[31m"
		bold   = "\x1b[1m"
		reset  = "\x1b[0m"
	)
	var lvlCol string
	switch r.Level {
	case slog.LevelDebug:
		lvlCol = grey
	case slog.LevelInfo:
		lvlCol = green
	case slog.LevelWarn:
		lvlCol = yellow
	case slog.LevelError:
		lvlCol = red
	default:
		lvlCol = blue
	}
	var sb strings.Builder
	sb.WriteString(grey)
	sb.WriteString(r.Time.Format(h.tfmt))
	sb.WriteString(reset + " ")
	sb.WriteString(lvlCol + bold + r.Level.String() + reset + " ")
	sb.WriteString(r.Message)
	for _, a := range h.attrs {
		writeAttr(&sb, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(&sb, a)
		return true
	})
	sb.WriteString("\n")
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.out, sb.String())
	return err
}

func writeAttr(sb *strings.Builder, a slog.Attr) {
	if a.Equal(slog.Attr{}) {
		return
	}
	sb.WriteString(" \x1b[36m")
	sb.WriteString(a.Key)
	sb.WriteString("\x1b[0m=")
	switch v := a.Value.Any().(type) {
	case string:
		sb.WriteString(strconv.Quote(v))
	case error:
		sb.WriteString(strconv.Quote(v.Error()))
	default:
		sb.WriteString(fmt.Sprintf("%v", v))
	}
}

func (h *JSONColorHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cp := *h
	cp.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &cp
}

func (h *JSONColorHandler) WithGroup(name string) slog.Handler {
	cp := *h
	cp.groups = append(append([]string{}, h.groups...), name)
	return &cp
}
