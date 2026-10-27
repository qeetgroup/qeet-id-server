package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
)

// replayCommand is the argument that makes the scheduler replay dead letters
// instead of running the jobs.
const replayCommand = "replay-dead-letters"

// replayFilter reads replay-dead-letters' flags: -type, the event type to
// replay, and -since, an RFC 3339 time the events were dead-lettered at or
// after.
func replayFilter(args []string) (outbox.ReplayFilter, error) {
	fs := flag.NewFlagSet(replayCommand, flag.ContinueOnError)
	eventType := fs.String("type", "", "replay only events of this type")
	since := fs.String("since", "", "replay only events dead-lettered at or after this RFC 3339 time")
	if err := fs.Parse(args); err != nil {
		return outbox.ReplayFilter{}, err
	}
	if fs.NArg() > 0 {
		return outbox.ReplayFilter{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	f := outbox.ReplayFilter{EventType: *eventType}
	if *since != "" {
		t, err := time.Parse(time.RFC3339, *since)
		if err != nil {
			return outbox.ReplayFilter{}, fmt.Errorf("-since: %w", err)
		}
		f.Since = t
	}
	return f, nil
}

// replayDeadLetters moves the dead-lettered outbox events args pick back to
// the outbox, to be published again, and returns the exit code.
func replayDeadLetters(ctx context.Context, pool *pgxpool.Pool, args []string) int {
	f, err := replayFilter(args)
	if err != nil {
		slog.Error(replayCommand + ": " + err.Error())
		return 2
	}
	n, err := outbox.ReplayDeadLetters(ctx, pool, f)
	if err != nil {
		slog.Error("replay dead-lettered outbox events", "replayed", n, "err", err)
		return 1
	}
	slog.Info("dead-lettered outbox events replayed", "replayed", n, "event_type", f.EventType, "since", f.Since)
	return 0
}
