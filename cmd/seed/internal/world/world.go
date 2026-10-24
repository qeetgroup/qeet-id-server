// Package world holds what every seed step shares: the API's own services,
// the organisations and people seeded so far, the story clock that places each
// step at its date, and the summary printed at the end.
package world

import (
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
)

// World is the seed's shared state.
type World struct {
	Ctx  context.Context
	Cfg  *config.Config
	Pool *pgxpool.Pool // the API's pool, as qeet_app
	// Admin connects as the configured database user, for history the API only
	// ever writes as it happens (sessions, deliveries, hash-chained audit rows).
	Admin *pgxpool.Pool
	Deps  bootstrap.Deps
	// Now is the story's present; every date in the seed is relative to it.
	Now  time.Time
	Rand *rand.Rand
	// Password is every seeded account's password; PasswordHash is its hash.
	Password     string
	PasswordHash string

	Orgs []*Org

	tables  []shiftTable
	summary []summaryLine
	drift   time.Duration
}

// New wires the API's services against pool and admin.
func New(ctx context.Context, cfg *config.Config, pool, admin *pgxpool.Pool, password, hash string) *World {
	w := &World{
		Ctx:          ctx,
		Cfg:          cfg,
		Pool:         pool,
		Admin:        admin,
		Deps:         bootstrap.Services(ctx, cfg, pool),
		Now:          time.Now().UTC().Truncate(time.Second),
		Rand:         rand.New(rand.NewPCG(20261024, 1)),
		Password:     password,
		PasswordHash: hash,
	}
	w.loadShiftTables()
	return w
}

// Must stops the seed when err is set, naming the step.
func Must(err error, what string) {
	if err != nil {
		log.Fatalf("seed: %s: %v", what, err)
	}
}

// Check is Must for a step of w.
func (w *World) Check(err error, what string) { Must(err, what) }

// Tx runs fn in a transaction on the API's pool, committed when fn succeeds.
func (w *World) Tx(what string, fn func(tx pgx.Tx) error) {
	tx, err := w.Pool.Begin(w.Ctx)
	Must(err, "begin "+what)
	defer tx.Rollback(w.Ctx) // a no-op after Commit
	Must(fn(tx), what)
	Must(tx.Commit(w.Ctx), "commit "+what)
}

// Exec runs one statement as the database user (Admin), for rows written
// directly.
func (w *World) Exec(what, sql string, args ...any) {
	_, err := w.Admin.Exec(w.Ctx, sql, args...)
	Must(err, what)
}

// Days returns the time n days before Now; a negative n is in the future.
func (w *World) Days(n float64) time.Time {
	return w.Now.Add(-time.Duration(n * float64(24*time.Hour)))
}

// Between returns a random time in [from, to).
func (w *World) Between(from, to time.Time) time.Time {
	if !to.After(from) {
		return from
	}
	return from.Add(time.Duration(w.Rand.Int64N(int64(to.Sub(from)))))
}

// WorkHours moves t to a plausible working time on the same local day in loc:
// 08:30–19:30, weighted to the morning and after lunch.
func (w *World) WorkHours(t time.Time, loc *time.Location) time.Time {
	l := t.In(loc)
	minute := 8*60 + 30 + w.Rand.IntN(11*60)
	return time.Date(l.Year(), l.Month(), l.Day(), minute/60, minute%60, w.Rand.IntN(60), 0, loc).UTC()
}

// Chance reports true with probability p.
func (w *World) Chance(p float64) bool { return w.Rand.Float64() < p }

// Pick returns a random element of s.
func Pick[T any](w *World, s []T) T { return s[w.Rand.IntN(len(s))] }

// summaryLine is one line of the closing summary, under section.
type summaryLine struct{ section, text string }

// Note adds a line to the closing summary, under section. Sections print in
// the order they were first used.
func (w *World) Note(section, format string, args ...any) {
	w.summary = append(w.summary, summaryLine{section, fmt.Sprintf(format, args...)})
}

// PrintSummary prints the notes, grouped by section.
func (w *World) PrintSummary() {
	var order []string
	seen := map[string]bool{}
	for _, l := range w.summary {
		if !seen[l.section] {
			seen[l.section] = true
			order = append(order, l.section)
		}
	}
	for _, s := range order {
		fmt.Printf("\n%s\n%s\n", s, strings.Repeat("─", len([]rune(s))))
		for _, l := range w.summary {
			if l.section == s {
				fmt.Println("  " + l.text)
			}
		}
	}
}
