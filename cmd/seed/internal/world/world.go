// Package world holds what every seed step shares: the server's services and
// handlers, the organizations and people seeded so far, and the summary
// printed at the end.
package world

import (
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
	"github.com/qeetgroup/qeet-id-server/internal/platform/config"
)

// World is the seed's shared state.
type World struct {
	Ctx  context.Context
	Cfg  *config.Config
	Pool *pgxpool.Pool
	Deps bootstrap.Deps
	// API is the server's handlers, for changes the console makes.
	API  *API
	Rand *rand.Rand
	// Password is every seeded account's password; PasswordHash is its hash.
	Password, PasswordHash string

	Orgs    []*Org
	summary []summaryLine
}

// New wires the server's services against pool.
func New(ctx context.Context, cfg *config.Config, pool *pgxpool.Pool, password, hash string) *World {
	w := &World{
		Ctx: ctx, Cfg: cfg, Pool: pool, Deps: bootstrap.Services(ctx, cfg, pool),
		Rand: rand.New(rand.NewPCG(20261024, 1)), Password: password, PasswordHash: hash,
	}
	w.API = newAPI(w)
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

// Tx runs fn in a transaction on the server's pool, committed when fn
// succeeds, for the services that take one.
func (w *World) Tx(what string, fn func(tx pgx.Tx) error) {
	tx, err := w.Pool.Begin(w.Ctx)
	Must(err, "begin "+what)
	defer tx.Rollback(w.Ctx) // a no-op after Commit
	Must(fn(tx), what)
	Must(tx.Commit(w.Ctx), "commit "+what)
}

// Chance reports true with probability p.
func (w *World) Chance(p float64) bool { return w.Rand.Float64() < p }

// Pick returns a random element of s.
func Pick[T any](w *World, s []T) T { return s[w.Rand.IntN(len(s))] }

// Token is n random characters of alphabet, for vendor-shaped identifiers.
func (w *World) Token(alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[w.Rand.IntN(len(alphabet))]
	}
	return string(b)
}

// Alphabets for Token.
const (
	Alnum  = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Hex    = "0123456789abcdef"
	Digits = "0123456789"
)

// Org returns the seeded organization with slug, or nil.
func (w *World) Org(slug string) *Org {
	for _, o := range w.Orgs {
		if o.Spec.Slug == slug {
			return o
		}
	}
	return nil
}

// Person returns the seeded person with email in any organization, or nil.
func (w *World) Person(email string) *Person {
	for _, o := range w.Orgs {
		if p := o.Person(email); p != nil {
			return p
		}
	}
	return nil
}

// BaseURL is the API's origin as testers reach it.
func (w *World) BaseURL() string {
	if w.Cfg.PublicBaseURL != "" {
		return strings.TrimRight(w.Cfg.PublicBaseURL, "/")
	}
	return "http://localhost:" + w.Cfg.HTTPPort
}

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
