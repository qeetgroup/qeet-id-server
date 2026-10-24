package world

import (
	"fmt"
	"strings"
	"time"
)

// The API stamps what it writes with the current time. At lets the seed tell
// a story over months anyway: it runs a step, then moves every timestamp the
// step wrote back to the step's date, keeping their order and spacing.

// shiftTable is a table whose timestamp columns At moves.
type shiftTable struct {
	name    string // schema-qualified and quoted
	columns []string
}

// unshifted are tables whose times describe the machine, not the story.
var unshifted = map[string]bool{
	"public.schema_migrations":     true,
	"platform.jwt_signing_keys":    true,
	"platform.scheduled_job_runs":  true,
	"platform.idempotency_keys":    true,
	"platform.billing_plans":       true,
	"platform.billing_plan_prices": true,
	"rbac.permissions":             true,
}

// loadShiftTables finds every writable timestamptz column, and how far the
// database clock is from this process's.
func (w *World) loadShiftTables() {
	rows, err := w.Admin.Query(w.Ctx, `
		SELECT c.table_schema, c.table_name, array_agg(c.column_name::text ORDER BY c.ordinal_position)
		FROM information_schema.columns c
		JOIN information_schema.tables t
		  ON t.table_schema = c.table_schema AND t.table_name = c.table_name AND t.table_type = 'BASE TABLE'
		WHERE c.data_type = 'timestamp with time zone' AND c.is_generated = 'NEVER'
		  AND c.table_schema NOT IN ('pg_catalog', 'information_schema')
		GROUP BY c.table_schema, c.table_name
		ORDER BY 1, 2`)
	Must(err, "list timestamp columns")
	defer rows.Close()
	for rows.Next() {
		var schema, table string
		var cols []string
		Must(rows.Scan(&schema, &table, &cols), "scan timestamp columns")
		if unshifted[schema+"."+table] {
			continue
		}
		quoted := make([]string, len(cols))
		for i, c := range cols {
			quoted[i] = `"` + c + `"`
		}
		w.tables = append(w.tables, shiftTable{name: fmt.Sprintf(`"%s"."%s"`, schema, table), columns: quoted})
	}
	Must(rows.Err(), "list timestamp columns")

	var db time.Time
	Must(w.Admin.QueryRow(w.Ctx, `SELECT clock_timestamp()`).Scan(&db), "read database clock")
	w.drift = time.Since(db)
	if w.drift < 0 {
		w.drift = -w.drift
	}
}

// At runs fn as though it happened at t. Every timestamp fn wrote moves back
// by the same amount, so the first lands at t. Dates fn set in the future,
// such as an expiry, stay as they are, so a later step can still use what fn
// made; date them explicitly where the story needs it. Steps must not
// overlap, and a write outside any At just before one may be moved with it.
func (w *World) At(t time.Time, fn func()) {
	margin := w.drift + 500*time.Millisecond
	start := time.Now()
	fn()
	end := time.Now()
	w.shift(start.Add(-margin), end.Add(margin), t.Sub(start))
}

// shift moves every timestamp in [from, to] by delta, in one round trip.
func (w *World) shift(from, to time.Time, delta time.Duration) {
	f, t := pgTime(from), pgTime(to)
	d := fmt.Sprintf("interval '%d microseconds'", delta.Microseconds())
	var b strings.Builder
	for _, tbl := range w.tables {
		sets := make([]string, len(tbl.columns))
		conds := make([]string, len(tbl.columns))
		for i, c := range tbl.columns {
			in := fmt.Sprintf("%s BETWEEN %s AND %s", c, f, t)
			sets[i] = fmt.Sprintf("%s = CASE WHEN %s THEN %s + %s ELSE %s END", c, in, c, d, c)
			conds[i] = in
		}
		fmt.Fprintf(&b, "UPDATE %s SET %s WHERE %s;\n", tbl.name, strings.Join(sets, ", "), strings.Join(conds, " OR "))
	}
	_, err := w.Admin.Exec(w.Ctx, b.String())
	Must(err, "move a step to its date")
}

// pgTime is t as a timestamptz literal.
func pgTime(t time.Time) string {
	return "'" + t.UTC().Format("2006-01-02 15:04:05.999999") + "+00'::timestamptz"
}
