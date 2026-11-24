// Package reseal seals stored values again with the envelope cipher's current
// data key, so that a previous key can be removed once nothing it sealed
// remains. It works on a list of encrypted columns the composition root gives
// it, and never reads or writes anything else.
package reseal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
)

// Column is an encrypted column and the encryption context each of its rows
// was sealed with. Every name and expression is SQL written in code, never
// input.
type Column struct {
	Table        string   // schema-qualified table
	Key          []string // the columns that identify a row, in index order
	Ciphertext   string   // the sealed value
	Nonce        string   // its nonce
	Organization string   // SQL for the context's organization
	Purpose      string   // the context's purpose
	Resource     string   // SQL for the context's resource
	// OrganizationOf turns Organization's text into the context's organization; nil parses it as
	// a UUID.
	OrganizationOf func(string) uuid.UUID
}

// Name is how logs and the metric refer to the column.
func (c Column) Name() string { return c.Table + "." + c.Ciphertext }

// Result is what a Run did.
type Result struct {
	Resealed   int  // values sealed again with the current key
	Unreadable int  // values no configured key opens under their context
	Finished   bool // false when the time budget ran out first
}

// Run seals again with box's current key every value in columns not sealed with it, batch rows at a
// time, stopping once budget has passed (a later run carries on). A row is replaced only while it
// still holds what was read, so a run is safe beside writes and other runs, and idempotent.
func Run(ctx context.Context, pool *pgxpool.Pool, box *envelope.Cipher, columns []Column, batch int, budget time.Duration) (Result, error) {
	ctx = postgres.AcrossOrganizations(ctx)
	deadline := time.Now().Add(budget)
	var res Result
	for _, c := range columns {
		finished, err := c.run(ctx, pool, box, batch, deadline, &res)
		if err != nil {
			return res, fmt.Errorf("re-encrypt %s: %w", c.Name(), err)
		}
		if !finished {
			return res, nil
		}
	}
	res.Finished = true
	return res, nil
}

// row is one stored value and what it was sealed with.
type row struct {
	key                    []any
	ciphertext, nonce      []byte
	organization, resource string
}

// run reseals the column's values and reports whether it got through them
// before deadline. It pages by key, so a value that can't be opened is passed
// over rather than read again.
func (c Column) run(ctx context.Context, pool *pgxpool.Pool, box *envelope.Cipher, batch int, deadline time.Time, res *Result) (bool, error) {
	prefix := box.CurrentPrefix()
	var after []any
	unreadable := 0
	var firstErr error
	defer func() {
		if unreadable > 0 {
			slog.Warn("re-encryption: stored values no configured key opens", "column", c.Name(),
				"values", unreadable, "err", firstErr)
		}
	}()
	for {
		if time.Now().After(deadline) {
			return false, nil
		}
		rows, err := c.next(ctx, pool, prefix, after, batch)
		if err != nil {
			return false, err
		}
		for _, r := range rows {
			organization, plaintext, err := c.open(box, r)
			if err != nil {
				unreadable++
				res.Unreadable++
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			resealed, err := c.store(ctx, pool, box, r, organization, plaintext)
			if err != nil {
				return false, err
			}
			if resealed {
				res.Resealed++
			}
		}
		if len(rows) < batch {
			return true, nil
		}
		after = rows[len(rows)-1].key
	}
}

// next returns up to batch values after the row keyed after (from the start
// when nil) that aren't sealed with the current key.
func (c Column) next(ctx context.Context, pool *pgxpool.Pool, prefix []byte, after []any, batch int) ([]row, error) {
	keys := strings.Join(c.Key, ", ")
	where := c.notCurrent(len(prefix))
	args := []any{prefix, batch}
	if after != nil {
		where += fmt.Sprintf(" AND (%s) > (%s)", keys, placeholders(len(args)+1, len(after)))
		args = append(args, after...)
	}
	// #nosec G201 -- the table, columns and expressions are the fixed list in code, never input.
	query := fmt.Sprintf(`SELECT %s, %s, %s, (%s)::text AS context_organization, (%s)::text AS context_resource
		FROM %s WHERE %s ORDER BY %s LIMIT $2`,
		keys, c.Ciphertext, c.Nonce, c.Organization, c.Resource, c.Table, where, keys)
	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []row
	for rows.Next() {
		r := row{key: make([]any, len(c.Key))}
		dest := make([]any, 0, len(c.Key)+4)
		for i := range r.key {
			dest = append(dest, &r.key[i])
		}
		dest = append(dest, &r.ciphertext, &r.nonce, &r.organization, &r.resource)
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// open decrypts one stored value under the context it was sealed with.
func (c Column) open(box *envelope.Cipher, r row) (uuid.UUID, []byte, error) {
	organization := uuid.Nil
	if c.OrganizationOf != nil {
		organization = c.OrganizationOf(r.organization)
	} else if id, err := uuid.Parse(r.organization); err == nil {
		organization = id
	}
	plaintext, err := box.Open(organization, c.Purpose, r.resource, r.ciphertext, r.nonce)
	return organization, plaintext, err
}

// store replaces one value with plaintext sealed with the current key, unless
// the row changed since it was read, and reports whether it did.
func (c Column) store(ctx context.Context, pool *pgxpool.Pool, box *envelope.Cipher, r row, organization uuid.UUID, plaintext []byte) (bool, error) {
	ciphertext, nonce, err := box.Seal(organization, c.Purpose, r.resource, plaintext)
	clear(plaintext)
	if err != nil {
		return false, err
	}
	match := make([]string, len(c.Key))
	for i, k := range c.Key {
		match[i] = fmt.Sprintf("%s = $%d", k, i+4)
	}
	// #nosec G201 -- the table and columns are the fixed list in code, never input.
	query := fmt.Sprintf(`UPDATE %s SET %s = $1, %s = $2 WHERE %s = $3 AND %s`,
		c.Table, c.Ciphertext, c.Nonce, c.Ciphertext, strings.Join(match, " AND "))
	tag, err := pool.Exec(ctx, query, append([]any{ciphertext, nonce, r.ciphertext}, r.key...)...)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// notCurrent is the condition for a stored value not sealed with the current
// key, whose ciphertext starts with the prefixLen bytes in $1.
func (c Column) notCurrent(prefixLen int) string {
	// #nosec G201 -- the column is the fixed list in code, never input.
	return fmt.Sprintf("%s IS NOT NULL AND substring(%s FROM 1 FOR %d) <> $1", c.Ciphertext, c.Ciphertext, prefixLen)
}

// placeholders returns "$from, …" for n parameters.
func placeholders(from, n int) string {
	p := make([]string, n)
	for i := range p {
		p[i] = fmt.Sprintf("$%d", from+i)
	}
	return strings.Join(p, ", ")
}

// Count returns, for each of columns in order, how many stored values are not
// sealed with box's current key.
func Count(ctx context.Context, pool *pgxpool.Pool, box *envelope.Cipher, columns []Column) ([]int64, error) {
	if len(columns) == 0 {
		return nil, nil
	}
	prefix := box.CurrentPrefix()
	parts := make([]string, len(columns))
	for i, c := range columns {
		// #nosec G201 -- the table and column are the fixed list in code, never input.
		parts[i] = fmt.Sprintf("SELECT %d, count(*) FROM %s WHERE %s", i, c.Table, c.notCurrent(len(prefix)))
	}
	rows, err := pool.Query(postgres.AcrossOrganizations(ctx), strings.Join(parts, " UNION ALL "), prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := make([]int64, len(columns))
	for rows.Next() {
		var i int
		var n int64
		if err := rows.Scan(&i, &n); err != nil {
			return nil, err
		}
		if i < 0 || i >= len(counts) {
			return nil, errors.New("reseal: count for an unknown column")
		}
		counts[i] = n
	}
	return counts, rows.Err()
}

// Collector reports envelope_rows_on_old_keys for each column, read from the
// database at scrape time: stored values not yet sealed with box's current
// key. Once it is 0 for every column, the previous keys can be removed.
func Collector(pool *pgxpool.Pool, box *envelope.Cipher, columns []Column) prometheus.Collector {
	return &collector{pool: pool, box: box, columns: columns, desc: prometheus.NewDesc(
		"envelope_rows_on_old_keys",
		"Stored values not sealed with the current data key, by column; at 0 everywhere the previous keys can be removed.",
		[]string{"column"}, nil)}
}

type collector struct {
	pool    *pgxpool.Pool
	box     *envelope.Cipher
	columns []Column
	desc    *prometheus.Desc
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	counts, err := Count(ctx, c.pool, c.box, c.columns)
	if err != nil {
		return
	}
	for i, n := range counts {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, float64(n), c.columns[i].Name())
	}
}
