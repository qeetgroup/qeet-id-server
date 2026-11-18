package postgres

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// backlog is a table of n rows that deletes at most limit at a time.
type backlog struct {
	n     int64
	calls int
	fail  error
}

func (b *backlog) delete(_ context.Context, limit int32) (int64, error) {
	b.calls++
	if b.fail != nil {
		return 0, b.fail
	}
	n := min(b.n, int64(limit))
	b.n -= n
	return n, nil
}

// TestDeleteInBatches checks that a backlog is deleted batch by batch until a
// batch comes up short, that one call stops after its bound, and that an
// error ends it.
func TestDeleteInBatches(t *testing.T) {
	ctx := context.Background()
	b := &backlog{n: 2*PurgeBatch + 7}
	total, err := DeleteInBatches(ctx, b.delete)
	if err != nil || total != 2*PurgeBatch+7 || b.n != 0 || b.calls != 3 {
		t.Errorf("deleted %d in %d calls (%v), %d left; want all in 3", total, b.calls, err, b.n)
	}

	b = &backlog{n: (maxPurgeBatches + 1) * PurgeBatch}
	total, err = DeleteInBatches(ctx, b.delete)
	if err != nil || total != maxPurgeBatches*PurgeBatch || b.n != PurgeBatch {
		t.Errorf("deleted %d (%v), %d left; want one batch left for the next run", total, err, b.n)
	}

	broken := errors.New("statement timeout")
	b = &backlog{n: 10, fail: broken}
	if _, err := DeleteInBatches(ctx, b.delete); !errors.Is(err, broken) || b.calls != 1 {
		t.Errorf("a failing batch: %v after %d calls, want its error at once", err, b.calls)
	}
}

// execer counts the rows each statement is asked to delete.
type execer struct {
	Querier
	rows int64
	args [][]any
}

func (e *execer) Exec(_ context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
	e.args = append(e.args, args)
	limit := int64(args[len(args)-1].(int32))
	n := min(e.rows, limit)
	e.rows -= n
	return pgconn.NewCommandTag("DELETE " + strconv.FormatInt(n, 10)), nil
}

// TestPurgeInBatches checks that the limit is passed as the last parameter,
// after the query's own.
func TestPurgeInBatches(t *testing.T) {
	e := &execer{rows: PurgeBatch + 1}
	total, err := PurgeInBatches(context.Background(), e, "DELETE … LIMIT $2", "cutoff")
	if err != nil || total != PurgeBatch+1 || len(e.args) != 2 {
		t.Fatalf("deleted %d in %d statements (%v)", total, len(e.args), err)
	}
	for _, args := range e.args {
		if len(args) != 2 || args[0] != "cutoff" || args[1] != int32(PurgeBatch) {
			t.Errorf("args %v, want the query's then the limit", args)
		}
	}
}
