package postgres

import (
	"context"
	"slices"
)

const (
	PurgeBatch      = 5000 // the most rows one cleanup statement deletes
	maxPurgeBatches = 200  // batches per call; a longer backlog waits for the next run
)

// DeleteInBatches calls del, which deletes at most limit rows and returns how
// many it deleted, until a call deletes fewer than limit, and returns the
// total. Each call is a short statement of its own, so a backlog drains
// without one statement outlasting the statement timeout.
func DeleteInBatches(ctx context.Context, del func(ctx context.Context, limit int32) (int64, error)) (int64, error) {
	var total int64
	for range maxPurgeBatches {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := del(ctx, PurgeBatch)
		total += n
		if err != nil || n < PurgeBatch {
			return total, err
		}
	}
	return total, nil
}

// PurgeInBatches runs query, a statement that deletes at most as many rows as
// its last parameter, with args before that limit, through DeleteInBatches.
func PurgeInBatches(ctx context.Context, db Querier, query string, args ...any) (int64, error) {
	args = append(slices.Clip(args), nil)
	return DeleteInBatches(ctx, func(ctx context.Context, limit int32) (int64, error) {
		args[len(args)-1] = limit
		tag, err := db.Exec(ctx, query, args...)
		return tag.RowsAffected(), err
	})
}
