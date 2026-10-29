package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/billing"
)

// markPaidCommand is the argument that makes the scheduler record an
// invoice paid instead of running the jobs.
const markPaidCommand = "mark-invoice-paid"

// markPaidArgs reads mark-invoice-paid's flags: -invoice, the invoice's id,
// and -reference, the payment's reference, such as a bank transfer's UTR.
func markPaidArgs(args []string) (uuid.UUID, string, error) {
	fs := flag.NewFlagSet(markPaidCommand, flag.ContinueOnError)
	invoice := fs.String("invoice", "", "the invoice's id")
	reference := fs.String("reference", "", "the payment's reference")
	if err := fs.Parse(args); err != nil {
		return uuid.Nil, "", err
	}
	if fs.NArg() > 0 {
		return uuid.Nil, "", fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	id, err := uuid.Parse(*invoice)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("-invoice: %w", err)
	}
	if *reference == "" {
		return uuid.Nil, "", fmt.Errorf("-reference is required")
	}
	return id, *reference, nil
}

// markInvoicePaid records the invoice args name as paid outside a checkout,
// starting the period a renewal billed, and returns the exit code.
func markInvoicePaid(ctx context.Context, svc *billing.Service, args []string) int {
	id, reference, err := markPaidArgs(args)
	if err != nil {
		slog.Error(markPaidCommand+": invalid arguments", "err", err)
		return 2
	}
	if err := svc.MarkInvoicePaid(ctx, id, reference); err != nil {
		slog.Error("mark invoice paid", "invoice_id", id, "err", err)
		return 1
	}
	slog.Info("invoice marked paid", "invoice_id", id, "reference", reference)
	return 0
}
