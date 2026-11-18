package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/servicehealth"
)

// The arguments that make the scheduler post or end a service incident instead
// of running the jobs.
const (
	openIncidentCommand    = "open-incident"
	resolveIncidentCommand = "resolve-incident"
)

// openIncident posts the incident args describe (-component, -impact, -title
// and -detail), shown to every organization, and returns the exit code.
func openIncident(ctx context.Context, svc *servicehealth.Incidents, args []string) int {
	fs := flag.NewFlagSet(openIncidentCommand, flag.ContinueOnError)
	component := fs.String("component", "", "api, sign_in, email, webhooks or directory")
	impact := fs.String("impact", "", "maintenance, degraded or outage")
	title := fs.String("title", "", "what organizations see")
	detail := fs.String("detail", "", "more about it, optional")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		slog.Error(openIncidentCommand+": invalid arguments", "err", fmt.Errorf("unexpected argument %q", fs.Arg(0)))
		return 2
	}
	id, err := svc.OpenIncident(ctx, *component, *impact, *title, *detail)
	if err != nil {
		slog.Error("open incident", "err", err)
		return 1
	}
	slog.Info("incident opened", "incident_id", id, "component", *component, "impact", *impact)
	return 0
}

// resolveIncident ends the incident -incident names, and returns the exit code.
func resolveIncident(ctx context.Context, svc *servicehealth.Incidents, args []string) int {
	fs := flag.NewFlagSet(resolveIncidentCommand, flag.ContinueOnError)
	incident := fs.String("incident", "", "the incident's id")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	id, err := uuid.Parse(*incident)
	if err != nil || fs.NArg() > 0 {
		slog.Error(resolveIncidentCommand+": invalid arguments", "err", fmt.Errorf("-incident: want an incident id"))
		return 2
	}
	if err := svc.ResolveIncident(ctx, id); err != nil {
		slog.Error("resolve incident", "incident_id", id, "err", err)
		return 1
	}
	slog.Info("incident resolved", "incident_id", id)
	return 0
}
