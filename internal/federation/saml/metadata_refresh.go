package saml

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/federation/saml/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// failureText is what a connection records for a failed refresh.
func failureText(err error) string {
	if e := errs.As(err); e != nil && e.Code != errs.CodeInternal {
		if e.Detail != "" {
			return e.Detail
		}
		return e.Message
	}
	return "The metadata couldn't be applied."
}

// MetadataRun is what one RefreshMetadata run did.
type MetadataRun struct {
	Refreshed int
	Failed    int
}

// RefreshMetadata fetches again the metadata of the connections backed by a
// metadata URL that weren't fetched for metadataRefreshAge, and applies it, so
// each picks up its IdP's next certificate. One whose metadata can't be fetched
// or used, or no longer describes its IdP, keeps its settings and records why.
func RefreshMetadata(ctx context.Context, pool *pgxpool.Pool, policy *egress.Policy) (MetadataRun, error) {
	s := NewService(pool, nil, "")
	s.SetEgressPolicy(policy)
	ctx = postgres.AcrossOrganizations(ctx)
	due, err := s.q.ListSamlMetadataDue(ctx, dbgen.ListSamlMetadataDueParams{
		CheckedBefore: new(time.Now().Add(-metadataRefreshAge)),
		MaxRows:       metadataRefreshBatch,
	})
	var run MetadataRun
	if err != nil {
		return run, err
	}
	for _, c := range due {
		if err := ctx.Err(); err != nil {
			return run, err
		}
		scoped := postgres.WithOrganization(ctx, c.OrganizationID)
		if err := s.refreshMetadata(scoped, c.ID, c.OrganizationID, c.MetadataUrl); err != nil {
			run.Failed++
			slog.Warn("saml metadata refresh failed", "connection", c.ID, "err", err)
			msg := failureText(err)
			if err := s.q.SetSamlMetadataError(scoped, dbgen.SetSamlMetadataErrorParams{MetadataError: &msg, ID: c.ID, OrganizationID: c.OrganizationID}); err != nil {
				return run, err
			}
			continue
		}
		run.Refreshed++
	}
	return run, nil
}

// refreshMetadata fetches connectionID's metadata from metadataURL and applies
// it, if the connection still refreshes from there. The metadata must still
// describe the connection's IdP, so the URL can't repoint it at another.
func (s *Service) refreshMetadata(ctx context.Context, connectionID, organizationID uuid.UUID, metadataURL string) error {
	raw, err := s.fetchMetadata(ctx, metadataURL)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	current, err := s.q.WithTx(tx).LockSamlMetadataSource(ctx, dbgen.LockSamlMetadataSourceParams{ID: connectionID, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (current.MetadataUrl == nil || *current.MetadataUrl != metadataURL)) {
		return nil // deleted, or no longer refreshed from this URL
	}
	if err != nil {
		return err
	}
	md, err := parseIdPMetadata(raw, current.IdpEntityID)
	if err != nil {
		return err
	}
	change, err := s.ApplyMetadata(ctx, tx, connectionID, organizationID, md, &metadataURL)
	if err != nil {
		return err
	}
	if !change.empty() {
		if err := audit.Record(ctx, tx, audit.Actor{Type: "system"}.Event(organizationID, "saml.metadata_refreshed", "saml_connection", connectionID, map[string]any{
			"certificates_added": change.Added, "certificates_removed": change.Removed, "idp_sso_url": change.SSOURL,
		})); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
