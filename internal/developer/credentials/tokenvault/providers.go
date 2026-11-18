package tokenvault

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/tokenvault/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// RegisterProviderInput is what RegisterProvider takes. Provider, ClientID and
// ClientSecret are required; AuthorizeURL and TokenURL must be allowed outbound
// destinations.
type RegisterProviderInput struct {
	Provider     string `json:"provider"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	AuthorizeURL string `json:"authorize_url"`
	TokenURL     string `json:"token_url"`
	Scopes       string `json:"scopes"`
}

// RegisterProvider stores the organization's settings for an OAuth provider. Its
// endpoints and client don't change while anyone is connected through it
// (ErrTokenVaultProviderInUse): their refresh tokens would go to the new ones.
func (s *Service) RegisterProvider(ctx context.Context, organizationID uuid.UUID, in RegisterProviderInput) (*Provider, error) {
	var missing []errs.FieldError
	for field, value := range map[string]string{"provider": in.Provider, "client_id": in.ClientID, "client_secret": in.ClientSecret} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, errs.FieldError{Field: field, Code: "required", Message: "This field is required."})
		}
	}
	if len(missing) > 0 {
		slices.SortFunc(missing, func(a, b errs.FieldError) int { return strings.Compare(a.Field, b.Field) })
		return nil, errs.ErrValidationFailed.WithFields(missing)
	}
	if _, err := s.egress.ValidateHTTPURL(in.AuthorizeURL); err != nil {
		return nil, ErrProviderAuthorizeInvalid
	}
	if _, err := s.egress.ValidateHTTPURL(in.TokenURL); err != nil {
		return nil, ErrProviderTokenURLInvalid
	}
	ct, nonce, err := s.box.Seal(organizationID, "token-vault-provider", in.Provider, []byte(in.ClientSecret))
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	if err := refuseRepointing(ctx, q, organizationID, in); err != nil {
		return nil, err
	}
	row, err := q.UpsertProvider(ctx, dbgen.UpsertProviderParams{
		OrganizationID: organizationID, Provider: in.Provider, ClientID: in.ClientID,
		ClientSecretCt: ct, ClientSecretNonce: nonce,
		AuthorizeUrl: in.AuthorizeURL, TokenUrl: in.TokenURL, Scopes: in.Scopes,
	})
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return new(providerOf(dbgen.ListProvidersRow(row))), nil
}

// providerOf maps a stored provider, without its client secret.
func providerOf(row dbgen.ListProvidersRow) Provider {
	return Provider{
		ID: row.ID, Provider: row.Provider, ClientID: row.ClientID,
		AuthorizeURL: row.AuthorizeUrl, TokenURL: row.TokenUrl, Scopes: row.Scopes,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
}

// refuseRepointing refuses giving a provider other endpoints or another client,
// or setting up again a name that still has grants, while anyone is connected
// through it. Its row is locked first, so no grant is stored under the
// settings being replaced (UpsertTokenGrant share-locks it).
func refuseRepointing(ctx context.Context, q *dbgen.Queries, organizationID uuid.UUID, in RegisterProviderInput) error {
	current, err := q.LockProvider(ctx, dbgen.LockProviderParams{OrganizationID: organizationID, Provider: in.Provider})
	if err == nil && current.ClientID == in.ClientID && current.AuthorizeUrl == in.AuthorizeURL && current.TokenUrl == in.TokenURL {
		return nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	inUse, err := q.ProviderHasGrants(ctx, dbgen.ProviderHasGrantsParams{OrganizationID: organizationID, Provider: in.Provider})
	if err != nil {
		return err
	}
	if inUse {
		return ErrProviderInUse
	}
	return nil
}

// ListProviders returns the organization's OAuth providers.
func (s *Service) ListProviders(ctx context.Context, organizationID uuid.UUID) ([]Provider, error) {
	rows, err := s.q.ListProviders(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Provider, 0, len(rows))
	for _, row := range rows {
		out = append(out, providerOf(row))
	}
	return out, nil
}

// DeleteProvider removes the organization's settings for an OAuth provider and
// disconnects everyone connected through it, so a provider set up again under
// its name inherits no grant.
func (s *Service) DeleteProvider(ctx context.Context, organizationID uuid.UUID, provider string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	// The grants go first: a refresh holds its grant's row while it waits to
	// share the provider's.
	if err := q.DeleteProviderGrants(ctx, dbgen.DeleteProviderGrantsParams{OrganizationID: organizationID, Provider: provider}); err != nil {
		return err
	}
	n, err := q.DeleteProvider(ctx, dbgen.DeleteProviderParams{OrganizationID: organizationID, Provider: provider})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrProviderNotFound
	}
	return tx.Commit(ctx)
}

// providerConfig returns how to call one of the organization's providers: its
// client, opened client secret, endpoints and scopes.
func (s *Service) providerConfig(ctx context.Context, organizationID uuid.UUID, provider string) (clientID, clientSecret, authorizeURL, tokenURL, scopes string, err error) {
	row, err := s.q.GetProviderConfig(ctx, dbgen.GetProviderConfigParams{OrganizationID: organizationID, Provider: provider})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", "", "", ErrProviderNotFound
	}
	if err != nil {
		return "", "", "", "", "", err
	}
	plain, err := s.box.Open(organizationID, "token-vault-provider", provider, row.ClientSecretCt, row.ClientSecretNonce)
	return row.ClientID, string(plain), row.AuthorizeUrl, row.TokenUrl, row.Scopes, err
}
