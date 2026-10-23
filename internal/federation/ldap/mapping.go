package ldap

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ProfileMapper maps directory attributes to a profile.
type ProfileMapper interface {
	SourceAttributes(context.Context, uuid.UUID, string) ([]string, error)
	MapProfile(context.Context, uuid.UUID, string, map[string]any, bool) (map[string]any, error)
	StoreProfile(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, string, map[string]any) error
}

// SetProfileMapper sets the mapper applied to signed-in directory accounts.
func (service *Service) SetProfileMapper(mapper ProfileMapper) { service.mapper = mapper }

func (service *Service) storeMappedProfile(ctx context.Context, tx pgx.Tx, tenantID, userID uuid.UUID, user *ldapUser) error {
	if service.mapper == nil || len(user.Profile) == 0 {
		return nil
	}
	return service.mapper.StoreProfile(ctx, tx, tenantID, userID, user.ConnectionID, user.Profile)
}
