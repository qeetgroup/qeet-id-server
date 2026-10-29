-- 0166_resource_identifiers_unique — a resource identifier names one service.
--
-- Every organisation's tokens come from the same issuer, and a resource
-- identifier was unique only within its organisation, so another organisation
-- could register a service's identifier and mint tokens bearing it as their
-- audience, which that service would accept. An identifier now belongs to one
-- organisation on the platform.
CREATE UNIQUE INDEX uq_oidc_resources_identifier ON auth.oidc_resources (identifier);
