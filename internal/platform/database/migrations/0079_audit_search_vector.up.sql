-- Generated stored tsvector column covering the structured event fields most
-- useful for free-text search. 'simple' dictionary tokenises without stemming,
-- which keeps technical tokens like "user.login" or "saml.provider" intact.
ALTER TABLE audit.events
    ADD COLUMN search_vector tsvector
    GENERATED ALWAYS AS (
        to_tsvector('simple',
            coalesce(action, '') || ' ' ||
            coalesce(resource_type, '') || ' ' ||
            coalesce(actor_type, '') || ' ' ||
            coalesce(user_agent, '') || ' ' ||
            coalesce(metadata::text, '{}')
        )
    ) STORED;

CREATE INDEX idx_audit_search_vector ON audit.events USING GIN (search_vector);
