ALTER TABLE audit.events DROP COLUMN IF EXISTS search_vector;
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
CREATE INDEX IF NOT EXISTS idx_audit_search_vector ON audit.events USING GIN (search_vector);
DROP FUNCTION IF EXISTS audit.like_escape(TEXT);
DROP FUNCTION IF EXISTS audit.search_query(TEXT);
DROP FUNCTION IF EXISTS audit.search_text(TEXT, TEXT, TEXT, TEXT, INET, JSONB);
