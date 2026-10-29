-- 0214_audit_search_words — audit search finds words: action names, user
-- agents, metadata and the address are split into words (auth.login_succeeded
-- is auth, login and succeeded), and a search's plain words match as
-- prefixes. The index is rebuilt by 0215.

-- search_text is what an event's search finds it by, as words.
CREATE OR REPLACE FUNCTION audit.search_text(action TEXT, resource_type TEXT, actor_type TEXT, user_agent TEXT,
                                             ip INET, metadata JSONB) RETURNS TEXT
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT regexp_replace(lower(
        coalesce(action, '') || ' ' || coalesce(resource_type, '') || ' ' || coalesce(actor_type, '') || ' ' ||
        coalesce(user_agent, '') || ' ' || coalesce(host(ip), '') || ' ' || coalesce(metadata::text, '')
    ), '[^[:alnum:]]+', ' ', 'g')
$$;

-- search_query is the tsquery for a search q: its plain words, each a prefix,
-- all of them; or, when q uses "quoted phrases", -exclusions or OR, those as
-- websearch_to_tsquery reads them, over the same words. NULL when q has none.
CREATE OR REPLACE FUNCTION audit.search_query(q TEXT) RETURNS tsquery
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE
        WHEN q ~ '"|(^|\s)-|\sOR\s' THEN
            websearch_to_tsquery('simple', regexp_replace(q, '[^[:alnum:]"\s-]+', ' ', 'g'))
        ELSE (
            SELECT to_tsquery('simple', string_agg(quote_literal(w) || ':*', ' & '))
            FROM regexp_split_to_table(lower(q), '[^[:alnum:]]+') AS w
            WHERE w <> ''
        )
    END
$$;

-- like_escape makes q match itself in a LIKE pattern.
CREATE OR REPLACE FUNCTION audit.like_escape(q TEXT) RETURNS TEXT
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT replace(replace(replace(q, '\', '\\'), '%', '\%'), '_', '\_')
$$;

DROP INDEX IF EXISTS audit.idx_audit_search_vector;
ALTER TABLE audit.events DROP COLUMN IF EXISTS search_vector;
ALTER TABLE audit.events
    ADD COLUMN search_vector tsvector
    GENERATED ALWAYS AS (
        to_tsvector('simple', audit.search_text(action, resource_type, actor_type, user_agent, ip, metadata))
    ) STORED;
