-- like_escape makes q match itself in a LIKE pattern.
CREATE OR REPLACE FUNCTION audit.like_escape(q TEXT) RETURNS TEXT
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT replace(replace(replace(q, '\', '\\'), '%', '\%'), '_', '\_')
$$;
