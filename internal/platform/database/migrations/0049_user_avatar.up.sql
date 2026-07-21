-- Profile picture stored inline as a small data-URL. There's no object storage
-- yet, and the app caps/compresses the image client-side (see qeetid-admin
-- account/profile), so a nullable TEXT column keeps avatars self-contained.
-- Only the single-user GET selects this column; the paginated users list stays lean.
ALTER TABLE "user".users ADD COLUMN avatar_url TEXT;
