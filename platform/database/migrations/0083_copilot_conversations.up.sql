-- 0083_copilot_conversations
--
-- Persistent conversation and message store for the AI copilot.
-- Every row is tenant-scoped and protected by Postgres Row-Level Security,
-- re-declared here exactly as 0082 requires: 0082's DO block only enabled
-- RLS on tables present at that migration; tables added later must declare
-- the same policy themselves.

CREATE SCHEMA IF NOT EXISTS copilot;

-- 1. Least-privilege application role (created by 0082; guard is idempotent).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qid_app') THEN
    CREATE ROLE qid_app NOLOGIN;
  END IF;
END $$;

-- 2. Schema grants + default privileges so qid_app can DML tables created here
--    and by any future migration that extends this schema.
GRANT USAGE ON SCHEMA copilot TO qid_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA copilot TO qid_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA copilot TO qid_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA copilot GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO qid_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA copilot GRANT USAGE, SELECT ON SEQUENCES TO qid_app;

-- 3. copilot.conversations — one row per conversation thread (tenant + user scoped).
CREATE TABLE copilot.conversations (
  id          uuid        not null default gen_random_uuid() primary key,
  tenant_id   uuid        not null,
  user_id     uuid        not null,
  title       text        not null default 'New conversation',
  pinned      boolean     not null default false,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

-- Index backs the list view (pinned first, then most-recently-updated).
CREATE INDEX ON copilot.conversations (tenant_id, user_id, pinned desc, updated_at desc);

-- 4. RLS: enable + declare the uniform tenant-isolation policy (mirrors 0082).
ALTER TABLE copilot.conversations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON copilot.conversations;
CREATE POLICY tenant_isolation ON copilot.conversations
  USING (
    current_setting('app.bypass_rls', true) = 'on'
    OR tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
  )
  WITH CHECK (
    current_setting('app.bypass_rls', true) = 'on'
    OR tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
  );

-- 5. copilot.messages — turn-by-turn content blocks (Anthropic content-block array as JSONB).
CREATE TABLE copilot.messages (
  id               uuid        not null default gen_random_uuid() primary key,
  tenant_id        uuid        not null,
  conversation_id  uuid        not null references copilot.conversations(id) on delete cascade,
  role             text        not null check (role in ('user', 'assistant', 'tool')),
  content          jsonb       not null,
  created_at       timestamptz not null default now()
);

-- Index backs message list for a conversation in chronological order.
CREATE INDEX ON copilot.messages (conversation_id, created_at);

-- 6. RLS on messages: same predicate as conversations.
ALTER TABLE copilot.messages ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON copilot.messages;
CREATE POLICY tenant_isolation ON copilot.messages
  USING (
    current_setting('app.bypass_rls', true) = 'on'
    OR tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
  )
  WITH CHECK (
    current_setting('app.bypass_rls', true) = 'on'
    OR tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
  );
