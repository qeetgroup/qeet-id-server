-- 0083_copilot_conversations — conversation + message store for the AI copilot.

CREATE SCHEMA IF NOT EXISTS copilot;

CREATE TABLE copilot.conversations (
  id          uuid        not null default gen_random_uuid() primary key,
  tenant_id   uuid        not null,
  user_id     uuid        not null,
  title       text        not null default 'New conversation',
  pinned      boolean     not null default false,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

-- Backs the list view (pinned first, then most-recently-updated).
CREATE INDEX ON copilot.conversations (tenant_id, user_id, pinned desc, updated_at desc);

-- Turn-by-turn content blocks (content-block array as JSONB).
CREATE TABLE copilot.messages (
  id               uuid        not null default gen_random_uuid() primary key,
  tenant_id        uuid        not null,
  conversation_id  uuid        not null references copilot.conversations(id) on delete cascade,
  role             text        not null check (role in ('user', 'assistant', 'tool')),
  content          jsonb       not null,
  created_at       timestamptz not null default now()
);

-- Backs message list for a conversation in chronological order.
CREATE INDEX ON copilot.messages (conversation_id, created_at);
