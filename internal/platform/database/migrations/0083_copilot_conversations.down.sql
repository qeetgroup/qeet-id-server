-- Reverse 0083_copilot_conversations: drop messages first (FK child), then
-- conversations, then the schema. Grants and default privileges are removed
-- with the schema objects automatically.
DROP TABLE IF EXISTS copilot.messages;
DROP TABLE IF EXISTS copilot.conversations;
DROP SCHEMA IF EXISTS copilot;
