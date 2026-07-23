-- Reverse 0083: drop messages (FK child) first, then conversations, then the schema.
DROP TABLE IF EXISTS copilot.messages;
DROP TABLE IF EXISTS copilot.conversations;
DROP SCHEMA IF EXISTS copilot;
