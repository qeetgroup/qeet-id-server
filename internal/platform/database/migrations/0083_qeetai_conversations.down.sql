-- Reverse 0083: drop messages (FK child) first, then conversations, then the schema.
DROP TABLE IF EXISTS qeetai.messages;
DROP TABLE IF EXISTS qeetai.conversations;
DROP SCHEMA IF EXISTS qeetai;
