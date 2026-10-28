-- 0201_qeetai_conversation_turns — a Qeet AI conversation answers one turn at
-- a time.
--
-- A turn sends the conversation's history to the model, and two at once in one
-- conversation doubled the work and raced each other's replies. A turn now
-- holds its conversation's row here while it runs, on whichever instance; one
-- left by a turn that never finished is taken over once it is older than the
-- longest a turn may run.
CREATE TABLE qeetai.conversation_turns (
    conversation_id UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT conversation_turns_conversation_id_fkey FOREIGN KEY (tenant_id, conversation_id)
        REFERENCES qeetai.conversations (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE qeetai.conversation_turns ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON qeetai.conversation_turns
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());
