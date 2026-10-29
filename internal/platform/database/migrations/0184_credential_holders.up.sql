-- 0184_credential_holders — the person a verifiable credential was issued to.
--
-- A credential's subject is free text, often a DID, so the list couldn't say
-- whose it was. An issuer can name the person, a member of the organisation;
-- the link clears if the account is deleted.
ALTER TABLE auth.credentials
    ADD COLUMN user_id UUID REFERENCES "user".users(id) ON DELETE SET NULL;
