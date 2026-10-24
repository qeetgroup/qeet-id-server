-- 0164_oidc_clients_without_client_credentials — drop a grant no application
-- can use.
--
-- Applications could register client_credentials, but no token endpoint ever
-- served it to one: a machine caller is a service principal. Registering it is
-- now refused, and an application that still held it failed every edit until
-- an admin removed it. Remove it everywhere.
UPDATE auth.oidc_clients
SET grant_types = array_remove(grant_types, 'client_credentials')
WHERE 'client_credentials' = ANY (grant_types);
