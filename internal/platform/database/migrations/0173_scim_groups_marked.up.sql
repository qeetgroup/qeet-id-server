-- 0173_scim_groups_marked — a directory manages only the groups it made.
--
-- SCIM could rename, delete and change the members of any group, so an
-- identity provider could put someone in a group an administrator gave roles
-- to. A group SCIM creates is now marked, and SCIM reads and changes only
-- those. Groups with an external ID were made by SCIM, the only writer of it.
ALTER TABLE tenant.groups ADD COLUMN provisioned_via TEXT CHECK (provisioned_via IN ('scim'));
UPDATE tenant.groups SET provisioned_via = 'scim' WHERE external_id IS NOT NULL;
