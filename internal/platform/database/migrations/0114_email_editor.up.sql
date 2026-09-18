ALTER TABLE tenant.email_templates
  ADD COLUMN options JSONB NOT NULL DEFAULT '{}'::jsonb;
