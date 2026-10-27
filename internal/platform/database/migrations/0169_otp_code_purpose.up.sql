-- 0169_otp_code_purpose — an email or SMS code works only for what it was
-- sent for.
--
-- A code sent to confirm a sensitive change could complete a sign-in, and a
-- sign-in code a step-up. Each code now names its purpose: signing in,
-- stepping up, or confirming a new factor. Codes already sent live minutes,
-- so they are taken as sign-in codes.
ALTER TABLE auth.mfa_otp_codes ADD COLUMN purpose TEXT;
UPDATE auth.mfa_otp_codes SET purpose = 'sign_in';
ALTER TABLE auth.mfa_otp_codes ALTER COLUMN purpose SET NOT NULL,
    ADD CONSTRAINT mfa_otp_codes_purpose_check CHECK (purpose IN ('sign_in', 'step_up', 'enrollment'));
