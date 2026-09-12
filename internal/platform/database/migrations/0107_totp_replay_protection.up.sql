-- 0107_totp_replay_protection — record the TOTP time-step a user last consumed.
--
-- RFC 6238 §5.2 requires the verifier to reject a code that has already been
-- accepted. Without this column a TOTP code stayed valid for the whole
-- acceptance window (the current 30s step plus one either side, ~90s), so a code
-- observed once — shoulder-surfed, phished through a relay, or captured on a
-- screen share — could be used a second time for an independent authentication.
--
-- Nullable: existing enrollments have consumed no step yet, and NULL is treated
-- as "no step consumed" by the check-and-set in internal/access/mfa. Additive
-- and backward compatible — older binaries ignore the column.
ALTER TABLE auth.mfa_totp
    ADD COLUMN IF NOT EXISTS last_used_step BIGINT;
