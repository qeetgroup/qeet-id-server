-- 0191_idempotency_attempt — each claim of an Idempotency-Key names the
-- attempt that made it, so only that attempt stores the answer or frees the
-- key. A claim left unanswered is never taken over: a retry is told its
-- outcome is unknown instead of running the request a second time.
ALTER TABLE platform.idempotency_keys ADD COLUMN attempt UUID;
