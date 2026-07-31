-- Convert historical 'action_error' entries accurately based on the detail string in the target column

-- 1. Pre-flight check failures definitively did not dispatch. Map to action_failure.
UPDATE audit_log
SET action = 'action_failure'
WHERE action = 'action_error'
  AND (
       target LIKE '%detail:Failed to query client status%'
    OR target LIKE '%detail:Target % not found%'
    OR target LIKE '%detail:Target % is offline%'
  );

-- 2. Dispatch timeouts and mid-poll connection drops are ambiguous. Map to action_timeout.
-- (This captures gRPC drops that happened during dispatch or polling in the previous logic)
UPDATE audit_log
SET action = 'action_timeout'
WHERE action = 'action_error'
  AND (
       target LIKE '%detail:Failed to trigger collection%'
    OR target LIKE '%detail:transport error%'
    OR target LIKE '%detail:connection closed%'
  );

-- 3. Any remaining historical errors that don't match our known patterns
-- are marked as legacy rather than being confidently miscategorized.
UPDATE audit_log
SET action = 'action_error_legacy'
WHERE action = 'action_error';
