-- Convert historical 'action_error' entries to 'action_timeout'
-- We err on the side of timeout since the previous error could have masked a dropped connection post-dispatch
UPDATE audit_log
SET action = 'action_timeout'
WHERE action = 'action_error';
