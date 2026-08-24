ALTER TABLE response_actions ADD COLUMN IF NOT EXISTS policy_id varchar;
ALTER TABLE response_action_approvals ADD COLUMN IF NOT EXISTS alert_id varchar;
ALTER TABLE response_action_approvals ADD COLUMN IF NOT EXISTS policy_id varchar;

CREATE INDEX IF NOT EXISTS idx_response_actions_policy_created
  ON response_actions (policy_id, created_at);
CREATE INDEX IF NOT EXISTS idx_response_approvals_alert
  ON response_action_approvals (alert_id);
