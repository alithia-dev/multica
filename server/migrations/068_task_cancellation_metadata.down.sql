ALTER TABLE agent_task_queue
  DROP COLUMN IF EXISTS superseded_by_task_id,
  DROP COLUMN IF EXISTS cancelled_by_id,
  DROP COLUMN IF EXISTS cancelled_by_type,
  DROP COLUMN IF EXISTS cancelled_reason;

