ALTER TABLE agent_task_queue
  ADD COLUMN cancelled_reason TEXT,
  ADD COLUMN cancelled_by_type TEXT CHECK (cancelled_by_type IS NULL OR cancelled_by_type IN ('member', 'agent', 'system', 'scheduler', 'server')),
  ADD COLUMN cancelled_by_id UUID,
  ADD COLUMN superseded_by_task_id UUID REFERENCES agent_task_queue(id) ON DELETE SET NULL;

