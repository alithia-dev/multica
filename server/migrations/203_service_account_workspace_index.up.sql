CREATE INDEX CONCURRENTLY idx_service_account_workspace ON service_account(workspace_id) WHERE revoked_at IS NULL;
