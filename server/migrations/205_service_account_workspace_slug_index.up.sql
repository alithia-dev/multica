CREATE UNIQUE INDEX CONCURRENTLY idx_service_account_workspace_slug ON service_account(workspace_id, slug);
