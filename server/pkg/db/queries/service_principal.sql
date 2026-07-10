-- name: GetServiceTokenAuth :one
SELECT st.id AS token_id, sp.id AS service_principal_id, sp.workspace_id, st.scopes
FROM service_token st
JOIN service_principal sp ON sp.id = st.service_principal_id
WHERE st.token_hash = $1
  AND st.revoked = FALSE
  AND st.expires_at > now()
  AND sp.disabled = FALSE;

-- name: UpdateServiceTokenLastUsed :exec
UPDATE service_token
SET last_used_at = now()
WHERE id = $1
  AND (last_used_at IS NULL OR last_used_at < now() - INTERVAL '5 minutes');
