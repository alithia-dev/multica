-- name: CreateServiceAccount :one
INSERT INTO service_account (workspace_id, name, slug, avatar_url, role, created_by_user_id)
VALUES ($1, $2, $3, $4, $5, $6) RETURNING *;

-- name: ListServiceAccounts :many
SELECT * FROM service_account WHERE workspace_id = $1 AND revoked_at IS NULL ORDER BY name;

-- name: GetServiceAccount :one
SELECT * FROM service_account WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeServiceAccount :execrows
UPDATE service_account SET revoked_at = now(), updated_at = now()
WHERE id = $1 AND workspace_id = $2 AND revoked_at IS NULL;

-- name: CreateServiceAccountToken :one
INSERT INTO service_account_token (service_account_id, name, token_hash, token_prefix, expires_at)
VALUES ($1, $2, $3, $4, $5) RETURNING *;

-- name: GetServiceAccountTokenByHash :one
SELECT t.id, t.service_account_id, t.expires_at, s.workspace_id, s.created_by_user_id
FROM service_account_token t JOIN service_account s ON s.id = t.service_account_id
WHERE t.token_hash = $1 AND t.revoked_at IS NULL AND s.revoked_at IS NULL
  AND (t.expires_at IS NULL OR t.expires_at > now());

-- name: ListServiceAccountTokens :many
SELECT * FROM service_account_token WHERE service_account_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC;

-- name: RevokeServiceAccountToken :execrows
UPDATE service_account_token SET revoked_at = now()
WHERE id = $1 AND service_account_id = $2 AND revoked_at IS NULL;

-- name: UpdateServiceAccountTokenLastUsed :exec
UPDATE service_account_token SET last_used_at = now() WHERE id = $1;
