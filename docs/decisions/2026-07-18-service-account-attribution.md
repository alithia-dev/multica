# Service account attribution

Decision: introduce workspace-scoped `service_account` principals and separately revocable `msa_` service tokens. Authentication, workspace binding, authorization role, and write attribution all come from the service account; `created_by_user_id` is audit metadata only and never grants or removes authority. Valid task-token attribution remains authoritative and agent-scoped.

Rationale: human, orchestration service, agent, and system actions need distinct audit identities. A separate token table keeps existing personal-token ownership and renewal semantics unchanged.

Reversibility: revoke service tokens/accounts first, move GRIT back to a member profile, then apply the down migrations. Existing member/agent rows are not rewritten. Rollback is blocked while persisted rows still use `service_account`; the down migration deliberately fails instead of silently relabeling audit history.

Lifecycle containment: migration 202 makes the workspace-to-service-account and service-account-to-token relationships cascading foreign keys. This is a narrow security exception to the repository's application-managed relationship policy: deleting a workspace must atomically destroy every credential that could authenticate as its service identity. The creator relationship instead uses `ON DELETE SET NULL`, retaining the service-account audit record without treating the creator as an authority source.

Rollback: the existing down migration drops tokens before accounts, removing the foreign keys with their tables. An up/down/up cycle recreates the same containment constraints; reverting only this decision requires replacing the three constrained columns without foreign keys after first verifying that no orphan rows exist.
