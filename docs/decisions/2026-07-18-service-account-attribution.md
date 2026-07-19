# Service account attribution

Decision: introduce workspace-scoped `service_account` principals and separately revocable `msa_` service tokens. Authentication, workspace binding, authorization role, and write attribution all come from the service account; `created_by_user_id` is audit metadata only and never grants or removes authority. Valid task-token attribution remains authoritative and agent-scoped.

Rationale: human, orchestration service, agent, and system actions need distinct audit identities. A separate token table keeps existing personal-token ownership and renewal semantics unchanged.

Reversibility: revoke service tokens/accounts first, move GRIT back to a member profile, then apply the down migrations. Existing member/agent rows are not rewritten. Rollback is blocked while persisted rows still use `service_account`; the down migration deliberately fails instead of silently relabeling audit history.
