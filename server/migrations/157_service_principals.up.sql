CREATE TABLE service_principal (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspace(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, name)
);

CREATE TABLE service_token (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_principal_id UUID NOT NULL REFERENCES service_principal(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    scopes TEXT[] NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT service_token_scopes_nonempty CHECK (cardinality(scopes) > 0),
    CONSTRAINT service_token_scopes_fixed CHECK (scopes <@ ARRAY[
        'control_plane.agents.read',
        'control_plane.tasks.read',
        'control_plane.brief.read',
        'control_plane.status.read'
    ]::TEXT[])
);

CREATE INDEX idx_service_token_principal_active ON service_token(service_principal_id, revoked);
