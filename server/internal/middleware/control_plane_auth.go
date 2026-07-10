package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

const (
	ControlPlaneAgentsRead = "control_plane.agents.read"
	ControlPlaneTasksRead  = "control_plane.tasks.read"
	ControlPlaneBriefRead  = "control_plane.brief.read"
	ControlPlaneStatusRead = "control_plane.status.read"
)

var ErrServiceTokenNotFound = errors.New("service token not found")

// ServicePrincipalIdentity is the server-authoritative identity recovered from
// an mcs_ bearer token. WorkspaceID is always derived from storage, never an
// HTTP header or query parameter.
type ServicePrincipalIdentity struct {
	ServicePrincipalID string
	WorkspaceID        string
	Scopes             []string
}

// ServiceTokenResolver resolves only active, non-expired service tokens.
type ServiceTokenResolver interface {
	ResolveServiceToken(ctx context.Context, rawToken string) (ServicePrincipalIdentity, error)
}

// DBServiceTokenResolver resolves mcs_ credentials solely from service_token
// storage. The query excludes revoked, expired, and disabled-principal rows.
type DBServiceTokenResolver struct {
	Queries *db.Queries
}

func (r DBServiceTokenResolver) ResolveServiceToken(ctx context.Context, rawToken string) (ServicePrincipalIdentity, error) {
	if r.Queries == nil {
		return ServicePrincipalIdentity{}, ErrServiceTokenNotFound
	}
	row, err := r.Queries.GetServiceTokenAuth(ctx, auth.HashToken(rawToken))
	if err != nil {
		return ServicePrincipalIdentity{}, ErrServiceTokenNotFound
	}
	// Last-used bookkeeping is deliberately non-authoritative and never lets a
	// failed update change a successful authorization result.
	go r.Queries.UpdateServiceTokenLastUsed(context.Background(), row.TokenID)
	return ServicePrincipalIdentity{
		ServicePrincipalID: util.UUIDToString(row.ServicePrincipalID),
		WorkspaceID:        util.UUIDToString(row.WorkspaceID),
		Scopes:             row.Scopes,
	}, nil
}

// ControlPlaneAuth authorizes one fixed control-plane scope. It intentionally
// does not call the general Auth middleware: mcs_ credentials are machine
// credentials and must not acquire access to the generic API surface.
func ControlPlaneAuth(resolver ServiceTokenResolver, requiredScope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// All actor/workspace identity headers are server-set only. Clearing
			// them before token resolution prevents client-supplied identity from
			// influencing a downstream handler on either a pass or failure path.
			r.Header.Del("X-Workspace-ID")
			r.Header.Del("X-Service-Principal-ID")
			r.Header.Del("X-Actor-Source")

			token := bearerToken(r.Header.Get("Authorization"))
			if !strings.HasPrefix(token, "mcs_") || resolver == nil {
				http.Error(w, `{"error":"invalid service token"}`, http.StatusUnauthorized)
				return
			}
			identity, err := resolver.ResolveServiceToken(r.Context(), token)
			if err != nil || identity.WorkspaceID == "" || identity.ServicePrincipalID == "" {
				http.Error(w, `{"error":"invalid service token"}`, http.StatusUnauthorized)
				return
			}
			if !hasScope(identity.Scopes, requiredScope) {
				http.Error(w, `{"error":"insufficient service token scope"}`, http.StatusForbidden)
				return
			}

			r.Header.Set("X-Workspace-ID", identity.WorkspaceID)
			r.Header.Set("X-Service-Principal-ID", identity.ServicePrincipalID)
			r.Header.Set("X-Actor-Source", "service_token")
			next.ServeHTTP(w, r)
		})
	}
}

func bearerToken(header string) string {
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(header, "Bearer ")
}

func hasScope(scopes []string, required string) bool {
	for _, scope := range scopes {
		if scope == required {
			return true
		}
	}
	return false
}
