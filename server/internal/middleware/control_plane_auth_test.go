package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeServiceTokenResolver struct {
	identity ServicePrincipalIdentity
	err      error
	rawToken string
}

func (f *fakeServiceTokenResolver) ResolveServiceToken(_ context.Context, rawToken string) (ServicePrincipalIdentity, error) {
	f.rawToken = rawToken
	return f.identity, f.err
}

func TestControlPlaneAuth_BindsWorkspaceAndRejectsForgedHeaders(t *testing.T) {
	resolver := &fakeServiceTokenResolver{identity: ServicePrincipalIdentity{
		ServicePrincipalID: "principal-1",
		WorkspaceID:        "workspace-bound",
		Scopes:             []string{ControlPlaneAgentsRead},
	}}
	handler := ControlPlaneAuth(resolver, ControlPlaneAgentsRead)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Workspace-ID"); got != "workspace-bound" {
			t.Fatalf("workspace must come from the service token, got %q", got)
		}
		if got := r.Header.Get("X-Service-Principal-ID"); got != "principal-1" {
			t.Fatalf("principal identity not server-stamped, got %q", got)
		}
		if got := r.Header.Get("X-Actor-Source"); got != "service_token" {
			t.Fatalf("actor source not server-stamped, got %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/control-plane/agents?workspace_id=forged", nil)
	req.Header.Set("Authorization", "Bearer mcs_real_token")
	req.Header.Set("X-Workspace-ID", "forged")
	req.Header.Set("X-Service-Principal-ID", "forged")
	req.Header.Set("X-Actor-Source", "member")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if resolver.rawToken != "mcs_real_token" {
		t.Fatalf("resolver token = %q", resolver.rawToken)
	}
}

func TestControlPlaneAuth_RejectsMissingScopeAndNonServiceBearer(t *testing.T) {
	tests := []struct {
		name  string
		token string
		ident ServicePrincipalIdentity
		want  int
	}{
		{name: "missing scope", token: "mcs_valid", ident: ServicePrincipalIdentity{ServicePrincipalID: "sp", WorkspaceID: "ws", Scopes: []string{ControlPlaneTasksRead}}, want: http.StatusForbidden},
		{name: "normal PAT", token: "mul_not_allowed", ident: ServicePrincipalIdentity{ServicePrincipalID: "sp", WorkspaceID: "ws", Scopes: []string{ControlPlaneAgentsRead}}, want: http.StatusUnauthorized},
		{name: "empty workspace", token: "mcs_bad", ident: ServicePrincipalIdentity{ServicePrincipalID: "sp", Scopes: []string{ControlPlaneAgentsRead}}, want: http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &fakeServiceTokenResolver{identity: tt.ident}
			nextCalled := false
			handler := ControlPlaneAuth(resolver, ControlPlaneAgentsRead)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true }))
			req := httptest.NewRequest(http.MethodGet, "/api/control-plane/agents", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tt.want {
				t.Fatalf("status = %d, want %d", w.Code, tt.want)
			}
			if nextCalled {
				t.Fatal("next handler must not be called")
			}
		})
	}
}

func TestControlPlaneAuth_RejectsRevokedOrExpiredResolverTokens(t *testing.T) {
	for _, err := range []error{ErrServiceTokenNotFound, errors.New("database unavailable")} {
		resolver := &fakeServiceTokenResolver{err: err}
		handler := ControlPlaneAuth(resolver, ControlPlaneStatusRead)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("next must not be called") }))
		req := httptest.NewRequest(http.MethodGet, "/api/control-plane/status", nil)
		req.Header.Set("Authorization", "Bearer mcs_revoked_or_expired")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
	}
}
