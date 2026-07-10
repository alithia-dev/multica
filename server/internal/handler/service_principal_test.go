package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/multica-ai/multica/server/internal/auth"
)

func servicePrincipalRequest(method, path string, body any, params map[string]string) *http.Request {
	req := newRequest(method, path, body)
	routeCtx := chi.NewRouteContext()
	for key, value := range params {
		routeCtx.URLParams.Add(key, value)
	}
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
}

func TestServicePrincipalTokenLifecycle(t *testing.T) {
	create := httptest.NewRecorder()
	testHandler.CreateServicePrincipal(create, servicePrincipalRequest(http.MethodPost,
		"/api/workspaces/"+testWorkspaceID+"/service-principals",
		map[string]any{"name": "build-bot"}, map[string]string{"id": testWorkspaceID}))
	if create.Code != http.StatusCreated {
		t.Fatalf("create service principal: want 201, got %d: %s", create.Code, create.Body.String())
	}

	var principal ServicePrincipalResponse
	if err := json.NewDecoder(create.Body).Decode(&principal); err != nil {
		t.Fatalf("decode principal: %v", err)
	}
	if principal.ID == "" || principal.Name != "build-bot" {
		t.Fatalf("unexpected principal response: %#v", principal)
	}
	t.Cleanup(func() {
		testPool.Exec(context.Background(), `DELETE FROM service_principal WHERE id = $1`, parseUUID(principal.ID))
	})

	issue := httptest.NewRecorder()
	testHandler.IssueServiceToken(issue, servicePrincipalRequest(http.MethodPost,
		"/api/workspaces/"+testWorkspaceID+"/service-principals/"+principal.ID+"/tokens",
		map[string]any{
			"scopes":          []string{"control_plane.agents.read", "control_plane.status.read"},
			"expires_in_days": 7,
		}, map[string]string{"id": testWorkspaceID, "principalId": principal.ID}))
	if issue.Code != http.StatusCreated {
		t.Fatalf("issue service token: want 201, got %d: %s", issue.Code, issue.Body.String())
	}

	var token CreateServiceTokenResponse
	if err := json.NewDecoder(issue.Body).Decode(&token); err != nil {
		t.Fatalf("decode issued token: %v", err)
	}
	if token.ID == "" || token.Token == "" || len(token.Token) < 4 || token.Token[:4] != "mcs_" {
		t.Fatalf("expected one-time mcs_ token, got %#v", token)
	}
	if token.ExpiresAt == "" {
		t.Fatal("issued token must have an expiry")
	}

	var storedHash string
	var expiresAt time.Time
	if err := testPool.QueryRow(context.Background(), `SELECT token_hash, expires_at FROM service_token WHERE id = $1`, parseUUID(token.ID)).Scan(&storedHash, &expiresAt); err != nil {
		t.Fatalf("read issued token: %v", err)
	}
	if storedHash != auth.HashToken(token.Token) || storedHash == token.Token {
		t.Fatalf("token must be stored only as a hash")
	}
	if expiresAt.Before(time.Now().Add(6 * 24 * time.Hour)) {
		t.Fatalf("expiry too soon: %s", expiresAt)
	}

	if err := testHandler.Queries.UpdateServiceTokenLastUsed(context.Background(), parseUUID(token.ID)); err != nil {
		t.Fatalf("record token use: %v", err)
	}
	var firstLastUsed time.Time
	if err := testPool.QueryRow(context.Background(), `SELECT last_used_at FROM service_token WHERE id = $1`, parseUUID(token.ID)).Scan(&firstLastUsed); err != nil {
		t.Fatalf("read recorded token use: %v", err)
	}
	if err := testHandler.Queries.UpdateServiceTokenLastUsed(context.Background(), parseUUID(token.ID)); err != nil {
		t.Fatalf("record repeated token use: %v", err)
	}
	var repeatedLastUsed time.Time
	if err := testPool.QueryRow(context.Background(), `SELECT last_used_at FROM service_token WHERE id = $1`, parseUUID(token.ID)).Scan(&repeatedLastUsed); err != nil {
		t.Fatalf("read repeated token use: %v", err)
	}
	if !repeatedLastUsed.Equal(firstLastUsed) {
		t.Fatalf("last-used update must be rate-bounded: first=%s repeated=%s", firstLastUsed, repeatedLastUsed)
	}

	revoke := httptest.NewRecorder()
	testHandler.RevokeServiceToken(revoke, servicePrincipalRequest(http.MethodDelete,
		"/api/workspaces/"+testWorkspaceID+"/service-principals/"+principal.ID+"/tokens/"+token.ID,
		nil, map[string]string{"id": testWorkspaceID, "principalId": principal.ID, "tokenId": token.ID}))
	if revoke.Code != http.StatusNoContent {
		t.Fatalf("revoke service token: want 204, got %d: %s", revoke.Code, revoke.Body.String())
	}

	var revoked bool
	if err := testPool.QueryRow(context.Background(), `SELECT revoked FROM service_token WHERE id = $1`, parseUUID(token.ID)).Scan(&revoked); err != nil {
		t.Fatalf("read revoked token: %v", err)
	}
	if !revoked {
		t.Fatal("service token was not revoked")
	}
}

func TestServicePrincipalAdminLifecycleAndScopeValidation(t *testing.T) {
	create := httptest.NewRecorder()
	testHandler.CreateServicePrincipal(create, servicePrincipalRequest(http.MethodPost,
		"/api/workspaces/"+testWorkspaceID+"/service-principals", map[string]any{"name": "review-bot"}, map[string]string{"id": testWorkspaceID}))
	if create.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", create.Code, create.Body.String())
	}
	var principal ServicePrincipalResponse
	if err := json.NewDecoder(create.Body).Decode(&principal); err != nil {
		t.Fatalf("decode principal: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM service_principal WHERE id = $1`, parseUUID(principal.ID))
	})

	list := httptest.NewRecorder()
	testHandler.ListServicePrincipals(list, servicePrincipalRequest(http.MethodGet,
		"/api/workspaces/"+testWorkspaceID+"/service-principals", nil, map[string]string{"id": testWorkspaceID}))
	if list.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d: %s", list.Code, list.Body.String())
	}
	var principals []ServicePrincipalResponse
	if err := json.NewDecoder(list.Body).Decode(&principals); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	found := false
	for _, got := range principals {
		if got.ID == principal.ID && !got.Disabled {
			found = true
		}
	}
	if !found {
		t.Fatalf("created principal missing from list: %#v", principals)
	}

	setDisabled := func(disabled bool) ServicePrincipalResponse {
		w := httptest.NewRecorder()
		testHandler.UpdateServicePrincipal(w, servicePrincipalRequest(http.MethodPatch,
			"/api/workspaces/"+testWorkspaceID+"/service-principals/"+principal.ID, map[string]any{"disabled": disabled}, map[string]string{"id": testWorkspaceID, "principalId": principal.ID}))
		if w.Code != http.StatusOK {
			t.Fatalf("set disabled=%t: want 200, got %d: %s", disabled, w.Code, w.Body.String())
		}
		var updated ServicePrincipalResponse
		if err := json.NewDecoder(w.Body).Decode(&updated); err != nil {
			t.Fatalf("decode update: %v", err)
		}
		return updated
	}
	if updated := setDisabled(true); !updated.Disabled {
		t.Fatalf("expected disabled principal: %#v", updated)
	}
	if updated := setDisabled(false); updated.Disabled {
		t.Fatalf("expected re-enabled principal: %#v", updated)
	}

	for _, tt := range []struct {
		name   string
		scopes []string
		want   int
	}{
		{"unknown scope", []string{"control_plane.admin.write"}, http.StatusBadRequest},
		{"duplicate scope", []string{"control_plane.agents.read", "control_plane.agents.read"}, http.StatusBadRequest},
		{"allowed scope", []string{"control_plane.agents.read"}, http.StatusCreated},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			testHandler.IssueServiceToken(w, servicePrincipalRequest(http.MethodPost,
				"/api/workspaces/"+testWorkspaceID+"/service-principals/"+principal.ID+"/tokens", map[string]any{"scopes": tt.scopes, "expires_in_days": 7}, map[string]string{"id": testWorkspaceID, "principalId": principal.ID}))
			if w.Code != tt.want {
				t.Fatalf("issue %s: want %d, got %d: %s", tt.name, tt.want, w.Code, w.Body.String())
			}
		})
	}
}
