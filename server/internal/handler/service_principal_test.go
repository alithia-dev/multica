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
