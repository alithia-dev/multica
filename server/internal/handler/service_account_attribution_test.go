package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/multica-ai/multica/server/internal/middleware"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

// TestWriteAttributionMatrix exercises the real issue-create, issue-update
// (status + assignment), and comment-create handlers for every interactive
// principal class. Resolver-only tests cannot catch a handler that forgets to
// use the resolved actor on one of these write paths.
func TestWriteAttributionMatrix(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	ctx := context.Background()

	var serviceID string
	if err := testPool.QueryRow(ctx, `
		INSERT INTO service_account (workspace_id, name, slug, role, created_by_user_id)
		VALUES ($1, 'Matrix Service', 'matrix-service', 'member', $2) RETURNING id
	`, testWorkspaceID, testUserID).Scan(&serviceID); err != nil {
		t.Fatalf("create service account: %v", err)
	}
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM service_account WHERE id=$1`, serviceID) })

	agentID := createHandlerTestAgent(t, "service-attribution-matrix-agent", nil)
	var taskID string
	if err := testPool.QueryRow(ctx, `
		INSERT INTO agent_task_queue (agent_id, runtime_id, status, priority, originator_user_id, accountable_user_id)
		VALUES ($1, (SELECT runtime_id FROM agent WHERE id=$1), 'running', 0, $2, $2) RETURNING id
	`, agentID, testUserID).Scan(&taskID); err != nil {
		t.Fatalf("create task: %v", err)
	}

	cases := []struct {
		name, wantType, wantID string
		decorate               func(*http.Request) *http.Request
	}{
		{"member", "member", testUserID, func(r *http.Request) *http.Request { return r }},
		{"service", "service_account", serviceID, func(r *http.Request) *http.Request {
			r.Header.Set("X-Actor-Source", "service_account")
			r.Header.Set("X-Service-Account-ID", serviceID)
			r.Header.Set("X-Service-Account-Role", "member")
			r.Header.Set("X-User-ID", serviceID)
			member := db.Member{ID: parseUUID(serviceID), UserID: parseUUID(serviceID), WorkspaceID: parseUUID(testWorkspaceID), Role: "member"}
			return r.WithContext(middleware.SetMemberContext(r.Context(), testWorkspaceID, member))
		}},
		{"task_agent", "agent", agentID, func(r *http.Request) *http.Request {
			r.Header.Set("X-Agent-ID", agentID)
			r.Header.Set("X-Task-ID", taskID)
			return r
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := tc.decorate(newRequest("POST", "/api/issues?workspace_id="+testWorkspaceID, map[string]any{"title": "attribution matrix " + tc.name}))
			testHandler.CreateIssue(w, r)
			if w.Code != http.StatusCreated {
				t.Fatalf("create: %d %s", w.Code, w.Body.String())
			}
			var issue IssueResponse
			if err := json.NewDecoder(w.Body).Decode(&issue); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				testPool.Exec(context.Background(), `DELETE FROM agent_task_queue WHERE issue_id=$1`, issue.ID)
				testPool.Exec(context.Background(), `DELETE FROM comment WHERE issue_id=$1`, issue.ID)
				testPool.Exec(context.Background(), `DELETE FROM activity_log WHERE issue_id=$1`, issue.ID)
				testPool.Exec(context.Background(), `DELETE FROM issue WHERE id=$1`, issue.ID)
			})

			var creatorType, creatorID string
			if err := testPool.QueryRow(ctx, `SELECT creator_type, creator_id FROM issue WHERE id=$1`, issue.ID).Scan(&creatorType, &creatorID); err != nil {
				t.Fatal(err)
			}
			if creatorType != tc.wantType || creatorID != tc.wantID {
				t.Fatalf("creator=(%s,%s), want (%s,%s)", creatorType, creatorID, tc.wantType, tc.wantID)
			}

			w = httptest.NewRecorder()
			r = tc.decorate(newRequest("PUT", "/api/issues/"+issue.ID, map[string]any{"status": "in_progress", "assignee_type": "member", "assignee_id": testUserID}))
			r = withURLParam(r, "id", issue.ID)
			testHandler.UpdateIssue(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("update: %d %s", w.Code, w.Body.String())
			}
			var activityCount int
			if err := testPool.QueryRow(ctx, `SELECT count(*) FROM activity_log WHERE issue_id=$1 AND actor_type=$2 AND actor_id=$3 AND action IN ('status_changed','assignee_changed')`, issue.ID, tc.wantType, tc.wantID).Scan(&activityCount); err != nil {
				t.Fatal(err)
			}
			if activityCount == 0 {
				t.Fatalf("no status/assignment update attributed to (%s,%s)", tc.wantType, tc.wantID)
			}

			w = httptest.NewRecorder()
			r = tc.decorate(newRequest("POST", "/api/issues/"+issue.ID+"/comments", map[string]any{"content": "matrix comment"}))
			r = withURLParam(r, "id", issue.ID)
			testHandler.CreateComment(w, r)
			if w.Code != http.StatusCreated {
				t.Fatalf("comment: %d %s", w.Code, w.Body.String())
			}
			var authorType, authorID string
			if err := testPool.QueryRow(ctx, `SELECT author_type, author_id FROM comment WHERE issue_id=$1 AND content='matrix comment'`, issue.ID).Scan(&authorType, &authorID); err != nil {
				t.Fatal(err)
			}
			if authorType != tc.wantType || authorID != tc.wantID {
				t.Fatalf("author=(%s,%s), want (%s,%s)", authorType, authorID, tc.wantType, tc.wantID)
			}
		})
	}
}
