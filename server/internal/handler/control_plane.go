package handler

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/util"
)

type controlPlaneAgent struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

type controlPlaneTask struct {
	ID          string  `json:"id"`
	AgentID     string  `json:"agent_id"`
	Status      string  `json:"status"`
	Priority    int32   `json:"priority"`
	CreatedAt   string  `json:"created_at"`
	StartedAt   *string `json:"started_at,omitempty"`
	CompletedAt *string `json:"completed_at,omitempty"`
}

func controlPlaneWorkspaceID(r *http.Request) (pgtype.UUID, bool) {
	id, err := util.ParseUUID(r.Header.Get("X-Workspace-ID"))
	return id, err == nil
}

func (h *Handler) ControlPlaneAgents(w http.ResponseWriter, r *http.Request) {
	workspaceID, ok := controlPlaneWorkspaceID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid service workspace")
		return
	}
	rows, err := h.DB.Query(r.Context(), `SELECT id, name, status, created_at FROM agent WHERE workspace_id = $1 AND archived_at IS NULL ORDER BY created_at ASC`, workspaceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list control-plane agents")
		return
	}
	defer rows.Close()
	out := []controlPlaneAgent{}
	for rows.Next() {
		var id pgtype.UUID
		var item controlPlaneAgent
		var created time.Time
		if err := rows.Scan(&id, &item.Name, &item.Status, &created); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to read control-plane agents")
			return
		}
		item.ID = util.UUIDToString(id)
		item.CreatedAt = created.UTC().Format(time.RFC3339)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read control-plane agents")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) ControlPlaneTasks(w http.ResponseWriter, r *http.Request) {
	workspaceID, ok := controlPlaneWorkspaceID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid service workspace")
		return
	}
	rows, err := h.DB.Query(r.Context(), `SELECT t.id, t.agent_id, t.status, t.priority, t.created_at, t.started_at, t.completed_at FROM agent_task_queue t JOIN agent a ON a.id = t.agent_id WHERE a.workspace_id = $1 ORDER BY t.created_at DESC LIMIT 100`, workspaceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list control-plane tasks")
		return
	}
	defer rows.Close()
	out := []controlPlaneTask{}
	for rows.Next() {
		var id, agentID pgtype.UUID
		var item controlPlaneTask
		var created time.Time
		var started, completed pgtype.Timestamptz
		if err := rows.Scan(&id, &agentID, &item.Status, &item.Priority, &created, &started, &completed); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to read control-plane tasks")
			return
		}
		item.ID, item.AgentID, item.CreatedAt = util.UUIDToString(id), util.UUIDToString(agentID), created.UTC().Format(time.RFC3339)
		if started.Valid {
			s := started.Time.UTC().Format(time.RFC3339)
			item.StartedAt = &s
		}
		if completed.Valid {
			s := completed.Time.UTC().Format(time.RFC3339)
			item.CompletedAt = &s
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read control-plane tasks")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) ControlPlaneBrief(w http.ResponseWriter, r *http.Request) {
	workspaceID, ok := controlPlaneWorkspaceID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid service workspace")
		return
	}
	var name, slug, description string
	if err := h.DB.QueryRow(r.Context(), `SELECT name, slug, description FROM workspace WHERE id = $1`, workspaceID).Scan(&name, &slug, &description); err != nil {
		writeError(w, http.StatusNotFound, "workspace not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"workspace_id": util.UUIDToString(workspaceID), "name": name, "slug": slug, "description": description})
}

func (h *Handler) ControlPlaneStatus(w http.ResponseWriter, r *http.Request) {
	workspaceID, ok := controlPlaneWorkspaceID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid service workspace")
		return
	}
	var agents, queued, running int64
	err := h.DB.QueryRow(r.Context(), `SELECT (SELECT count(*) FROM agent WHERE workspace_id = $1 AND archived_at IS NULL), (SELECT count(*) FROM agent_task_queue t JOIN agent a ON a.id = t.agent_id WHERE a.workspace_id = $1 AND t.status = 'queued'), (SELECT count(*) FROM agent_task_queue t JOIN agent a ON a.id = t.agent_id WHERE a.workspace_id = $1 AND t.status IN ('running', 'in_progress'))`, workspaceID).Scan(&agents, &queued, &running)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read control-plane status")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"agents": agents, "queued_tasks": queued, "running_tasks": running})
}
