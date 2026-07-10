package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/multica-ai/multica/server/internal/auth"
)

const maxServiceTokenLifetimeDays = 365

type ServicePrincipalResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Disabled  bool   `json:"disabled"`
	CreatedAt string `json:"created_at"`
}
type CreateServicePrincipalRequest struct {
	Name string `json:"name"`
}
type IssueServiceTokenRequest struct {
	Scopes        []string `json:"scopes"`
	ExpiresInDays int      `json:"expires_in_days"`
}
type CreateServiceTokenResponse struct {
	ID        string   `json:"id"`
	Token     string   `json:"token"`
	Prefix    string   `json:"token_prefix"`
	Scopes    []string `json:"scopes"`
	ExpiresAt string   `json:"expires_at"`
	CreatedAt string   `json:"created_at"`
}

func (h *Handler) CreateServicePrincipal(w http.ResponseWriter, r *http.Request) {
	workspaceID, ok := parseUUIDOrBadRequest(w, chi.URLParam(r, "id"), "workspace id")
	if !ok {
		return
	}
	var req CreateServicePrincipalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	var row struct {
		ID, Name  string
		Disabled  bool
		CreatedAt time.Time
	}
	err := h.DB.QueryRow(r.Context(), `INSERT INTO service_principal (workspace_id, name) VALUES ($1, $2) RETURNING id::text, name, disabled, created_at`, workspaceID, req.Name).Scan(&row.ID, &row.Name, &row.Disabled, &row.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "service_principal_workspace_id_name_key") {
			writeError(w, http.StatusConflict, "service principal name already exists")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to create service principal")
		}
		return
	}
	writeJSON(w, http.StatusCreated, ServicePrincipalResponse{ID: row.ID, Name: row.Name, Disabled: row.Disabled, CreatedAt: row.CreatedAt.UTC().Format(time.RFC3339)})
}

func (h *Handler) IssueServiceToken(w http.ResponseWriter, r *http.Request) {
	workspaceID, ok := parseUUIDOrBadRequest(w, chi.URLParam(r, "id"), "workspace id")
	if !ok {
		return
	}
	principalID, ok := parseUUIDOrBadRequest(w, chi.URLParam(r, "principalId"), "service principal id")
	if !ok {
		return
	}
	var req IssueServiceTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Scopes) == 0 {
		writeError(w, http.StatusBadRequest, "at least one scope is required")
		return
	}
	if req.ExpiresInDays < 1 || req.ExpiresInDays > maxServiceTokenLifetimeDays {
		writeError(w, http.StatusBadRequest, "expires_in_days must be between 1 and 365")
		return
	}
	var exists bool
	if err := h.DB.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM service_principal WHERE id = $1 AND workspace_id = $2 AND disabled = FALSE)`, principalID, workspaceID).Scan(&exists); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to look up service principal")
		return
	}
	if !exists {
		writeError(w, http.StatusNotFound, "service principal not found")
		return
	}
	raw, err := auth.GenerateServiceToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate service token")
		return
	}
	expiresAt := time.Now().AddDate(0, 0, req.ExpiresInDays)
	prefix := raw[:12]
	var row struct {
		ID        string
		CreatedAt time.Time
	}
	if err := h.DB.QueryRow(r.Context(), `INSERT INTO service_token (service_principal_id, token_hash, token_prefix, scopes, expires_at) VALUES ($1, $2, $3, $4, $5) RETURNING id::text, created_at`, principalID, auth.HashToken(raw), prefix, req.Scopes, expiresAt).Scan(&row.ID, &row.CreatedAt); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to issue service token")
		return
	}
	writeJSON(w, http.StatusCreated, CreateServiceTokenResponse{ID: row.ID, Token: raw, Prefix: prefix, Scopes: req.Scopes, ExpiresAt: expiresAt.UTC().Format(time.RFC3339), CreatedAt: row.CreatedAt.UTC().Format(time.RFC3339)})
}

func (h *Handler) RevokeServiceToken(w http.ResponseWriter, r *http.Request) {
	workspaceID, ok := parseUUIDOrBadRequest(w, chi.URLParam(r, "id"), "workspace id")
	if !ok {
		return
	}
	principalID, ok := parseUUIDOrBadRequest(w, chi.URLParam(r, "principalId"), "service principal id")
	if !ok {
		return
	}
	tokenID, ok := parseUUIDOrBadRequest(w, chi.URLParam(r, "tokenId"), "service token id")
	if !ok {
		return
	}
	var id string
	err := h.DB.QueryRow(r.Context(), `UPDATE service_token st SET revoked = TRUE FROM service_principal sp WHERE st.id = $1 AND st.service_principal_id = $2 AND sp.id = st.service_principal_id AND sp.workspace_id = $3 RETURNING st.id::text`, tokenID, principalID, workspaceID).Scan(&id)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "failed to revoke service token")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
