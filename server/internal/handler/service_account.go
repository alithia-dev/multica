package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/auth"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

var serviceAccountSlugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

type serviceAccountResponse struct {
	ID          string  `json:"id"`
	WorkspaceID string  `json:"workspace_id"`
	Name        string  `json:"name"`
	Slug        string  `json:"slug"`
	AvatarURL   *string `json:"avatar_url"`
	Role        string  `json:"role"`
	CreatedAt   string  `json:"created_at"`
}

func serviceAccountToResponse(a db.ServiceAccount) serviceAccountResponse {
	var avatar *string
	if a.AvatarUrl.Valid {
		avatar = &a.AvatarUrl.String
	}
	return serviceAccountResponse{uuidToString(a.ID), uuidToString(a.WorkspaceID), a.Name, a.Slug, avatar, a.Role, timestampToString(a.CreatedAt)}
}

func (h *Handler) ListServiceAccounts(w http.ResponseWriter, r *http.Request) {
	wsID := h.resolveWorkspaceID(r)
	if _, ok := h.requireWorkspaceMember(w, r, wsID, "workspace not found"); !ok {
		return
	}
	rows, err := h.Queries.ListServiceAccounts(r.Context(), parseUUID(wsID))
	if err != nil {
		writeError(w, 500, "failed to list service accounts")
		return
	}
	resp := make([]serviceAccountResponse, len(rows))
	for i, row := range rows {
		resp[i] = serviceAccountToResponse(row)
	}
	writeJSON(w, 200, resp)
}

func (h *Handler) CreateServiceAccount(w http.ResponseWriter, r *http.Request) {
	wsID := h.resolveWorkspaceID(r)
	if _, ok := h.requireWorkspaceRole(w, r, wsID, "workspace not found", "owner", "admin"); !ok {
		return
	}
	var req struct {
		Name      string `json:"name"`
		Slug      string `json:"slug"`
		AvatarURL string `json:"avatar_url"`
		Role      string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "invalid request body")
		return
	}
	req.Name, req.Slug, req.Role = strings.TrimSpace(req.Name), strings.TrimSpace(req.Slug), strings.TrimSpace(req.Role)
	if req.Name == "" || !serviceAccountSlugPattern.MatchString(req.Slug) {
		writeError(w, 400, "name and valid slug are required")
		return
	}
	if req.Role == "" {
		req.Role = "member"
	}
	if req.Role != "member" && req.Role != "admin" {
		writeError(w, 400, "role must be member or admin")
		return
	}
	a, err := h.Queries.CreateServiceAccount(r.Context(), db.CreateServiceAccountParams{WorkspaceID: parseUUID(wsID), Name: req.Name, Slug: req.Slug, AvatarUrl: pgtype.Text{String: req.AvatarURL, Valid: req.AvatarURL != ""}, Role: req.Role, CreatedByUserID: parseUUID(requestUserID(r))})
	if err != nil {
		writeError(w, 409, "service account slug already exists")
		return
	}
	writeJSON(w, 201, serviceAccountToResponse(a))
}

func (h *Handler) CreateServiceAccountToken(w http.ResponseWriter, r *http.Request) {
	wsID := h.resolveWorkspaceID(r)
	if _, ok := h.requireWorkspaceRole(w, r, wsID, "workspace not found", "owner", "admin"); !ok {
		return
	}
	aID, ok := parseUUIDOrBadRequest(w, chi.URLParam(r, "id"), "service account id")
	if !ok {
		return
	}
	a, err := h.Queries.GetServiceAccount(r.Context(), aID)
	if err != nil || uuidToString(a.WorkspaceID) != wsID {
		writeError(w, 404, "service account not found")
		return
	}
	var req struct {
		Name          string `json:"name"`
		ExpiresInDays *int   `json:"expires_in_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		writeError(w, 400, "name is required")
		return
	}
	raw, err := auth.GenerateServiceAccountToken()
	if err != nil {
		writeError(w, 500, "failed to generate token")
		return
	}
	var expires pgtype.Timestamptz
	if req.ExpiresInDays != nil && *req.ExpiresInDays > 0 {
		expires = pgtype.Timestamptz{Time: time.Now().Add(time.Duration(*req.ExpiresInDays) * 24 * time.Hour), Valid: true}
	}
	prefix := raw
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	t, err := h.Queries.CreateServiceAccountToken(r.Context(), db.CreateServiceAccountTokenParams{ServiceAccountID: aID, Name: strings.TrimSpace(req.Name), TokenHash: auth.HashToken(raw), TokenPrefix: prefix, ExpiresAt: expires})
	if err != nil {
		writeError(w, 500, "failed to create token")
		return
	}
	writeJSON(w, 201, map[string]any{"id": uuidToString(t.ID), "service_account_id": uuidToString(t.ServiceAccountID), "name": t.Name, "token_prefix": t.TokenPrefix, "expires_at": timestampToPtr(t.ExpiresAt), "token": raw})
}

func (h *Handler) RevokeServiceAccountToken(w http.ResponseWriter, r *http.Request) {
	wsID := h.resolveWorkspaceID(r)
	if _, ok := h.requireWorkspaceRole(w, r, wsID, "workspace not found", "owner", "admin"); !ok {
		return
	}
	aID, ok := parseUUIDOrBadRequest(w, chi.URLParam(r, "id"), "service account id")
	if !ok {
		return
	}
	a, err := h.Queries.GetServiceAccount(r.Context(), aID)
	if err != nil || uuidToString(a.WorkspaceID) != wsID {
		writeError(w, 404, "service account not found")
		return
	}
	tID, ok := parseUUIDOrBadRequest(w, chi.URLParam(r, "tokenId"), "token id")
	if !ok {
		return
	}
	_, err = h.Queries.RevokeServiceAccountToken(r.Context(), db.RevokeServiceAccountTokenParams{ID: tID, ServiceAccountID: aID})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 500, "failed to revoke token")
		return
	}
	w.WriteHeader(204)
}
