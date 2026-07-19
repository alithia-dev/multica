package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestNewAPIClient_GritProfileFailsClosedWithoutServiceToken(t *testing.T) {
	t.Setenv("MULTICA_SERVER_URL", "http://multica.test")
	t.Setenv("MULTICA_TOKEN", "mul_human")
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("profile", "grit", "")

	_, err := newAPIClient(cmd)
	if err == nil || !strings.Contains(err.Error(), "requires a service-account msa_ token") {
		t.Fatalf("newAPIClient error = %v, want fail-closed service-token guidance", err)
	}
}

func TestServiceAccountRevokeCLI(t *testing.T) {
	var gotMethod, gotPath, gotWorkspace string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotWorkspace = r.Method, r.URL.Path, r.URL.Query().Get("workspace_id")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	t.Setenv("MULTICA_SERVER_URL", srv.URL)
	t.Setenv("MULTICA_WORKSPACE_ID", "workspace-1")
	t.Setenv("MULTICA_TOKEN", "mul_admin")

	if err := runServiceAccountRevoke(&cobra.Command{Use: "test"}, []string{"service-1"}); err != nil {
		t.Fatalf("runServiceAccountRevoke: %v", err)
	}
	if gotMethod != http.MethodDelete || gotPath != "/api/service-accounts/service-1" || gotWorkspace != "workspace-1" {
		t.Fatalf("request = %s %s workspace=%s", gotMethod, gotPath, gotWorkspace)
	}
}

func TestNewAPIClient_GritProfileAcceptsServiceToken(t *testing.T) {
	t.Setenv("MULTICA_SERVER_URL", "http://multica.test")
	t.Setenv("MULTICA_TOKEN", "msa_service")
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("profile", "grit", "")

	client, err := newAPIClient(cmd)
	if err != nil {
		t.Fatalf("newAPIClient: %v", err)
	}
	if client.Token != "msa_service" {
		t.Fatalf("token = %q", client.Token)
	}
}
