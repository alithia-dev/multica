package main

import (
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
