package main

import (
	"context"
	"fmt"
	"os"

	"github.com/multica-ai/multica/server/internal/cli"
	"github.com/spf13/cobra"
)

var serviceAccountCmd = &cobra.Command{Use: "service-account", Short: "Manage workspace service accounts"}
var serviceAccountListCmd = &cobra.Command{Use: "list", Args: exactArgs(0), RunE: runServiceAccountList}
var serviceAccountCreateCmd = &cobra.Command{Use: "create", Args: exactArgs(0), RunE: runServiceAccountCreate}
var serviceAccountTokenCmd = &cobra.Command{Use: "token", Short: "Manage service-account tokens"}
var serviceAccountTokenCreateCmd = &cobra.Command{Use: "create <service-account-id>", Args: exactArgs(1), RunE: runServiceAccountTokenCreate}
var serviceAccountTokenRevokeCmd = &cobra.Command{Use: "revoke <service-account-id> <token-id>", Args: exactArgs(2), RunE: runServiceAccountTokenRevoke}

func init() {
	serviceAccountCmd.AddCommand(serviceAccountListCmd, serviceAccountCreateCmd, serviceAccountTokenCmd)
	serviceAccountTokenCmd.AddCommand(serviceAccountTokenCreateCmd, serviceAccountTokenRevokeCmd)
	serviceAccountCreateCmd.Flags().String("name", "", "Display name (required)")
	serviceAccountCreateCmd.Flags().String("slug", "", "Workspace-unique slug (required)")
	serviceAccountCreateCmd.Flags().String("role", "member", "Role: member or admin")
	serviceAccountTokenCreateCmd.Flags().String("name", "", "Token name (required)")
	serviceAccountTokenCreateCmd.Flags().Int("expires-in-days", 90, "Token lifetime in days; 0 means no expiry")
}

func serviceAccountClient(cmd *cobra.Command) (*cli.APIClient, context.Context, context.CancelFunc, error) {
	c, err := newAPIClient(cmd)
	if err != nil {
		return nil, nil, nil, err
	}
	if c.WorkspaceID == "" {
		return nil, nil, nil, fmt.Errorf("workspace is required; pass --workspace-id")
	}
	ctx, cancel := cli.APIContext(context.Background())
	return c, ctx, cancel, nil
}

func runServiceAccountList(cmd *cobra.Command, _ []string) error {
	c, ctx, cancel, err := serviceAccountClient(cmd)
	if err != nil {
		return err
	}
	defer cancel()
	var out []map[string]any
	if err := c.GetJSON(ctx, "/api/service-accounts?workspace_id="+c.WorkspaceID, &out); err != nil {
		return err
	}
	return cli.PrintJSON(os.Stdout, out)
}

func runServiceAccountCreate(cmd *cobra.Command, _ []string) error {
	c, ctx, cancel, err := serviceAccountClient(cmd)
	if err != nil {
		return err
	}
	defer cancel()
	name, _ := cmd.Flags().GetString("name")
	slug, _ := cmd.Flags().GetString("slug")
	role, _ := cmd.Flags().GetString("role")
	if name == "" || slug == "" {
		return fmt.Errorf("--name and --slug are required")
	}
	var out map[string]any
	if err := c.PostJSON(ctx, "/api/service-accounts?workspace_id="+c.WorkspaceID, map[string]any{"name": name, "slug": slug, "role": role}, &out); err != nil {
		return err
	}
	return cli.PrintJSON(os.Stdout, out)
}

func runServiceAccountTokenCreate(cmd *cobra.Command, args []string) error {
	c, ctx, cancel, err := serviceAccountClient(cmd)
	if err != nil {
		return err
	}
	defer cancel()
	name, _ := cmd.Flags().GetString("name")
	days, _ := cmd.Flags().GetInt("expires-in-days")
	if name == "" {
		return fmt.Errorf("--name is required")
	}
	var out map[string]any
	path := "/api/service-accounts/" + args[0] + "/tokens?workspace_id=" + c.WorkspaceID
	if err := c.PostJSON(ctx, path, map[string]any{"name": name, "expires_in_days": days}, &out); err != nil {
		return err
	}
	return cli.PrintJSON(os.Stdout, out)
}

func runServiceAccountTokenRevoke(cmd *cobra.Command, args []string) error {
	c, ctx, cancel, err := serviceAccountClient(cmd)
	if err != nil {
		return err
	}
	defer cancel()
	path := "/api/service-accounts/" + args[0] + "/tokens/" + args[1] + "?workspace_id=" + c.WorkspaceID
	return c.DeleteJSON(ctx, path)
}
