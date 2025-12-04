package main

import (
	"fmt"
	"os"
	"strings"

	"axonctl/internal/cloudflare"

	"github.com/spf13/cobra"
)

// getCloudflareClient creates a Cloudflare Access client from environment variables.
func getCloudflareClient() (*cloudflare.AccessClient, error) {
	apiToken := os.Getenv("CF_API_TOKEN")
	accountID := os.Getenv("CF_ACCOUNT_ID")
	groupID := os.Getenv("CF_ACCESS_GROUP_ID")

	if apiToken == "" {
		return nil, fmt.Errorf("CF_API_TOKEN environment variable is required")
	}
	if accountID == "" {
		return nil, fmt.Errorf("CF_ACCOUNT_ID environment variable is required")
	}
	if groupID == "" {
		return nil, fmt.Errorf("CF_ACCESS_GROUP_ID environment variable is required")
	}

	return cloudflare.NewAccessClient(apiToken, accountID, groupID), nil
}

// docsGrantCmd returns the command for granting documentation access.
func docsGrantCmd() *cobra.Command {
	var email string
	var reason string
	var notify bool

	cmd := &cobra.Command{
		Use:   "grant",
		Short: "Grant access to protected documentation",
		Long: `Grant access to protected documentation for a specific email address.

The user will receive a one-time PIN via email when they visit the protected docs.

Examples:
  axonctl docs grant --email investor@vc.com --reason "Series A DD"
  axonctl docs grant --email advisor@company.com --notify`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if email == "" {
				return fmt.Errorf("--email is required")
			}

			// Validate email format (basic check)
			if !strings.Contains(email, "@") {
				return fmt.Errorf("invalid email format: %s", email)
			}

			client, err := getCloudflareClient()
			if err != nil {
				return err
			}

			fmt.Printf("Granting documentation access to %s...\n", email)

			if err := client.AddEmail(email); err != nil {
				return fmt.Errorf("failed to grant access: %w", err)
			}

			fmt.Printf("✅ Access granted to %s\n", email)
			if reason != "" {
				fmt.Printf("   Reason: %s\n", reason)
			}
			fmt.Printf("\n📧 Instructions for %s:\n", email)
			fmt.Println("   1. Visit: https://docs.getaxonflow.com/docs/protected/")
			fmt.Println("   2. Enter your email address when prompted")
			fmt.Println("   3. Check your email for a one-time PIN")
			fmt.Println("   4. Enter the PIN to access the documentation")
			fmt.Println("\n   Session duration: 7 days (re-authenticate weekly)")

			if notify {
				fmt.Println("\n📤 Notification: (email notification not yet implemented)")
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&email, "email", "e", "", "Email address to grant access to (required)")
	cmd.Flags().StringVarP(&reason, "reason", "r", "", "Reason for granting access (for audit)")
	cmd.Flags().BoolVarP(&notify, "notify", "n", false, "Send notification email to the user")

	return cmd
}

// docsRevokeCmd returns the command for revoking documentation access.
func docsRevokeCmd() *cobra.Command {
	var email string

	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke access to protected documentation",
		Long: `Revoke access to protected documentation for a specific email address.

The revocation takes effect immediately.

Examples:
  axonctl docs revoke --email investor@vc.com`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if email == "" {
				return fmt.Errorf("--email is required")
			}

			client, err := getCloudflareClient()
			if err != nil {
				return err
			}

			fmt.Printf("Revoking documentation access for %s...\n", email)

			if err := client.RemoveEmail(email); err != nil {
				return fmt.Errorf("failed to revoke access: %w", err)
			}

			fmt.Printf("✅ Access revoked for %s\n", email)
			fmt.Println("   The user will no longer be able to access protected documentation.")

			return nil
		},
	}

	cmd.Flags().StringVarP(&email, "email", "e", "", "Email address to revoke access from (required)")

	return cmd
}

// docsListCmd returns the command for listing documentation access.
func docsListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all users with documentation access",
		Long: `List all email addresses that have been granted access to protected documentation.

Examples:
  axonctl docs list`,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := getCloudflareClient()
			if err != nil {
				return err
			}

			emails, err := client.ListEmails()
			if err != nil {
				return fmt.Errorf("failed to list access: %w", err)
			}

			if len(emails) == 0 {
				fmt.Println("No users have been granted documentation access.")
				return nil
			}

			fmt.Printf("Users with documentation access (%d):\n", len(emails))
			fmt.Println(strings.Repeat("-", 50))
			for i, email := range emails {
				fmt.Printf("%3d. %s\n", i+1, email)
			}
			fmt.Println(strings.Repeat("-", 50))
			fmt.Printf("\nTotal: %d users\n", len(emails))

			return nil
		},
	}

	return cmd
}
