package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"axonctl/internal/axonflow"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// getAxonFlowClient creates an AxonFlow API client from environment variables.
func getAxonFlowClient() (*axonflow.Client, error) {
	endpoint := os.Getenv("AXONFLOW_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}

	clientID := os.Getenv("AXONFLOW_CLIENT_ID")
	if clientID == "" {
		return nil, fmt.Errorf("AXONFLOW_CLIENT_ID environment variable is required")
	}

	clientSecret := os.Getenv("AXONFLOW_CLIENT_SECRET")
	if clientSecret == "" {
		return nil, fmt.Errorf("AXONFLOW_CLIENT_SECRET environment variable is required")
	}

	return axonflow.NewClient(endpoint, clientID, clientSecret), nil
}

// executionsCmd returns the executions subcommand.
func executionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "executions",
		Aliases: []string{"exec"},
		Short:   "Manage and inspect workflow executions",
		Long: `View, replay, and export workflow execution data.

The executions command provides tools for debugging, auditing, and
compliance review of AI workflow executions captured by AxonFlow.

Environment variables:
  AXONFLOW_ENDPOINT       Agent endpoint (default: http://localhost:8080)
  AXONFLOW_CLIENT_ID      Client ID (required)
  AXONFLOW_CLIENT_SECRET  Client secret (required)`,
	}

	cmd.AddCommand(executionsListCmd())
	cmd.AddCommand(executionsGetCmd())
	cmd.AddCommand(executionsReplayCmd())
	cmd.AddCommand(executionsExportCmd())

	return cmd
}

// executionsListCmd returns the list subcommand.
func executionsListCmd() *cobra.Command {
	var (
		limit      int
		offset     int
		status     string
		workflowID string
		format     string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List workflow executions",
		Long: `List workflow executions with optional filtering and pagination.

Examples:
  axonctl executions list
  axonctl executions list --limit 20 --status completed
  axonctl executions list --workflow-id my-workflow --format json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := getAxonFlowClient()
			if err != nil {
				return err
			}

			resp, err := client.ListExecutions(axonflow.ListOptions{
				Limit:      limit,
				Offset:     offset,
				Status:     status,
				WorkflowID: workflowID,
			})
			if err != nil {
				return fmt.Errorf("listing executions: %w", err)
			}

			if format == "json" {
				return printJSON(resp)
			}

			if len(resp.Executions) == 0 {
				fmt.Println("No executions found.")
				fmt.Println("\nTo generate executions, run a workflow through AxonFlow.")
				fmt.Println("See: examples/execution-replay/ for SDK examples.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tWORKFLOW\tSTATUS\tSTEPS\tDURATION\tCOST")
			fmt.Fprintln(w, "--\t--------\t------\t-----\t--------\t----")
			for _, e := range resp.Executions {
				duration := "-"
				if e.DurationMs != nil {
					duration = formatDuration(*e.DurationMs)
				}
				cost := fmt.Sprintf("$%.4f", e.TotalCostUSD)
				workflow := e.WorkflowName
				if workflow == "" {
					workflow = "-"
				}
				steps := fmt.Sprintf("%d/%d", e.CompletedSteps, e.TotalSteps)
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					truncateID(e.RequestID), workflow, string(e.Status), steps, duration, cost)
			}
			w.Flush()
			fmt.Printf("\nShowing %d of %d executions (offset %d)\n", len(resp.Executions), resp.Total, resp.Offset)

			return nil
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 20, "Maximum number of results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset for pagination")
	cmd.Flags().StringVar(&status, "status", "", "Filter by status (pending, running, completed, failed)")
	cmd.Flags().StringVar(&workflowID, "workflow-id", "", "Filter by workflow ID")
	cmd.Flags().StringVar(&format, "format", "table", "Output format (table, json)")

	return cmd
}

// executionsGetCmd returns the get subcommand.
func executionsGetCmd() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "get <execution-id>",
		Short: "Get execution details",
		Long: `Get detailed information about a specific workflow execution.

Shows the execution summary, all steps with timing, and policy events.

Examples:
  axonctl executions get exec-abc123
  axonctl executions get exec-abc123 --format json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := getAxonFlowClient()
			if err != nil {
				return err
			}

			exec, err := client.GetExecution(args[0])
			if err != nil {
				return fmt.Errorf("getting execution: %w", err)
			}

			if format == "json" {
				return printJSON(exec)
			}

			printExecutionDetail(exec)
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "table", "Output format (table, json)")

	return cmd
}

// executionsReplayCmd returns the replay subcommand.
func executionsReplayCmd() *cobra.Command {
	var showIO bool

	cmd := &cobra.Command{
		Use:   "replay <execution-id>",
		Short: "Replay execution step by step",
		Long: `Replay a workflow execution interactively, stepping through each stage.

Press Enter to advance to the next step. Each step shows timing,
LLM details, and policy events.

Examples:
  axonctl executions replay exec-abc123
  axonctl executions replay exec-abc123 --show-io`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := getAxonFlowClient()
			if err != nil {
				return err
			}

			exec, err := client.GetExecution(args[0])
			if err != nil {
				return fmt.Errorf("getting execution: %w", err)
			}

			return replayExecution(exec, showIO)
		},
	}

	cmd.Flags().BoolVar(&showIO, "show-io", false, "Show full input/output for each step")

	return cmd
}

// executionsExportCmd returns the export subcommand.
func executionsExportCmd() *cobra.Command {
	var (
		output    string
		includeIO bool
	)

	cmd := &cobra.Command{
		Use:   "export <execution-id>",
		Short: "Export execution data",
		Long: `Export execution data to a JSON file for compliance and auditing.

Examples:
  axonctl executions export exec-abc123
  axonctl executions export exec-abc123 --output report.json
  axonctl executions export exec-abc123 --include-io`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := getAxonFlowClient()
			if err != nil {
				return err
			}

			data, err := client.ExportExecution(args[0], includeIO)
			if err != nil {
				return fmt.Errorf("exporting execution: %w", err)
			}

			// Pretty-print the JSON
			var formatted bytes.Buffer
			if err := json.Indent(&formatted, data, "", "  "); err != nil {
				return fmt.Errorf("formatting export data: %w", err)
			}

			if output == "" {
				output = fmt.Sprintf("execution-%s.json", args[0])
			}

			if err := os.WriteFile(output, formatted.Bytes(), 0644); err != nil {
				return fmt.Errorf("writing file: %w", err)
			}

			fmt.Printf("Exported execution %s to %s (%d bytes)\n", args[0], output, formatted.Len())
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path (default: execution-<id>.json)")
	cmd.Flags().BoolVar(&includeIO, "include-io", false, "Include full input/output data")

	return cmd
}

// printExecutionDetail prints formatted execution details.
func printExecutionDetail(exec *axonflow.Execution) {
	s := exec.Summary
	bold := color.New(color.Bold)

	bold.Println("Execution Summary")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  ID:       %s\n", s.RequestID)
	fmt.Printf("  Workflow: %s\n", defaultStr(s.WorkflowName, "-"))
	fmt.Printf("  Status:   %s\n", colorStatus(string(s.Status)))
	fmt.Printf("  Steps:    %d/%d completed\n", s.CompletedSteps, s.TotalSteps)
	if s.DurationMs != nil {
		fmt.Printf("  Duration: %s\n", formatDuration(*s.DurationMs))
	}
	fmt.Printf("  Tokens:   %d\n", s.TotalTokens)
	fmt.Printf("  Cost:     $%.4f\n", s.TotalCostUSD)
	fmt.Printf("  Started:  %s\n", s.StartedAt.Format(time.RFC3339))
	if s.ErrorMessage != "" {
		fmt.Printf("  Error:    %s\n", color.RedString(s.ErrorMessage))
	}

	if len(exec.Steps) > 0 {
		fmt.Println()
		bold.Println("Steps")
		fmt.Println(strings.Repeat("-", 60))
		for _, step := range exec.Steps {
			printStep(step, false)
		}
	}

	// Collect all policy events from steps
	var policyEvents []axonflow.PolicyEvent
	for _, step := range exec.Steps {
		policyEvents = append(policyEvents, step.PoliciesTriggered...)
	}
	if len(policyEvents) > 0 {
		fmt.Println()
		bold.Println("Policy Events")
		fmt.Println(strings.Repeat("-", 60))
		for _, pe := range policyEvents {
			name := pe.PolicyName
			if name == "" {
				name = pe.PolicyID
			}
			fmt.Printf("  [%s] %s - %s (resolution: %s)\n",
				pe.Action, name, pe.Matched, pe.Resolution)
		}
	}
}

// printStep prints a single step.
func printStep(step axonflow.ExecutionSnapshot, showIO bool) {
	status := colorStatus(string(step.Status))
	duration := "-"
	if step.DurationMs != nil {
		duration = formatDuration(*step.DurationMs)
	}

	fmt.Printf("  %d. [%s] %s  (%s)", step.StepIndex+1, status, step.StepName, duration)
	if step.Provider != "" {
		fmt.Printf("  [%s/%s]", step.Provider, step.Model)
	}
	if step.TokensIn > 0 || step.TokensOut > 0 {
		fmt.Printf("  tokens: %d in / %d out", step.TokensIn, step.TokensOut)
	}
	fmt.Println()

	if step.ErrorMessage != "" {
		fmt.Printf("     Error: %s\n", color.RedString(step.ErrorMessage))
	}

	if len(step.PoliciesTriggered) > 0 {
		for _, pe := range step.PoliciesTriggered {
			fmt.Printf("     Policy: [%s] %s\n", pe.Action, pe.Matched)
		}
	}

	if showIO {
		if len(step.Input) > 0 {
			fmt.Printf("     Input:  %s\n", truncateJSON(step.Input, 200))
		}
		if len(step.Output) > 0 {
			fmt.Printf("     Output: %s\n", truncateJSON(step.Output, 200))
		}
	}
}

// replayExecution replays an execution interactively.
func replayExecution(exec *axonflow.Execution, showIO bool) error {
	s := exec.Summary
	bold := color.New(color.Bold)
	reader := bufio.NewReader(os.Stdin)

	bold.Printf("Replaying: %s", s.RequestID)
	if s.WorkflowName != "" {
		fmt.Printf(" (%s)", s.WorkflowName)
	}
	fmt.Printf("\nStatus: %s | Steps: %d | Cost: $%.4f\n",
		colorStatus(string(s.Status)), s.TotalSteps, s.TotalCostUSD)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Press Enter to advance through steps...")
	fmt.Println()

	for i, step := range exec.Steps {
		fmt.Printf("--- Step %d/%d ---\n", i+1, len(exec.Steps))
		printStep(step, showIO)
		fmt.Println()

		if i < len(exec.Steps)-1 {
			fmt.Print("Press Enter for next step (q to quit)... ")
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)
			if input == "q" || input == "Q" {
				fmt.Println("Replay stopped.")
				return nil
			}
		}
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Replay complete.")
	if s.DurationMs != nil {
		fmt.Printf("Total execution time: %s\n", formatDuration(*s.DurationMs))
	}

	return nil
}

// Helper functions

func formatDuration(ms int) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	if ms < 60000 {
		return fmt.Sprintf("%.1fs", float64(ms)/1000)
	}
	return fmt.Sprintf("%.1fm", float64(ms)/60000)
}

func truncateID(id string) string {
	if len(id) > 36 {
		return id[:33] + "..."
	}
	return id
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func colorStatus(status string) string {
	switch status {
	case "completed":
		return color.GreenString(status)
	case "failed":
		return color.RedString(status)
	case "running":
		return color.YellowString(status)
	case "paused":
		return color.YellowString(status)
	default:
		return status
	}
}

func truncateJSON(data json.RawMessage, maxLen int) string {
	s := string(data)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func printJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
