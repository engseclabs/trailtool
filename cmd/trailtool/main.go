package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/cli/commands"
)

var version = "dev"

func main() {
	rootCmd := &cobra.Command{
		Use:   "trailtool",
		Short: "TrailTool - AWS CloudTrail analysis CLI",
		Long:  "Analyze AWS CloudTrail data for people, sessions, accounts, roles, services, and resources.",
	}

	rootCmd.PersistentFlags().StringVar(&commands.Format, "format", "text", "Output format: text or json")
	rootCmd.PersistentFlags().StringVar(&commands.ColorMode, "color", "auto", "Colorize output: auto, always, or never")
	rootCmd.PersistentFlags().BoolVar(&commands.Debug, "debug", false, "Show raw AWS/service errors for diagnosis")

	rootCmd.Version = version
	rootCmd.AddCommand(commands.StatusCmd())
	rootCmd.AddCommand(commands.PeopleCmd())
	rootCmd.AddCommand(commands.SessionsCmd())
	rootCmd.AddCommand(commands.AccountsCmd())
	rootCmd.AddCommand(commands.RolesCmd())
	rootCmd.AddCommand(commands.ServicesCmd())
	rootCmd.AddCommand(commands.ResourcesCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
