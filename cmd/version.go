package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "print version",
	RunE:  versionRun,
}

func init() {
	RootCmd.AddCommand(versionCmd)
}

func versionRun(cmd *cobra.Command, args []string) error {
	fmt.Fprintf(os.Stdout, "aws-aad %s\n", version)
	return nil
}
