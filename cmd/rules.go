package cmd

import "github.com/spf13/cobra"

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "List available rule names and aliases",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		if err := validateOutputFormat(flagFormat); err != nil {
			return err
		}
		switch flagFormat {
		case outputFormatJSON:
			printRulesJSON()
		case outputFormatHTML:
			return printRulesHTML()
		default:
			printRulesTable()
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(rulesCmd)
}
