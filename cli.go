package main

import (
	"github.com/spf13/cobra"
)

var (
	flagNoColor  bool
	flagRevision uint
	flagFile     string
)

type cliContext struct {
	ctx *uiContext
}

func initCobra(ctx *uiContext) (*cobra.Command, error) {
	cli := cliContext{
		ctx: ctx,
	}

	rootCmd := &cobra.Command{
		Use:           "bpass",
		Short:         "Command line password manager",
		RunE:          cli.rootHandler,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Shows the version",
		Run:   func(*cobra.Command, []string) {},
	}

	rootCmd.PersistentFlags().StringVarP(&flagFile, "file", "f", "passwd.blob", "Bpass file")
	rootCmd.Flags().BoolVarP(&flagNoColor, "no-color", "", false, "Disable color output")

	rootCmd.AddCommand(versionCmd)

	return rootCmd, nil
}

func (c cliContext) rootHandler(cmd *cobra.Command, args []string) error {
	r := repl{
		ctx: c.ctx,
	}
	return r.run()
}
