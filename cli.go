package main

import (
	"github.com/spf13/cobra"
)

/*

commands:
bpass open <filename>
bpass set <name> <key> <value>
bpass get [--history n] <name> <key>
bpass (user|pass|email) [--history n] <name>
bpass show [--history n] <name>

bpass totp [--history n] <name>
bpass settotp <name> <secret|url>

bpass notes [--history n] <name>
bpass note <name> <index>
bpass addnote <name> <note>
bpass rmnote <name> <index>

bpass labels [--history n] <name>
bpass addlabel <name> <label>
bpass rmlabel <name> <label>

bpass new <name>
bpass ls [name]
bpass rm <name>

bpass sync

repl:
findlabel <label1,label2>
ls [name]
cd name
rm name
show name
set name key value
get name key
cp  name key
*/

var ()

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

	rootCmd.PersistentFlags().StringVarP(&flagFile, "file", "f", "passwd.blob", "Bpass file")
	rootCmd.Flags().BoolVarP(&flagNoColor, "no-color", "", false, "Disable color output")

	return rootCmd, nil
}

func (c cliContext) rootHandler(cmd *cobra.Command, args []string) error {
	r := repl{
		ctx: c.ctx,
	}
	return r.run()
}
