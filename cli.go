package main

import (
	"fmt"

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
set name key value
get name key value
cp  name key value
*/

var ()

var (
	flagRevision uint
	flagFile     string
)

func initCobra(ctx *uiContext) (*cobra.Command, error) {
	rootCmd := &cobra.Command{
		Use:           "bpass",
		Short:         "Command line password manager",
		RunE:          ctx.rootHandler,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	setCmd := &cobra.Command{
		Use:           "set [flags] <name> <key> <value>",
		Short:         "Set a key-value on an entry",
		RunE:          ctx.setHandler,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	getCmd := &cobra.Command{
		Use:           "get [flags] <name> <key>",
		Short:         "Get a value by key on an entry",
		RunE:          ctx.getHandler,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	showCmd := &cobra.Command{
		Use:           "show [flags] <name>",
		Short:         "Show an entire entry",
		RunE:          ctx.showHandler,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	for _, c := range []*cobra.Command{setCmd, getCmd, showCmd} {
		c.Flags().UintVarP(&flagRevision, "revision", "r", 0, "Number of revisions in the past")
	}

	rootCmd.PersistentFlags().StringVarP(&flagFile, "file", "f", "passwd.blob", "Bpass file")

	rootCmd.AddCommand(setCmd, getCmd, showCmd)

	return rootCmd, nil
}

func (u *uiContext) rootHandler(cmd *cobra.Command, args []string) error {
	return u.repl()
}

func (u *uiContext) setHandler(cmd *cobra.Command, args []string) error {
	fmt.Println("not implemented")
	return nil
}

func (u *uiContext) getHandler(cmd *cobra.Command, args []string) error {
	fmt.Println("not implemented")
	return nil
}

func (u *uiContext) showHandler(cmd *cobra.Command, args []string) error {
	fmt.Println("not implemented")
	return nil
}
