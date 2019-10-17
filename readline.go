package main

import (
	"os"
	"sort"

	"github.com/gookit/color"

	"github.com/chzyer/readline"
)

var (
	normalPrompt = "(%s)> "
	dirPrompt    = "(%s):%s> "

	promptColor = color.FgLightBlue
)

func newReadline(ctx *uiContext, filename string) (*readline.Instance, error) {
	completer := readlineCompleter(ctx)

	config := &readline.Config{
		Prompt: promptColor.Sprintf(normalPrompt, ctx.shortFilename),

		HistoryFile:            "",
		HistoryLimit:           -1,
		DisableAutoSaveHistory: true,

		AutoComplete: completer,

		InterruptPrompt: "^C",
		EOFPrompt:       "exit",

		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,

		UniqueEditLine: false,
	}

	return readline.NewEx(config)
}

func readlineCompleter(ctx *uiContext) readline.AutoCompleter {
	return readline.NewPrefixCompleter(
		readline.PcItem("get",
			readline.PcItemDynamic(ctx.readlineKeyComplete,
				readline.PcItem("email"),
				readline.PcItem("user"),
				readline.PcItem("pass"),
			),
		),
		readline.PcItem("email",
			readline.PcItemDynamic(ctx.readlineKeyComplete),
		),
		readline.PcItem("user",
			readline.PcItemDynamic(ctx.readlineKeyComplete),
		),
	)
}

func (u *uiContext) readlineKeyComplete(s string) []string {
	if u.store == nil {
		return nil
	}

	names := u.store.Find("")
	sort.Strings(names)
	return names
}

func (u *uiContext) readlineResetPrompt() {
	u.rl.SetPrompt(promptColor.Sprintf(normalPrompt, u.shortFilename))
}

func (u *uiContext) readlineDirPrompt(dir string) {
	u.rl.SetPrompt(promptColor.Sprintf(dirPrompt, u.shortFilename, dir))
}
