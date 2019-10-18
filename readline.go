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
		HistoryLimit:           1000,
		DisableAutoSaveHistory: false,

		AutoComplete: completer,

		InterruptPrompt: "interrupt",
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
		readline.PcItem("add"),
		readline.PcItem("rm", readline.PcItemDynamic(ctx.readlineKeyComplete)),
		readline.PcItem("mv", readline.PcItemDynamic(ctx.readlineKeyComplete)),
		readline.PcItem("ls"),
		readline.PcItem("cd", readline.PcItemDynamic(ctx.readlineKeyComplete)),
		readline.PcItem("show", readline.PcItemDynamic(ctx.readlineKeyComplete)),
		readline.PcItem("set",
			readline.PcItemDynamic(ctx.readlineKeyComplete,
				readline.PcItem("email"),
				readline.PcItem("user"),
				readline.PcItem("pass"),
				readline.PcItem("totp"),
				readline.PcItem("twofactor"),
				readline.PcItem("labels"),
				readline.PcItem("notes"),
			),
		),
		readline.PcItem("get",
			readline.PcItemDynamic(ctx.readlineKeyComplete,
				readline.PcItem("email"),
				readline.PcItem("user"),
				readline.PcItem("pass"),
				readline.PcItem("totp"),
				readline.PcItem("twofactor"),
				readline.PcItem("labels"),
				readline.PcItem("notes"),
				readline.PcItem("updated"),
			),
		),
		readline.PcItem("cp",
			readline.PcItemDynamic(ctx.readlineKeyComplete,
				readline.PcItem("email"),
				readline.PcItem("user"),
				readline.PcItem("pass"),
				readline.PcItem("totp"),
				readline.PcItem("twofactor"),
				readline.PcItem("labels"),
				readline.PcItem("notes"),
			),
		),
		readline.PcItem("note", readline.PcItemDynamic(ctx.readlineKeyComplete)),
		readline.PcItem("rmnote", readline.PcItemDynamic(ctx.readlineKeyComplete)),
		readline.PcItem("label", readline.PcItemDynamic(ctx.readlineKeyComplete)),
		readline.PcItem("rmlabel", readline.PcItemDynamic(ctx.readlineKeyComplete)),
		readline.PcItem("pass", readline.PcItemDynamic(ctx.readlineKeyComplete)),
		readline.PcItem("user", readline.PcItemDynamic(ctx.readlineKeyComplete)),
		readline.PcItem("email", readline.PcItemDynamic(ctx.readlineKeyComplete)),
		readline.PcItem("totp", readline.PcItemDynamic(ctx.readlineKeyComplete)),
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
	if len(u.promptDir) != 0 {
		u.rl.SetPrompt(promptColor.Sprintf(dirPrompt, u.shortFilename, u.promptDir))
	} else {
		u.rl.SetPrompt(promptColor.Sprintf(normalPrompt, u.shortFilename))
	}
}
