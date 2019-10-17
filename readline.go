package main

import (
	"fmt"
	"os"

	"github.com/chzyer/readline"
)

var (
	normalPrompt = "(%s)> "
	dirPrompt    = "(%s):%s> "
)

func newReadline(ctx *uiContext, filename string) (*readline.Instance, error) {
	return readline.NewEx(readlineBasicConfig(ctx))
}

func readlineResetPrompt(ctx *uiContext) {
	ctx.rl.SetPrompt(fmt.Sprintf(normalPrompt, ctx.shortFilename))
}

func readlineDirPrompt(ctx *uiContext, dir string) {
	ctx.rl.SetPrompt(fmt.Sprintf(dirPrompt, ctx.shortFilename, dir))
}

func readlineBasicConfig(ctx *uiContext) *readline.Config {
	completer := readlineCompleter(ctx)

	return &readline.Config{
		Prompt: fmt.Sprintf(normalPrompt, ctx.shortFilename),

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
}

func readlineListenConfig(ctx *uiContext, listen listenFunc) *readline.Config {
	cfg := readlineBasicConfig(ctx)
	cfg.SetListener(listen)
	return cfg
}

type listenFunc func(line []rune, pos int, key rune) (newline []rune, newPos int, ok bool)

func readlineCompleter(ctx *uiContext) readline.AutoCompleter {
	return readline.NewPrefixCompleter(
		readline.PcItem("set",
			readline.PcItemDynamic(ctx.keyComplete,
				readline.PcItem("email"),
				readline.PcItem("user"),
				readline.PcItem("pass"),
			),
		),
		readline.PcItem("email",
			readline.PcItemDynamic(ctx.keyComplete),
		),
		readline.PcItem("user",
			readline.PcItemDynamic(ctx.keyComplete),
		),
	)
}
