package main

import (
	"errors"
	"io"
)

// Handle-able error codes that arise from line editors
var (
	ErrInterrupt = errors.New("Interrupt")
	ErrEnd       = io.EOF
)

// LineEditor should provide decent line editing abilities like up/down arrow
// history, left/right arrow cursor movement, hidden password entry etc.
type LineEditor interface {
	// Line returns a line of text as read from the user
	Line(prompt string) (string, error)
	// LineHidden returns a line of text as read from the user, but does not
	// show what's typed to the user.
	LineHidden(prompt string) (string, error)

	// AddHistory puts line into the history. It should be called when a valid
	// command has occurred.
	AddHistory(line string)

	// SetEntryCompleter is used to allow a line editor to provide completion
	// for entries.
	SetEntryCompleter(func(string) []string)

	// Close the line editor, restoring any terminal magic to its proper place
	Close() error
}

/*
var (
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
}

func (u *uiContext) readlineKeyComplete(s string) []string {
	if u.store == nil {
		return nil
	}

	names := u.store.Find("")
	sort.Strings(names)
	return names
}

	normalPrompt = "(%s)> "
	dirPrompt    = "(%s):%s> "

	promptColor = color.FgLightBlue
func (u *uiContext) readlineResetPrompt() {
	if len(u.promptDir) != 0 {
		u.rl.SetPrompt(promptColor.Sprintf(dirPrompt, u.shortFilename, u.promptDir))
	} else {
		u.rl.SetPrompt(promptColor.Sprintf(normalPrompt, u.shortFilename))
	}
}

*/
