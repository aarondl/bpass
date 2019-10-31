// +build linux darwin

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/chzyer/readline"
)

func setupLineEditor(u *uiContext) error {
	var err error
	u.in, err = newReadlineEditor(u.out)
	return err
}

type readlineEditor struct {
	currentPrompt    string
	promptNeedsReset bool
	instance         *readline.Instance
	out              io.Writer
}

func newReadlineEditor(out io.Writer) (readlineEditor, error) {
	instance, err := readline.NewEx(readlineConfig(out, nil))
	if err != nil {
		return readlineEditor{}, err
	}

	return readlineEditor{instance: instance, out: out}, nil
}

func readlineConfig(out io.Writer, entryCompleter func(string) []string) *readline.Config {
	var completer readline.AutoCompleter
	if entryCompleter != nil {
		completer = readlineAutocompleter(entryCompleter)
	}

	return &readline.Config{
		Prompt: "> ",

		AutoComplete: completer,

		HistoryFile:            "",
		HistoryLimit:           1000,
		DisableAutoSaveHistory: true,

		InterruptPrompt: "interrupt",
		EOFPrompt:       "exit",

		Stdin:  os.Stdin,
		Stdout: out,
		Stderr: os.Stderr,

		UniqueEditLine: false,
	}
}

// Line implements LineEditor.Line
func (r readlineEditor) Line(prompt string) (string, error) {
	if r.currentPrompt != prompt || r.promptNeedsReset {
		r.currentPrompt = prompt
		r.promptNeedsReset = false
		r.instance.SetPrompt(prompt)
	}

	s, err := r.instance.Readline()
	switch err {
	case nil:
		return s, nil
	case io.EOF:
		r.promptNeedsReset = true
		return "", ErrEnd
	case readline.ErrInterrupt:
		return "", ErrInterrupt
	default:
		return "", err
	}
}

// LineHidden implements LineEditor.LineHidden
func (r readlineEditor) LineHidden(prompt string) (string, error) {
	byt, err := r.instance.ReadPassword(prompt)
	switch err {
	case nil:
		return string(byt), nil
	case io.EOF:
		r.promptNeedsReset = true
		return "", ErrEnd
	case readline.ErrInterrupt:
		return "", ErrInterrupt
	default:
		return "", err
	}
}

// AddHistory adds a line to history
func (r readlineEditor) AddHistory(line string) {
	err := r.instance.SaveHistory(line)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to save history line:", err)
	}
}

// SetEntryCompleter sets a completion function for entries.
func (r readlineEditor) SetEntryCompleter(entryCompleter func(string) []string) {
	r.instance.SetConfig(readlineConfig(r.out, entryCompleter))
}

func readlineAutocompleter(entryCompleter func(string) []string) readline.AutoCompleter {
	return readline.NewPrefixCompleter(
		readline.PcItem("add"),
		readline.PcItem("rm", readline.PcItemDynamic(entryCompleter)),
		readline.PcItem("mv", readline.PcItemDynamic(entryCompleter)),
		readline.PcItem("ls"),
		readline.PcItem("cd", readline.PcItemDynamic(entryCompleter)),
		readline.PcItem("show", readline.PcItemDynamic(entryCompleter)),
		readline.PcItem("set",
			readline.PcItemDynamic(entryCompleter,
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
			readline.PcItemDynamic(entryCompleter,
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
			readline.PcItemDynamic(entryCompleter,
				readline.PcItem("email"),
				readline.PcItem("user"),
				readline.PcItem("pass"),
				readline.PcItem("totp"),
				readline.PcItem("twofactor"),
				readline.PcItem("labels"),
				readline.PcItem("notes"),
			),
		),
		readline.PcItem("open", readline.PcItemDynamic(entryCompleter)),
		readline.PcItem("note", readline.PcItemDynamic(entryCompleter)),
		readline.PcItem("rmnote", readline.PcItemDynamic(entryCompleter)),
		readline.PcItem("label", readline.PcItemDynamic(entryCompleter)),
		readline.PcItem("rmlabel", readline.PcItemDynamic(entryCompleter)),
		readline.PcItem("pass", readline.PcItemDynamic(entryCompleter)),
		readline.PcItem("user", readline.PcItemDynamic(entryCompleter)),
		readline.PcItem("email", readline.PcItemDynamic(entryCompleter)),
		readline.PcItem("totp", readline.PcItemDynamic(entryCompleter)),
		readline.PcItem("sync",
			readline.PcItem("add",
				readline.PcItem("ssh"),
			),
			readline.PcItem("rm",
				readline.PcItem("ssh"),
			),
		),
	)
}

// Close the liner editor
func (r readlineEditor) Close() error {
	return r.instance.Close()
}
