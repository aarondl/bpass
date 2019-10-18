// +build liner

package main

import (
	"fmt"
	"io"

	"github.com/peterh/liner"
)

func setupLineEditor(u *uiContext) error {
	u.term = newLinerEditor()
	return nil
}

type linerEditor struct {
	state *liner.State
}

func newLinerEditor() linerEditor {
	state := liner.NewLiner()
	state.SetTabCompletionStyle(liner.TabPrints)
	state.SetCtrlCAborts(true)

	return linerEditor{
		state: state,
	}
}

// Line implements LineEditor.Line
func (l linerEditor) Line(prompt string) (string, error) {
	s, err := l.state.Prompt(prompt)
	switch err {
	case nil:
		return s, nil
	case io.EOF:
		fmt.Println()
		return s, ErrEnd
	case liner.ErrPromptAborted:
		return s, ErrInterrupt
	default:
		return "", err
	}
}

// LineHidden implements LineEditor.LineHidden
func (l linerEditor) LineHidden(prompt string) (string, error) {
	s, err := l.state.PasswordPrompt(prompt)
	switch err {
	case nil:
		return s, nil
	case io.EOF:
		fmt.Println()
		return s, ErrEnd
	case liner.ErrPromptAborted:
		return s, ErrInterrupt
	default:
		return "", err
	}
}

// AddHistory adds a line to history
func (l linerEditor) AddHistory(line string) {
	l.state.AppendHistory(line)
}

// SetEntryCompleter sets a completion function for entries.
func (l linerEditor) SetEntryCompleter(fn func(string) []string) {
	panic("not implemented")
}

// Close the liner editor
func (l linerEditor) Close() error {
	return l.state.Close()
}
