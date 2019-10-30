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
