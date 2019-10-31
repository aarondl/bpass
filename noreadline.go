// +build windows

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

const (
	stdInputHandle  = uint32(0xFFFFFFF6) // -10
	stdOutputHandle = uint32(0xFFFFFFF5) // -11
	stdErrHandle    = uint32(0xFFFFFFF4) // -12
)

func setupLineEditor(u *uiContext) error {
	u.in = newScanEditor(u.out)
	return nil
}

type scanEditor struct {
	*bufio.Scanner
	io.Writer
}

func newScanEditor(out io.Writer) *scanEditor {
	return &scanEditor{
		Scanner: bufio.NewScanner(os.Stdin),
		Writer:  out,
	}
}

// Line implements LineEditor.Line
func (s *scanEditor) Line(prompt string) (string, error) {
	fmt.Fprint(s, prompt)
	if !s.Scanner.Scan() {
		return "", ErrInterrupt
	}

	return s.Scanner.Text(), nil
}

// LineHidden implements LineEditor.LineHidden
func (s *scanEditor) LineHidden(prompt string) (string, error) {
	stdinHandle, err := windows.GetStdHandle(stdInputHandle)
	if err != nil {
		return "", err
	}
	var oldMode uint32
	err = windows.GetConsoleMode(stdinHandle, &oldMode)
	if err != nil {
		return "", err
	}

	var newMode uint32
	err = windows.SetConsoleMode(stdinHandle, newMode)
	if err != nil {
		return "", err
	}

	defer func() {
		err = windows.SetConsoleMode(stdinHandle, oldMode)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error resetting console:", err)
		}
	}()

	fmt.Fprint(s, prompt)

	var builder bytes.Buffer
	var buf [256]uint16
	var nRead uint32
Loop:
	for {
		err = windows.ReadConsole(stdinHandle, &buf[0], uint32(len(buf)), &nRead, nil)
		if err != nil {
			return "", err
		}

		for i, c := range buf {
			switch c {
			case 0x08:
				// Backspace
				builder.Truncate(builder.Len() - 1)
				continue Loop
			case 0x0D, 0x0A:
				// Newline
				fmt.Println()
				builder.WriteString(string(utf16.Decode(buf[:i])))
				break Loop
			case 0x04:
				// CTRL+D
				return "", ErrEnd
			case 0x03:
				// CTRL+C
				return "", ErrInterrupt
			}
		}

		builder.WriteString(string(utf16.Decode(buf[:nRead])))
	}

	out := builder.String()
	// Ignore carriage return that hangs on the end
	// why ReadConsole returns \r and not \r\n is beyond me
	out = strings.TrimSpace(out)

	return out, nil
}

// AddHistory adds a line to history
func (s *scanEditor) AddHistory(line string) {}

// SetEntryCompleter sets a completion function for entries.
func (s *scanEditor) SetEntryCompleter(entryCompleter func(string) []string) {}

// Close the liner editor
func (s *scanEditor) Close() error { return nil }
