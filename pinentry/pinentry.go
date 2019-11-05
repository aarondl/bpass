// Package pinentry finds a pinentry program and attempts to use it
package pinentry

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

var (
	// ErrNotFound is returned when pinentry programs cannot be located.
	ErrNotFound = errors.New("pinentry program not found")

	pinEntryPrograms = []string{
		"pinentry",
		"pinentry-gnome3",
		"pinentry-kde",
		"pinentry-x11",
		"pinentry-curses",
		"pinentry-tty",
	}

	cachedPinEntry string
)

// Password retrieves a password from a pinentry program if it exists.
// If a pinentry program could not be found it returns ErrNotFound.
//
// If the user cancel's the pinentry it will just return an empty string
// and no error.
func Password(prompt string) (password string, err error) {
	program := os.Getenv("PINENTRY")
	if len(program) == 0 {
		if len(cachedPinEntry) == 0 {
			for _, p := range pinEntryPrograms {
				if _, err := exec.LookPath(p); err == nil {
					cachedPinEntry = p
					break
				}
			}
		}

		program = cachedPinEntry
	}

	if len(program) == 0 {
		return "", ErrNotFound
	}

	cmd := exec.Command(program, "--ttyname", "/dev/tty")
	cmd.Stderr = os.Stderr

	var in io.WriteCloser
	var out io.ReadCloser
	in, err = cmd.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("failed to open pinentry stdin: %w", err)
	}
	out, err = cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("failed to open pinentry stdout: %w", err)
	}

	if err = cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start pinentry: %w", err)
	}

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to communicate with pinentry: %v", r)
		}
	}()

	scanner := bufio.NewScanner(out)
	getLine := func() string {
		if !scanner.Scan() {
			if e := scanner.Err(); e != nil {
				panic(e)
			}
			panic("failed to scan line")
		}
		return scanner.Text()
	}

	if getLine() != "OK Pleased to meet you" {
		return "", errors.New("rogue pinentry program")
	}

	setup := []string{
		fmt.Sprintf("SETTITLE %s\n", "Bpass password entry"),
		fmt.Sprintf("SETDESC %s\n", prompt),
		fmt.Sprintf("OPTION lc-ctype %s\n", "UTF-8"),
	}
	if term := os.Getenv("TERM"); len(term) != 0 {
		setup = append(setup, fmt.Sprintf("OPTION ttytype %s\n", term))
	}
	if display := os.Getenv("DISPLAY"); len(display) != 0 {
		setup = append(setup, fmt.Sprintf("OPTION display %s\n", display))
	}

	for _, s := range setup {
		mustWrite(in.Write([]byte(s)))

		if getLine() != "OK" {
			return "", fmt.Errorf("failed setting option (%s): %w", s, err)
		}
	}

	mustWrite(fmt.Fprintln(in, "GETPIN"))

	resp := getLine()
	if strings.HasPrefix(resp, "D ") {
		password = resp[2:]
		resp = getLine()
	} else if strings.HasPrefix(resp, "ERR") && strings.Contains(resp, "Operation cancelled") {
		return "", nil
	}
	if resp != "OK" {
		return "", fmt.Errorf("rogue pinentry program")
	}

	mustWrite(fmt.Fprintln(in, "BYE"))

	if err = cmd.Wait(); err != nil {
		return "", err
	}

	return password, nil
}

func mustWrite(_ int, err error) {
	if err != nil {
		panic(err)
	}
}
