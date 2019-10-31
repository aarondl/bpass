package osutil

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// OpenURL uses xdg-open on linux
func OpenURL(uri string) error {
	command, err := exec.LookPath("xdg-open")
	if err != nil {
		return errors.New("could not find xdg-open in path")
	}

	attrs := &os.ProcAttr{
		Files: []*os.File{os.Stdin, nil, nil},
		Sys: &syscall.SysProcAttr{
			Noctty: true,
		},
	}

	process, err := os.StartProcess(command, []string{command, uri}, attrs)
	if err != nil {
		return fmt.Errorf("error starting xdg-open: %w", err)
	}

	if err = process.Release(); err != nil {
		return fmt.Errorf("failed to release process")
	}

	return nil
}

// RunEditor runs the best possible editor on linux
func RunEditor(filename string) error {
	editor := os.Getenv("EDITOR")
	if len(editor) == 0 {
		editors := []string{"vim", "code", "atom", "sublime", "emacs", "nano"}
		for _, e := range editors {
			if _, err := exec.LookPath(e); err == nil {
				editor = e
				break
			}
		}
	}

	cmd := exec.Command(editor, filename)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
