package osutil

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// OpenURL uses cmd.exe's start on linux
func OpenURL(uri string) error {
	command, err := exec.LookPath("explorer.exe")
	if err != nil {
		return errors.New("could not find explorer.exe in path")
	}

	attrs := &os.ProcAttr{
		Files: []*os.File{nil, nil, nil},
	}

	process, err := os.StartProcess(command, []string{command, uri}, attrs)
	if err != nil {
		return fmt.Errorf("error starting explorer.exe: %w", err)
	}

	if err = process.Release(); err != nil {
		return fmt.Errorf("failed to release process")
	}

	return nil
}

// RunEditor runs the best possible editor on windows
func RunEditor(filename string) error {
	editor := os.Getenv("EDITOR")
	if len(editor) == 0 {
		editors := []string{"code", "atom", "sublime", "vim", "notepad"}
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
