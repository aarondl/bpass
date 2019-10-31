package osutil

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// OpenURL uses the open program on darwin
func OpenURL(uri string) error {
	command, err := exec.LookPath("open")
	if err != nil {
		return errors.New("could not find open in path")
	}

	attrs := &os.ProcAttr{
		Files: []*os.File{nil, nil, nil},
	}

	process, err := os.StartProcess(command, []string{command, uri}, attrs)
	if err != nil {
		return fmt.Errorf("error starting open: %w", err)
	}

	if err = process.Release(); err != nil {
		return fmt.Errorf("failed to release process")
	}

	return nil
}

// RunEditor runs the best possible editor on osx
func RunEditor(filename string) error {
	editor := os.Getenv("EDITOR")
	if len(editor) == 0 {
		cmd := exec.Command("open", "-W", filename)
		return cmd.Run()
	}

	cmd := exec.Command(editor, filename)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
