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
