package osutil

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// OpenURL uses start on linux
func OpenURL(uri string) error {
	command, err := exec.LookPath("start")
	if err != nil {
		return errors.New("could not find start in path")
	}

	process, err := os.StartProcess(command, []string{command, uri}, attrs)
	if err != nil {
		return fmt.Errorf("error starting start: %w", err)
	}

	if err = process.Release(); err != nil {
		return fmt.Errorf("failed to release process")
	}

	return nil
}
