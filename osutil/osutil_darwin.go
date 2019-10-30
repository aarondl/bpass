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

	process, err := os.StartProcess(command, []string{command, uri}, attrs)
	if err != nil {
		return fmt.Errorf("error starting open: %w", err)
	}

	if err = process.Release(); err != nil {
		return fmt.Errorf("failed to release process")
	}

	return nil
}
