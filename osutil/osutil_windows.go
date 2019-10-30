package osutil

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// OpenURL uses cmd.exe's start on linux
func OpenURL(uri string) error {
	command, err := exec.LookPath("cmd.exe")
	if err != nil {
		return errors.New("could not find start in path")
	}

	attrs := &os.ProcAttr{
		Files: []*os.File{nil, nil, nil},
	}

	process, err := os.StartProcess(command, []string{command, "/c", "start", uri}, attrs)
	if err != nil {
		return fmt.Errorf("error starting cmd.exe: %w", err)
	}

	if err = process.Release(); err != nil {
		return fmt.Errorf("failed to release process")
	}

	return nil
}
