package main

import (
	"net/url"
	"os"
	"os/exec"
	"syscall"
)

func (u *uiContext) openurl(search string) error {
	uuid, err := u.findOne(search)
	if err != nil {
		return nil
	}
	if len(uuid) == 0 {
		return nil
	}

	blob, err := u.store.Get(uuid)
	if err != nil {
		return err
	}

	link := blob.Get("url")
	if len(link) == 0 {
		errColor.Printf("url not set on %s\n", blob.Name())
		return nil
	}

	_, err = url.Parse(link)
	if err != nil {
		errColor.Printf("url was not a valid url: %v\n", err)
		return nil
	}

	command, err := exec.LookPath("xdg-open")
	if err != nil {
		errColor.Println("could not find xdg-open in path")
		return nil
	}

	attrs := &os.ProcAttr{
		Files: []*os.File{os.Stdin, nil, nil},
		Sys: &syscall.SysProcAttr{
			Noctty: true,
		},
	}

	process, err := os.StartProcess(command, []string{command, link}, attrs)
	if err != nil {
		errColor.Printf("error starting xdg-open: %v\n", err)
		return nil
	}

	if err = process.Release(); err != nil {
		errColor.Printf("error releasing process, exit the browser to resume session: %v\n", err)
		return nil
	}

	return nil
}
