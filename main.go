package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/aarondl/bpass/blobformat"
	"github.com/aarondl/bpass/crypt"
	"github.com/chzyer/readline"
)

type uiContext struct {
	filename      string
	shortFilename string

	promptDir string

	store blobformat.Blobs
	rl    *readline.Instance

	// for later encryption
	key  []byte
	salt []byte
}

var (
	version      = "unknown"
	cryptVersion = 1
)

func main() {
	parseCli()

	if versionCmd.Used {
		fmt.Println("bpass version", version)
		return
	}

	var err error
	ctx := new(uiContext)

	// setup readline needs to have the filenames parsed and ready
	// to use from above
	if err = ctx.setupReadline(); err != nil {
		fmt.Printf("failed to load file: %+v", err)
		os.Exit(1)
	}

	// loadBlob uses readline and the filenames to load the blob
	if err = ctx.loadBlob(); err != nil {
		fmt.Printf("failed to load file: %+v", err)
		os.Exit(1)
	}

	r := repl{ctx: ctx}
	if err = r.run(); err != nil {
		if err == readline.ErrInterrupt {
			fmt.Println("exiting, did not save file")
			os.Exit(1)
		}
		fmt.Printf("error occurred: %+v\n", err)
		os.Exit(1)
	}

	// save the changed data
	if err = ctx.saveBlob(); err != nil {
		fmt.Printf("failed to save file: %+v\n", err)
		os.Exit(1)
	}
}

func (u *uiContext) setupReadline() error {
	var err error
	u.filename, err = filepath.Abs(flagFile)
	if err != nil {
		return err
	}
	u.shortFilename = shortPath(u.filename)

	u.rl, err = newReadline(u, u.shortFilename)
	if err != nil {
		return err
	}

	return nil
}

func (u *uiContext) loadBlob() error {
	pwd, err := u.rl.ReadPassword(fmt.Sprintf("%s password: ", u.shortFilename))
	if err != nil {
		return err
	}

	create := false

	// Check the file exists and it's a file
	check, err := os.Stat(flagFile)
	if err != nil {
		if os.IsNotExist(err) {
			create = true
		} else {
			return err
		}
	} else if check.IsDir() {
		return errors.New("given file name is a directory")
	}

	if !create {
		// Read in the file, decrypt it, parse the blob data.
		payload, err := ioutil.ReadFile(flagFile)
		if err != nil {
			return err
		}

		_, pt, err := crypt.Decrypt(pwd, payload)
		if err != nil {
			return err
		}

		if u.store, err = blobformat.New(pt); err != nil {
			return err
		}
	}

	// Derive a new key from the password for later encryption
	u.key, u.salt, err = crypt.DeriveKey(cryptVersion, pwd)
	if err != nil {
		return err
	}

	// It's possible the store was empty/null even on a load, just create it
	if u.store == nil {
		u.store = make(blobformat.Blobs)
	}

	return nil
}

func (u *uiContext) saveBlob() error {
	data, err := u.store.Save()
	if err != nil {
		return err
	}

	data, err = crypt.Encrypt(cryptVersion, u.key, u.salt, data)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(flagFile, data, 0600)
}

func shortPath(filename string) string {
	parts := strings.Split(filename, string(filepath.Separator))
	if len(parts) == 1 {
		return filename
	}

	var newParts []string
	for _, p := range parts[:len(parts)-1] {
		if len(p) == 0 {
			newParts = append(newParts, p)
			continue
		}
		newParts = append(newParts, string(p[0]))
	}
	newParts = append(newParts, parts[len(parts)-1])

	return strings.Join(newParts, string(filepath.Separator))
}
