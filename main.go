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
	"github.com/atotto/clipboard"

	"github.com/gookit/color"
)

type uiContext struct {
	term LineEditor

	filename      string
	shortFilename string

	// Decrypted and decoded storage
	store blobformat.Blobs
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

	if flagNoColor {
		color.Disable()
	}

	var err error
	ctx := new(uiContext)
	ctx.filename, err = filepath.Abs(flagFile)
	if err != nil {
		fmt.Printf("failed to find the absolute path to: %q\n", flagFile)
		os.Exit(1)
	}
	ctx.shortFilename = shortPath(ctx.filename)
	r := repl{ctx: ctx}

	// setup readline needs to have the filenames parsed and ready
	// to use from above
	if err = setupLineEditor(ctx); err != nil {
		fmt.Printf("failed to setup line editor: %+v", err)
		goto Exit
	}

	// loadBlob uses readline and the filenames to load the blob
	if err = ctx.loadBlob(); err != nil {
		errColor.Printf("failed to open file: %+v\n", err)
		goto Exit
	}

	if err = r.run(); err != nil {
		if err == ErrInterrupt {
			errColor.Println("exiting, did not save file")
			goto Exit
		}
		errColor.Printf("error occurred: %+v\n", err)
		goto Exit
	}

	// save the changed data
	if err = ctx.saveBlob(); err != nil {
		errColor.Printf("failed to save file: %+v\n", err)
		goto Exit
	}

Exit:
	if !flagNoClearClip {
		if err = clipboard.WriteAll(""); err != nil {
			errColor.Println("failed to clear the clipboard")
		}
	}

	if err = ctx.term.Close(); err != nil {
		errColor.Println("failed to close terminal properly:", err)
	}
	if err != nil {
		os.Exit(1)
	}
}

func (u *uiContext) loadBlob() error {
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

	if create {
		infoColor.Printf("Creating new file: %s\n", u.filename)
	}

	var pwd string
	if create {
		pwd, err = u.term.LineHidden(inputPromptColor.Sprint("passphrase: "))
		if err != nil {
			return err
		}

		verify, err := u.term.LineHidden(inputPromptColor.Sprint("verify passphrase: "))
		if err != nil {
			return err
		}

		if pwd != verify {
			return errors.New("passphrases did not match")
		}
	} else {
		pwd, err = u.term.LineHidden(inputPromptColor.Sprintf("%s passphrase: ", u.shortFilename))
		if err != nil {
			return err
		}

		// Read in the file, decrypt it, parse the blob data.
		payload, err := ioutil.ReadFile(flagFile)
		if err != nil {
			return err
		}

		_, pt, err := crypt.Decrypt([]byte(pwd), payload)
		if err != nil {
			return err
		}

		if u.store, err = blobformat.New(pt); err != nil {
			return err
		}
	}

	// Derive a new key from the password for later encryption
	u.key, u.salt, err = crypt.DeriveKey(cryptVersion, []byte(pwd))
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
