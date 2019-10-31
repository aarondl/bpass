package main

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/aarondl/bpass/crypt"
	"github.com/aarondl/bpass/txblob"
	"github.com/aarondl/bpass/txformat"

	"github.com/atotto/clipboard"
	colorable "github.com/mattn/go-colorable"
)

type uiContext struct {
	// Input
	in LineEditor
	// Output
	out io.Writer

	created       bool
	filename      string
	shortFilename string

	// Decrypted and decoded storage
	store txblob.Blobs
	// save key + salt for encrypting later
	// save password for decrypting sync'd copies
	pass string
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
	if flagNoColor {
		ctx.out = colorable.NewNonColorable(os.Stdout)
	} else {
		ctx.out = colorable.NewColorable(os.Stdout)
	}

	ctx.filename, err = filepath.Abs(flagFile)
	if err != nil {
		fmt.Printf("failed to find the absolute path to: %q\n", flagFile)
		os.Exit(1)
	}
	ctx.shortFilename = shortPath(ctx.filename)
	r := repl{ctx: ctx}

	// setup readline needs to have the filenames parsed and ready
	// to use from above
	if err = setupLineEditor(ctx, io.Writer); err != nil {
		fmt.Printf("failed to setup line editor: %+v\n", err)
		goto Exit
	}

	// loadBlob uses readline and the filenames to load the blob
	if err = ctx.loadBlob(); err != nil {
		errColor.Printf("failed to open file: %+v\n", err)
		goto Exit
	}

	switch {
	case lpassImportCmd.Used:
		if err = importLastpass(ctx); err != nil {
			errColor.Println("error occurred: %+v\nexiting without saving", err)
			goto Exit
		}
	default:
		if err = r.run(); err != nil {
			if err == ErrInterrupt {
				errColor.Println("exiting, did not save file")
				goto Exit
			}
			errColor.Printf("error occurred: %+v\n", err)
			goto Exit
		}
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

	if err = ctx.inClose(); err != nil {
		errColor.Println("failed to close terminal properly:", err)
	}
	if err != nil {
		os.Exit(1)
	}
}

func (u *uiContext) loadBlob() error {
	// Check the file exists and it's a file
	check, err := os.Stat(flagFile)
	if err != nil {
		if os.IsNotExist(err) {
			u.created = true
		} else {
			return err
		}
	} else if check.IsDir() {
		return errors.New("given file name is a directory")
	}

	if u.created {
		infoColor.Printf("Creating new file: %s\n", u.filename)
	}

	var pwd string
	if u.created {
		pwd, err = u.in.LineHidden(inputPromptColor.Sprint("passphrase: "))
		if err != nil {
			return err
		}

		verify, err := u.in.LineHidden(inputPromptColor.Sprint("verify passphrase: "))
		if err != nil {
			return err
		}

		if pwd != verify {
			return errors.New("passphrases did not match")
		}

		// Derive a new key from the password for later encryption
		u.key, u.salt, err = crypt.DeriveKey(cryptVersion, []byte(pwd))
		if err != nil {
			return err
		}
	} else {
		pwd, err = u.in.LineHidden(inputPromptColor.Sprintf("%s passphrase: ", u.shortFilename))
		if err != nil {
			return err
		}

		// Read in the file, decrypt it, parse the blob data.
		payload, err := ioutil.ReadFile(flagFile)
		if err != nil {
			return err
		}

		meta, pt, err := crypt.Decrypt([]byte(pwd), payload)
		if err != nil {
			return err
		}

		u.pass = pwd
		u.key = meta.Key
		u.salt = meta.Salt

		store, err := txformat.New(pt)
		if err != nil {
			return err
		}

		u.store = txblob.Blobs{Store: store}
	}

	// It's possible the store was empty/null even on a load, just create it
	if u.store.Store == nil {
		u.store = txblob.Blobs{Store: new(txformat.Store)}
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
