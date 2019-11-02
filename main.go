package main

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/aarondl/bpass/blobformat"
	"github.com/aarondl/bpass/crypt"
	"github.com/aarondl/bpass/txlogs"

	"github.com/aarondl/color"
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
	store blobformat.Blobs

	// save user & password for syncing later
	user   string
	pass   string
	params *crypt.Params
}

var (
	version      = "unknown"
	cryptVersion = 1
)

func main() {
	var r repl
	var err error

	parseCli()

	if versionCmd.Used {
		fmt.Println("bpass version", version)
		return
	}

	ctx := new(uiContext)
	if flagNoColor {
		color.Disable = true
		ctx.out = os.Stdout
	} else {
		writer := colorable.NewColorable(os.Stdout)
		color.Writer = writer
		ctx.out = writer
	}

	// setup readline needs to have the filenames parsed and ready
	// to use from above
	if err = setupLineEditor(ctx); err != nil {
		fmt.Printf("failed to setup line editor: %+v\n", err)
		goto Exit
	}

	if genCmd.Used {
		passwd, err := ctx.getPassword()
		if err != nil {
			fmt.Printf("failed to get a password: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(passwd)
		return
	}

	ctx.filename, err = filepath.Abs(flagFile)
	if err != nil {
		fmt.Printf("failed to find the absolute path to: %q\n", flagFile)
		os.Exit(1)
	}
	ctx.shortFilename = shortPath(ctx.filename)
	r = repl{ctx: ctx}

	// loadBlob uses readline and the filenames to load the blob
	if err = ctx.loadBlob(); err != nil {
		errColor.Printf("failed to open file: %+v\n", err)
		goto Exit
	}

	switch {
	case lpassImportCmd.Used:
		if err = importLastpass(ctx); err != nil {
			fmt.Printf("error occurred: %+v\nexiting without saving", err)
			goto Exit
		}
	default:
		if err = r.run(); err != nil {
			if err == ErrInterrupt {
				fmt.Println("exiting, did not save file")
				goto Exit
			}
			fmt.Printf("error occurred: %+v\n", err)
			goto Exit
		}
	}

	// save the changed data
	if err = ctx.saveBlob(); err != nil {
		fmt.Printf("failed to save file: %+v\n", err)
		goto Exit
	}

Exit:
	if !flagNoClearClip {
		if err = clipboard.WriteAll(""); err != nil {
			fmt.Println("failed to clear the clipboard")
		}
	}

	if err = ctx.in.Close(); err != nil {
		fmt.Println("failed to close terminal properly:", err)
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
		pwd, err = u.promptPassword(promptColor.Sprint("passphrase: "))
		if err != nil {
			return err
		}

		verify, err := u.promptPassword(promptColor.Sprint("verify passphrase: "))
		if err != nil {
			return err
		}

		if pwd != verify {
			return errors.New("passphrases did not match")
		}

		// Derive a new key from the password for later encryption
		key, salt, err := crypt.DeriveKey(cryptVersion, []byte(pwd))
		if err != nil {
			return err
		}

		u.params = new(crypt.Params)
		u.params.SetSingleUser(key, salt)
	} else {
		// Read in the file, decrypt it, parse the blob data.
		payload, err := ioutil.ReadFile(flagFile)
		if err != nil {
			return err
		}

		var user string
		var ok bool
		if ok, err = crypt.IsMultiUser(payload); err != nil {
			return err
		} else if ok {
			user, err = u.prompt(promptColor.Sprintf("%s user: ", u.shortFilename))
			if err != nil {
				return err
			}
		}

		pwd, err = u.promptPassword(promptColor.Sprintf("%s passphrase: ", u.shortFilename))
		if err != nil {
			return err
		}

		_, params, pt, err := crypt.Decrypt([]byte(user), []byte(pwd), nil, nil, payload)
		if err != nil {
			return err
		}
		u.params = &params
		u.user = user
		u.pass = pwd

		store, err := txlogs.New(pt)
		if err != nil {
			return err
		}

		u.store = blobformat.Blobs{DB: store}
	}

	// It's possible the store was empty/null even on a load, just create it
	if u.store.DB == nil {
		u.store = blobformat.Blobs{DB: new(txlogs.DB)}
	}

	return nil
}

func (u *uiContext) saveBlob() error {
	data, err := u.store.Save()
	if err != nil {
		return err
	}

	data, err = crypt.Encrypt(cryptVersion, u.params, data)
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
