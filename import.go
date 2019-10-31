package main

import (
	"bytes"
	"encoding/csv"
	"errors"
	"io"
	"os/exec"
	"strings"

	"github.com/aarondl/bpass/txblob"
)

func importLastpass(u *uiContext) error {
	if !u.created {
		infoColor.Println("this is not a new file")
		infoColor.Println("are you sure you wish to import into it?")
		line, err := u.prompt(promptColor.Sprint("proceed (y/N): "))
		if err != nil {
			return err
		}

		switch line {
		case "Y", "y":
			// Let pass through
		default:
			errColor.Println("aborting")
			return nil
		}
	}

	// get data from lpass command line client
	lpassCmd := exec.Command("lpass", "export", "--color=never")
	out, err := lpassCmd.CombinedOutput()
	if err != nil {
		return err
	}

	reader := csv.NewReader(bytes.NewReader(out))

	for i := 0; ; i++ {
		record, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		if i == 0 {
			if strings.Join(record, ",") != "url,username,password,extra,name,grouping,fav" {
				return errors.New("lastpass csv format not recognized")
			}
		}

		// Fields:
		//  0    1         2       3     4    5        6
		// url,username,password,extra,name,grouping,fav

		// Create the
		var uuid string

		// Create the new entry, make sure the name is unique
		oldName := strings.ReplaceAll(strings.ToLower(record[4]), " ", "_")
		newName := oldName
		for {
			uuid, err = u.store.New(newName)
			if err != nil {
				if err == txblob.ErrNameNotUnique {
					newName += "1"
					continue
				}

				return err
			}

			if oldName == newName {
				infoColor.Println("importing:", oldName)
			} else {
				infoColor.Printf("importing: %s => %s\n", oldName, newName)
			}
			break
		}

		if len(record[1]) != 0 {
			u.store.Store.Set(uuid, txblob.KeyUser, record[1])
		}
		if len(record[2]) != 0 {
			u.store.Store.Set(uuid, txblob.KeyPass, record[2])
		}
		if len(record[0]) != 0 {
			u.store.Store.Set(uuid, txblob.KeyURL, record[0])
		}
		if len(record[3]) != 0 {
			u.store.Store.Set(uuid, txblob.KeyNotes, record[3])
		}

		var labels []string
		if len(record[5]) != 0 {
			labels = append(labels, strings.ToLower(record[5]))
		}
		if record[6] == "1" {
			labels = append(labels, "lpfav")
		}
		if len(labels) != 0 {
			u.store.Store.Set(uuid, txblob.KeyLabels, strings.Join(labels, ","))
		}
	}

	infoColor.Println("import complete")

	return nil
}
