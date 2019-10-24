package main

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/aarondl/bpass/blobformat"

	"github.com/gookit/color"
)

var replHelp = `Commands:
 passwd          - Change the file's password
 add <name>      - Add a new entry
 rm  <name>      - Delete an entry
 mv  <old> <new> - Rename an entry
 ls  [search]    - Search for entries, leave [search] blank to list all entries
 cd  [search]    - "cd" into an entry, omit argument to return to root
 labels <lbl...> - Search entries by labels (entry must have all given labels)

CD aware commands (omit name|search when cd'd into entry):
 show <search> [snapshot]    - Dump the entire entry (optionally at a specific snapshot)
 set  <search> <key> <value> - Set a value on an entry (set pass can omit value to use generator)
 get  <search> <key> [index] - Show a specific part of an entry (notes/labels can use index)
 cp   <search> <key> [index] - Copy a specific part of an entry to the clipboard
 open <search>               - Open url key using the browser (linux only atm, xdg-open shell out)

 note    <search>            - Add a note
 rmnote  <search> <index>    - Delete a note
 label   <search>            - Add labels
 rmlabel <search> <label>    - Remove a label

Clipboard copy shortcuts (equivalent to cp name CMD):
 pass  <search>       - Copy password to clipboard
 user  <search>       - Copy username to clipboard
 email <search>       - Copy email to clipboard
 totp  <search>       - Copy twofactor to clipboard

Sync commands:
 sync              - Synchronize the file with all sources (pull, merge, push)
 sync add <ssh>    - Add an automatic synchronization option
 sync rm  <name>   - Removes automatic synchronization (use rm to delete sync entries permanently)

Debug commands:
 dump <search>     - Dumps an entire entry in debug mode
 dumpall           - Dumps the entire store in debug mode

Common Arguments:
  name:   a fully qualified name
  search: a fuzzy search (breaks on / for pseudo-folder structuring)
  index:  the number representing the item, not 0-based
`

const (
	promptColor  = color.FgLightBlue
	normalPrompt = "(%s)> "
	dirPrompt    = "(%s):%s> "
)

type repl struct {
	ctx *uiContext

	prompt   string
	ctxEntry string
}

func (r *repl) run() error {
	r.prompt = promptColor.Sprintf(normalPrompt, r.ctx.shortFilename)
	r.ctxEntry = ""

	for {
		unknownCmd := false
		line, err := r.ctx.term.Line(r.prompt)
		switch err {
		case ErrInterrupt:
			return err
		case ErrEnd:
			// All done
			return nil
		case nil:
			// Allow through
		default:
			return err
		}

		line = strings.TrimSpace(line)
		splits := strings.Fields(line)
		if len(splits) == 0 {
			continue
		}

		cmd := splits[0]
		splits = splits[1:]

		switch cmd {
		case "passwd":
			err = r.ctx.passwd()

		case "add":
			if len(splits) < 1 {
				errColor.Println("syntax: add <name>")
				continue
			}
			err = r.ctx.addNewInterruptible(splits[0])

		case "mv":
			if len(splits) < 2 {
				errColor.Println("syntax: mv <old> <new>")
				continue
			}

			err = r.ctx.rename(splits[0], splits[1])

		case "rm":
			if len(splits) < 1 {
				errColor.Println("syntax: rm <name>")
				continue
			}
			name := splits[0]
			err = r.ctx.remove(name)

			if err == nil && r.ctxEntry == name {
				r.ctxEntry = ""
				r.prompt = promptColor.Sprintf(normalPrompt, r.ctx.shortFilename)
			}

		case "ls":
			search := ""
			if len(splits) != 0 {
				search = splits[0]
			}
			err = r.ctx.list(search)

		case "cd":
			switch len(splits) {
			case 0:
				r.prompt = promptColor.Sprintf(normalPrompt, r.ctx.shortFilename)
			case 1:
				var uuid string
				uuid, err = r.ctx.findOne(splits[0])
				if err != nil {
					return err
				}
				if len(uuid) == 0 {
					continue
				}

				blob, err := r.ctx.store.Get(uuid)
				if err != nil {
					return err
				}

				r.ctxEntry = blob.Name()
				r.prompt = promptColor.Sprintf(dirPrompt, r.ctx.shortFilename, r.ctxEntry)
			default:
				fmt.Println("cd needs an argument")
			}

		case "cp", "get":
			name := r.ctxEntry
			if len(splits) < 1 || (len(splits) < 2 && len(name) == 0) {
				errColor.Printf("syntax: %s <search> <key> [index]\n", cmd)
				continue
			}

			if len(name) == 0 {
				name = splits[0]
				splits = splits[1:]
			}

			key := splits[0]
			splits = splits[1:]

			index := -1
			if len(splits) != 0 {
				i, err := strconv.Atoi(splits[0])
				if err != nil {
					errColor.Println("Index must be an integer")
					continue
				}
				index = i
			}

			err = r.ctx.get(name, key, index, cmd == "cp")

		case "totp", blobformat.KeyUser, blobformat.KeyPass, blobformat.KeyEmail:
			name := r.ctxEntry
			if len(splits) < 1 && len(name) == 0 {
				errColor.Printf("syntax: %s <search>\n", cmd)
				continue
			}

			if len(name) == 0 {
				name = splits[0]
				splits = splits[1:]
			}

			err = r.ctx.get(name, cmd, -1, true)

		case "set":
			name := r.ctxEntry
			var key, value string
			showHelpErr := false
			doPassSet := false

			switch len(splits) {
			case 0:
				showHelpErr = true
			case 1:
				// context is set, and the arg is pass
				key = splits[0]
				doPassSet = len(name) != 0 && key == "pass"
				showHelpErr = !doPassSet
			case 2:
				// With two args we have two valid possibilities:
				// context not set & key == "pass"
				// set <name> "pass"
				// context set & key, value
				// cd <name>; set <key> <value>
				if len(name) == 0 && splits[1] == "pass" {
					name = splits[0]
					key = splits[1]
					doPassSet = true
				} else if len(name) != 0 {
					key, value = splits[0], splits[1]
				} else {
					showHelpErr = true
				}
			default:
				// We have at least 3 args so we can fill name/key/value easily
				if len(name) == 0 {
					name = splits[0]
					splits = splits[1:]
				}

				key = splits[0]
				value = splits[1]
				splits = splits[2:]
			}

			if showHelpErr {
				errColor.Println("syntax: set <search> <key> <value>")
				break
			} else if doPassSet {
				err = r.ctx.set(name, key, "")
				if err == io.EOF {
					errColor.Println("Aborted")
				} else if err != nil {
					break
				}
				continue
			}

			if len(splits) > 0 {
				// This means there's extra pieces at the end, because we
				// parsed with strings.Fields() recombining with strings.Join
				// is lossy. In order to have a nice interface we'll find the
				// key in the line after the set command (so we don't get fooled
				// by keys named set)
				indexKey := strings.Index(line[3:], key)
				if indexKey <= 0 {
					errColor.Println("failed to parse set command")
					continue
				}

				// 3 = compensation for offsetting the slice above
				// 1 = space between key and value
				indexKey += 3 + 1 + len(key)
				value = line[indexKey:]
			}

			err = r.ctx.set(name, key, value)

		case "open":
			name := r.ctxEntry
			if len(name) == 0 {
				if len(splits) == 0 {
					errColor.Println("syntax: open <search>")
					continue
				}
				name = splits[0]
			}

			err = r.ctx.openurl(name)

		case "note":
			name := r.ctxEntry
			if len(name) == 0 {
				if len(splits) == 0 {
					errColor.Println("syntax: note <search>")
					continue
				}
				name = splits[0]
			}

			err = r.ctx.addNote(name)

		case "rmnote":
			name := r.ctxEntry
			if len(splits) < 1 || (len(name) == 0 && len(splits) < 2) {
				errColor.Println("syntax: rmnote <search> <index>")
				continue
			}

			if len(name) == 0 {
				name = splits[0]
				splits = splits[1:]
			}

			number, err := strconv.Atoi(splits[0])
			if err != nil {
				errColor.Printf("%q is not a number\n", splits[0])
				continue
			}

			err = r.ctx.deleteNote(name, number)

		case "label":
			name := r.ctxEntry
			if len(name) == 0 {
				if len(splits) == 0 {
					errColor.Println("syntax: label <search>")
					continue
				}
				name = splits[0]
			}

			err = r.ctx.addLabels(name)

		case "rmlabel":
			name := r.ctxEntry
			if len(splits) < 1 || (len(name) == 0 && len(splits) < 2) {
				errColor.Println("syntax: rmlabel <search> <label>")
				continue
			}

			if len(name) == 0 {
				name = splits[0]
				splits = splits[1:]
			}

			err = r.ctx.deleteLabel(name, splits[0])

		case "labels":
			if len(splits) == 0 {
				errColor.Println("syntax: labels <label...>")
				continue
			}

			err = r.ctx.listByLabels(splits)

		case "show":
			name := r.ctxEntry
			snapshot := 0
			if len(name) == 0 {
				// We need to get a name
				if len(splits) == 0 {
					errColor.Println("syntax: show <search> [snapshot]")
					continue
				}
				name = splits[0]
				splits = splits[1:]

			}
			if len(splits) != 0 {
				// THe user gave us a snapshot ^_^
				snapshot, err = strconv.Atoi(splits[0])
				if err != nil {
					snapshot = 0
				}
			}
			err = r.ctx.show(name, snapshot)
		case "sync":
			if len(splits) == 0 {
				err = r.ctx.sync()
			} else {
				kind := splits[1]
				switch splits[0] {
				case "add":
					err = r.ctx.syncAdd(kind)
				case "rm":
					err = r.ctx.syncRemove(kind)
				default:
					errColor.Println("syntax: sync add <kind>")
				}
			}

		case "dump":
			name := r.ctxEntry
			if len(name) == 0 {
				if len(splits) == 0 {
					errColor.Println("syntax: dump <search>")
					continue
				}
				name = splits[0]
			}

			err = r.ctx.dump(name)

		case "dumpall":
			err = r.ctx.dumpall()

		case "help":
			fmt.Println(replHelp)
		default:
			unknownCmd = true
		}

		if err != nil {
			return err
		}

		if unknownCmd {
			fmt.Println(`unknown command, try "help"`)
		} else {
			r.ctx.term.AddHistory(line)
		}
	}
}

func (u *uiContext) prompt(prompt string) (string, error) {
	line, err := u.term.Line(prompt)
	if err != nil {
		return "", err
	}

	return line, nil
}

// findOne returns a uuid iff a single one could be found, else an error
// message will have been printed to the user.
func (u *uiContext) findOne(search string) (string, error) {
	entries, err := u.store.Search(search)
	if err != nil {
		return "", err
	}

	switch len(entries) {
	case 0:
		errColor.Printf("No matches for search (%q)\n", search)
		return "", nil
	case 1:
		ids := entries.UUIDs()
		id := ids[0]
		name := entries[id]
		if search != name {
			infoColor.Printf("using: %s\n", name)
		}

		return id, nil
	}

	names := entries.Names()
	sort.Strings(names)
	errColor.Printf("Multiple matches for search (%q):", search)
	fmt.Print("\n  ")
	fmt.Println(strings.Join(names, "\n  "))

	return "", nil
}

// getString ensures a non-empty string
func (u *uiContext) getString(key string) (string, error) {
	var str string
	var err error

Again:
	str, err = u.prompt(inputPromptColor.Sprint(key + ": "))
	if err != nil {
		return "", err
	}
	if len(str) == 0 {
		errColor.Println(key, "cannot be empty")
		goto Again
	}

	return str, nil
}

func (u *uiContext) getInt(key string, min, max int) (int, error) {
	var str string
	var err error
	var integer int

Again:
	str, err = u.prompt(inputPromptColor.Sprint(key + ": "))
	if err != nil {
		return 0, err
	}

	if len(str) == 0 {
		errColor.Println(key, "cannot be empty")
		goto Again
	}

	integer, err = strconv.Atoi(str)
	if err != nil {
		errColor.Printf("%s must be an integer between %d and %d\n", key, min, max)
		goto Again
	}

	return integer, nil
}

func (u *uiContext) getMenuChoice(prompt string, items []string) (int, error) {
	var choice string
	var integer int
	var i int
	var item string
	var err error

Again:
	for i, item = range items {
		inputPromptColor.Printf(" %d) %s\n", i+1, item)
	}
	choice, err = u.prompt(infoColor.Sprint(prompt))
	if err != nil {
		return 0, err
	}

	integer, err = strconv.Atoi(choice)
	if err != nil {
		errColor.Println("invalid choice")
		goto Again
	}

	integer--
	if integer < 0 || integer >= len(items) {
		goto Again
	}

	return integer, nil
}
