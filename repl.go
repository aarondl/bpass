package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/aarondl/bpass/blobformat"
	"github.com/chzyer/readline"
)

var replHelp = `Commands:
 add <name>      - Add a new entry
 rm  <name>      - Delete an entry
 mv  <old> <new> - Rename an entry
 ls [search]  - Search for entries, leave [search] blank to list all entries
 cd [search]  - "cd" into an entry, omit argument to return to root

 labels <label...> - Search entries by labels (entry must have all given labels)

CD aware commands (omit name|search when cd'd into entry):
 show <search> [snapshot]    - Dump the entire entry (optionally at a specific snapshot)
 set  <search> <key> <value> - Set a value on an entry (set pass can omit value to use generator)
 get  <search> <key> [index] - Show a specific part of an entry (notes/labels can use index)
 cp   <search> <key> [index] - Copy a specific part of an entry to the clipboard

 note    <search>            - Add a note
 rmnote  <search> <index>    - Delete a note
 label   <search>            - Add labels
 rmlabel <search> <label>    - Remove a label

Clipboard copy shortcuts (equivalent to cp name CMD):
 pass  <search>       - Copy password to clipboard
 user  <search>       - Copy username to clipboard
 email <search>       - Copy email to clipboard
 totp  <search>       - Copy twofactor to clipboard

Arguments:
  name:   a fully qualified name
  search: a fuzzy search (breaks on / for pseudo-folder structuring)
  index:  the number representing the item, not 0-based
`

type repl struct {
	ctx *uiContext
}

func (r repl) run() error {
	var contextName string

	for {
		line, err := r.ctx.rl.Readline()
		switch err {
		case readline.ErrInterrupt:
			return err
		case io.EOF:
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

			if err == nil && name == contextName {
				r.ctx.promptDir = contextName
				r.ctx.readlineResetPrompt()
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
				contextName = ""
				r.ctx.promptDir = ""
				r.ctx.readlineResetPrompt()
			case 1:
				name, ok := r.ctx.singleName(splits[0])
				if !ok {
					continue
				}
				contextName = name
				r.ctx.promptDir = name
				r.ctx.readlineResetPrompt()
			default:
				fmt.Println("cd needs an argument")
			}

		case "cp", "get":
			name := contextName
			if len(splits) < 1 || (len(splits) < 2 && len(name) == 0) {
				errColor.Printf("syntax: %s <search> <key> [index]", cmd)
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
			name := contextName
			if len(splits) < 1 && len(name) == 0 {
				errColor.Printf("syntax: %s <search>", cmd)
				continue
			}

			if len(name) == 0 {
				name = splits[0]
				splits = splits[1:]
			}

			err = r.ctx.get(name, cmd, -1, true)

		case "set":
			name := contextName
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
				fmt.Println(`N, K, V`)
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
					r.ctx.readlineResetPrompt()
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

		case "note":
			name := contextName
			if len(name) == 0 {
				if len(splits) == 0 {
					errColor.Println("syntax: note <search>")
					continue
				}
				name = splits[0]
			}

			err = r.ctx.addNote(name)

		case "rmnote":
			name := contextName
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
				errColor.Printf("%q is not a number", splits[0])
				continue
			}

			err = r.ctx.deleteNote(name, number)

		case "label":
			name := contextName
			if len(name) == 0 {
				if len(splits) == 0 {
					errColor.Println("syntax: label <search>")
					continue
				}
				name = splits[0]
			}

			err = r.ctx.addLabels(name)

		case "rmlabel":
			name := contextName
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
			name := contextName
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
		case "help":
			fmt.Println(replHelp)
		default:
			fmt.Println(`unknown command, try "help"`)
		}

		if err != nil {
			return err
		}
	}
}
