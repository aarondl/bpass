package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/aarondl/bpass/txblob"
	"github.com/gookit/color"
)

const replHelp = `Bpass repl uses analogs to basic unix commands for general
familiarity and brevity however it's important to note that there's no actual
directory hierarchy, you can however "cd" into an entry to omit specifying
the entry query in key commands.

Global Commands:
 passwd          - Change the file's password
 sync            - Synchronize the file with all sources (pull, merge, push)
 sync add <scp>  - Add a sync entry (does ssh keygen)

Entry Commands:
 add <name>      - Add a new entry
 rm  <name>      - Delete an entry
 mv  <old> <new> - Rename an entry
 ls  [query]     - Lists entries, query restricts entries to a fuzzy match
 cd  [query]     - "cd" into an entry, omit argument to return to root
 labels <lbl...> - List entries by labels (entry must have all given labels)

Key commands (cd <query> to omit query from these commands):
 show <query> [snapshot]    - Show all keys for an entry (optionally at a specific snapshot)
 set  <query> <key> [value] - Set a value on an entry (omit value for multi-line or password gen)
 get  <query> <key>         - Show a specific key of an entry (lists can use index)
 cp   <query> <key>         - Copy a specific key of an entry to the clipboard (lists can use index)
 edit <query> <key>         - Open $EDITOR to edit an existing value
 open <query>               - Launch browser using value in url key (requires xdg-open)
 rmk  <query> <key>         - Delete a key from an entry

 label   <query>            - Add labels in an easier way than with set
 rmlabel <query> <label>    - Remove labels in an easier way than with edit

Clipboard copy shortcuts (alias of cp <query> <key>):
 pass  <query>       - Copy password to clipboard
 user  <query>       - Copy username to clipboard
 email <query>       - Copy email to clipboard
 totp  <query>       - Copy twofactor to clipboard

Debug commands:
 dump <query>      - Dumps an entire entry in debug mode
 dumpall           - Dumps the entire store in debug mode

Common Arguments:
  name:   a fully qualified name
  query:  a fuzzy search (breaks on / for pseudo-folder structuring)
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
			err = r.ctx.deleteEntry(name)

			if err == nil && r.ctxEntry == name {
				r.ctxEntry = ""
				r.prompt = promptColor.Sprintf(normalPrompt, r.ctx.shortFilename)
			}

		case "rmk":
			name := r.ctxEntry
			if len(splits) < 1 || (len(name) == 0 && len(splits) < 2) {
				errColor.Println("syntax: rmk <query> <key>")
				continue
			}

			if len(name) == 0 {
				name = splits[0]
				splits = splits[1:]
			}

			err = r.ctx.deleteKey(name, splits[0])

		case "ls":
			query := ""
			if len(splits) != 0 {
				query = splits[0]
			}
			err = r.ctx.list(query)

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
				errColor.Printf("syntax: %s <query> <key> [index]\n", cmd)
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

		case "totp", txblob.KeyUser, txblob.KeyPass, txblob.KeyEmail:
			name := r.ctxEntry
			if len(splits) < 1 && len(name) == 0 {
				errColor.Printf("syntax: %s <query>\n", cmd)
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

			// with context:
			// set key
			// set key val
			// without context:
			// set name key
			// set name key value

			if len(splits) < 1 || (len(name) == 0 && len(splits) < 2) {
				errColor.Println("syntax: set <query> <key> [value]")
				continue
			}

			if len(name) == 0 {
				name = splits[0]
				splits = splits[1:]
			}

			key = splits[0]
			splits = splits[1:]

			if len(splits) != 0 {
				value = splits[0]
				splits = splits[1:]
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

		case "edit":
			name := r.ctxEntry
			if len(splits) < 1 || (len(name) == 0 && len(splits) < 2) {
				errColor.Println("syntax: edit <query> <key>")
				continue
			}

			if len(name) == 0 {
				name = splits[0]
				splits = splits[1:]
			}

			key := splits[0]
			err = r.ctx.edit(name, key)

		case "open":
			name := r.ctxEntry
			if len(name) == 0 {
				if len(splits) == 0 {
					errColor.Println("syntax: open <query>")
					continue
				}
				name = splits[0]
			}

			err = r.ctx.openurl(name)

		case "label":
			name := r.ctxEntry
			if len(name) == 0 {
				if len(splits) == 0 {
					errColor.Println("syntax: label <query>")
					continue
				}
				name = splits[0]
			}

			err = r.ctx.addLabels(name)

		case "rmlabel":
			name := r.ctxEntry
			if len(splits) < 1 || (len(name) == 0 && len(splits) < 2) {
				errColor.Println("syntax: rmlabel <query> <label>")
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
					errColor.Println("syntax: show <query> [snapshot]")
					continue
				}
				name = splits[0]
				splits = splits[1:]

			}
			if len(splits) != 0 {
				// The user gave us a snapshot ^_^
				snapshot, err = strconv.Atoi(splits[0])
				if err != nil {
					snapshot = 0
				}
			}
			err = r.ctx.show(name, snapshot)

		case "sync":
			if len(splits) == 0 {
				err = r.ctx.sync(false, true)
			} else {
				kind := splits[1]
				switch splits[0] {
				case "add":
					err = r.ctx.syncAdd(kind)
				default:
					errColor.Println("syntax: sync add <kind>")
				}
			}

		case "dump":
			name := r.ctxEntry
			if len(name) == 0 {
				if len(splits) == 0 {
					errColor.Println("syntax: dump <query>")
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

func (u *uiContext) promptMultiline(prompt string) (string, error) {
	infoColor.Println(`Enter text, 2 empty lines or "." or ctrl-d to stop:`)

	var lines []string
	oneBlank := false
	for {
		line, err := u.prompt(prompt)
		if err == ErrEnd || line == "." {
			break
		} else if err != nil {
			return "", err
		}

		if line == "." {
			break
		} else if len(line) == 0 {
			if oneBlank {
				break
			}
			oneBlank = true
			continue
		}

		if oneBlank {
			lines = append(lines, "")
			oneBlank = false
		}

		lines = append(lines, line)
	}

	return strings.Join(lines, "\n"), nil
}

// findOne returns a uuid iff a single one could be found, else an error
// message will have been printed to the user.
func (u *uiContext) findOne(query string) (string, error) {
	entries, err := u.store.Search(query)
	if err != nil {
		return "", err
	}

	switch len(entries) {
	case 0:
		errColor.Printf("No matches for query (%q)\n", query)
		return "", nil
	case 1:
		ids := entries.UUIDs()
		id := ids[0]
		name := entries[id]
		if query != name {
			infoColor.Printf("using: %s\n", name)
		}

		return id, nil
	}

	// If there's an exact match use that
	for u, name := range entries {
		if name == query {
			return u, nil
		}
	}

	names := entries.Names()
	sort.Strings(names)
	errColor.Printf("Multiple matches for query (%q):", query)
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
