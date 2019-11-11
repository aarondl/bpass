package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aarondl/bpass/blobformat"
	"github.com/aarondl/color"
)

const replHelp = `Bpass repl uses analogs to basic unix commands for general
familiarity and brevity however it's important to note that there is no actual
directory hierarchy, you can however "cd" into an entry to omit specifying
the entry name as a query in the key commands below.

General Commands:
 passwd       - Change the file's password for current user
 help [topic] - This help (how did you find this without seeing this help?)
 exit         - Exit the repl

Entry Commands (manage entries in the file):
 add <name>      - Add a new entry
 rm  <name>      - Delete an entry
 mv  <old> <new> - Rename an entry
 ls  [query]     - Lists entries, query restricts entries to a fuzzy match
 cd  [query]     - "cd" into an entry, omit argument to return to root
 labels <lbl...> - List entries by labels (entry must have all given labels)

Key commands (manage keys in entries, use "cd" command to omit query from these commands):
 show <query> [snapshot]    - Show all keys for an entry (optionally at a specific snapshot)
 set  <query> <key> [value] - Set a value on an entry (omit value for multi-line or password gen)
 get  <query> <key>         - Show a specific key of an entry
 cp   <query> <key>         - Copy a specific key of an entry to the clipboard
 edit <query> <key>         - Open $EDITOR to edit an existing value
 open <query>               - Launch browser using value in url key
 rmk  <query> <key>         - Delete a key from an entry

 label   <query>            - Add labels in an easier way than with set
 rmlabel <query> <label>    - Remove labels in an easier way than with edit

Clipboard copy shortcuts (alias of cp <query> <key>):
 pass  <query>       - Copy password to clipboard
 user  <query>       - Copy username to clipboard
 email <query>       - Copy email to clipboard
 totp  <query>       - Copy twofactor to clipboard

Other help topics (use help <topic>):
 sync, users, other

Common Arguments:
  name:   a fully qualified name
  query:  a fuzzy search (breaks on / for pseudo-folder structuring)
  index:  the number representing the item, not 0-based
`

var syncHelp = `Syncing the file with remotes in bpass is done via sync entries.

A sync entry must have a url key with the type of sync as it's schema
(eg. scp://) as the most basic requirement.

Certain sync types (such as scp) may require other keys to be present to work
correctly. The best way to ensure that you have a properly configured sync
entry is to use the "addsync" command.

Additionally if the "sync" key of an entry is set to "true" then this entry
will be automatically synchronized when an auto-sync occurs (usually
when opening/closing the file, or running "sync" with no arguments)

Types of sync: scp, file

Example of values in an auto-sync scp account:
 url: scp://myuser@localhost.com:22/folder/filename.blob
 sync: true
 privkey: ======= RSA PRIVATE KEY ======= ...
 pubkey: ssh-rsa AAA...238da friend@bpass.com

Sync Commands:
 sync    [name]  - Sync (Pull, Merge, Push) the file to all auto-sync accounts (or a given account)
 addsync <kind>  - Sync entry setup wizard (help sync for more details)
`

var usersHelp = `Users in bpass are managed using user entries.

When you first start a file, it is a single-user file and multi-user is not
considered at all. When you first call adduser, the current user (you) are
converted to a user entry in the database (user/<username>).

Users are just entries with a particular naming scheme of: user/<username>

These entries contain many system fields that cannot be set manually but apart
from those user entries are unremarkable and can be renamed with mv or deleted
with rm. (Remember when renaming to keep the user/ prefix intact or the user
will no longer be considered a user).

User/Password Commands:
 adduser <user> - Add user to the file (first add should use current user's username)
 passwd  [user] - Change the file's password for current user, or a specific user
 rekey   [user] - Rekey the file (change salt) for current user, or a specific user
 rekeyall       - Nuclear button, change all passwords & master key for all users
`

var otherHelp = `Debug commands:
 dump <query>      - Dumps an entire entry in debug mode
 dumpall           - Dumps the entire store in debug mode
`

const (
	mainPromptColor = color.FgBrightBlue
	normalPrompt    = "(%s)> "
	dirPrompt       = "(%s):%s> "
)

type repl struct {
	ctx *uiContext

	prompt   string
	ctxEntry string
}

func (r *repl) run() error {
	r.prompt = mainPromptColor.Sprintf(normalPrompt, r.ctx.shortFilename)
	r.ctxEntry = ""

	for {
		unknownCmd := false
		line, err := r.ctx.in.Line(r.prompt)
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
			var user string
			if len(splits) > 0 {
				user = splits[0]
			}

			err = r.ctx.passwd(user)

		case "adduser":
			if len(splits) == 0 {
				errColor.Println("syntax: adduser <user>")
				continue
			}

			err = r.ctx.adduser(splits[0])

		case "rekey":
			var user string
			if len(splits) > 0 {
				user = splits[0]
			}

			err = r.ctx.rekey(user)

		case "rekeyall":
			err = r.ctx.rekeyAll()

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
				r.prompt = mainPromptColor.Sprintf(normalPrompt, r.ctx.shortFilename)
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
				r.prompt = mainPromptColor.Sprintf(normalPrompt, r.ctx.shortFilename)
			case 1:
				var uuid string
				uuid, err = r.ctx.findOne(splits[0])
				if err != nil {
					return err
				}
				if len(uuid) == 0 {
					continue
				}

				blob, err := r.ctx.store.MustFind(uuid)
				if err != nil {
					return err
				}

				r.ctxEntry = blob.Name()
				r.prompt = mainPromptColor.Sprintf(dirPrompt, r.ctx.shortFilename, r.ctxEntry)
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

		case "totp", blobformat.KeyUser, blobformat.KeyPass, blobformat.KeyEmail:
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
			var name string
			if len(splits) > 0 {
				name = splits[0]
			}

			err = r.ctx.sync(name, false, true)

		case "addsync":
			if len(splits) == 0 {
				errColor.Println("syntax: addsync <kind>")
				continue
			}
			err = r.ctx.addSyncInterruptible(splits[0])

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
			if len(splits) == 0 {
				fmt.Print(replHelp)
			} else if splits[0] == "sync" {
				fmt.Print(syncHelp)
			} else if splits[0] == "users" {
				fmt.Print(usersHelp)
			} else if splits[0] == "other" {
				fmt.Print(otherHelp)
			}

		case "exit":
			return nil

		default:
			unknownCmd = true
		}

		if err != nil {
			return err
		}

		if unknownCmd {
			fmt.Println(`unknown command, try "help"`)
		} else {
			r.ctx.in.AddHistory(line)
		}
	}
}
