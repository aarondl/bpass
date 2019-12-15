package main

import (
	"errors"
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

var (
	errExit = errors.New("exit")
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
		args := strings.Fields(line)
		if len(args) == 0 {
			continue
		}

		cmd := args[0]
		// Special case this thing, no commands care about additional space
		// except set
		if cmd == "set" {
			args = strings.Split(line, " ")
		}
		args = args[1:]

		replCommand, ok := replCmds[cmd]
		if !ok {
			fmt.Println(`unknown command, try "help"`)
			continue
		}

		if r.ctx.readOnly && !replCommand.ReadOnly {
			errColor.Println("cannot use write commands in read-only mode")
			continue
		}

		err = replCommand.Run(r, cmd, args)
		if err == errExit {
			return nil
		} else if err != nil {
			return err
		}

		r.ctx.in.AddHistory(line)
	}
}

type replCmd struct {
	ReadOnly bool
	Run      func(r *repl, cmd string, args []string) error
}

var replCmds = map[string]replCmd{
	"passwd": {
		Run: func(r *repl, cmd string, args []string) error {
			var user string
			if len(args) > 0 {
				user = args[0]
			}

			return r.ctx.passwd(user)
		},
	},

	"adduser": {
		Run: func(r *repl, _ string, args []string) error {
			if len(args) == 0 {
				errColor.Println("syntax: adduser <user>")
				return nil
			}

			return r.ctx.adduser(args[0])
		},
	},

	"rekey": {
		Run: func(r *repl, _ string, args []string) error {
			var user string
			if len(args) > 0 {
				user = args[0]
			}

			return r.ctx.rekey(user)
		},
	},

	"rekeyall": {
		Run: func(r *repl, _ string, args []string) error {
			return r.ctx.rekeyAll()
		},
	},

	"add": {
		Run: func(r *repl, _ string, args []string) error {
			if len(args) < 1 {
				errColor.Println("syntax: add <name>")
				return nil
			}
			return r.ctx.addNewInterruptible(args[0])
		},
	},

	"mv": {
		Run: func(r *repl, _ string, args []string) error {
			if len(args) < 2 {
				errColor.Println("syntax: mv <old> <new>")
				return nil
			}

			return r.ctx.rename(args[0], args[1])
		},
	},

	"rm": {
		Run: func(r *repl, _ string, args []string) error {
			if len(args) < 1 {
				errColor.Println("syntax: rm <name>")
				return nil
			}
			name := args[0]
			err := r.ctx.deleteEntry(name)

			if err == nil && r.ctxEntry == name {
				r.ctxEntry = ""
				r.prompt = mainPromptColor.Sprintf(normalPrompt, r.ctx.shortFilename)
			}

			return err
		},
	},

	"rmk": {
		Run: func(r *repl, _ string, args []string) error {
			name := r.ctxEntry
			if len(args) < 1 || (len(name) == 0 && len(args) < 2) {
				errColor.Println("syntax: rmk <query> <key>")
				return nil
			}

			if len(name) == 0 {
				name = args[0]
				args = args[1:]
			}

			return r.ctx.deleteKey(name, args[0])
		},
	},

	"ls": {
		ReadOnly: true,
		Run: func(r *repl, _ string, args []string) error {
			query := ""
			if len(args) != 0 {
				query = args[0]
			}
			return r.ctx.list(query)
		},
	},

	"cd": {
		ReadOnly: true,
		Run: func(r *repl, _ string, args []string) error {
			switch len(args) {
			case 0:
				r.ctxEntry = ""
				r.prompt = mainPromptColor.Sprintf(normalPrompt, r.ctx.shortFilename)
			case 1:
				var uuid string
				var err error
				uuid, err = r.ctx.findOne(args[0])
				if err != nil {
					return err
				}
				if len(uuid) == 0 {
					return nil
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

			return nil
		},
	},

	"cp":                    {ReadOnly: true, Run: getCopy},
	"get":                   {ReadOnly: true, Run: getCopy},
	blobformat.KeyUser:      {ReadOnly: true, Run: quickCopy},
	blobformat.KeyPass:      {ReadOnly: true, Run: quickCopy},
	blobformat.KeyEmail:     {ReadOnly: true, Run: quickCopy},
	blobformat.KeyTwoFactor: {ReadOnly: true, Run: quickCopy},

	"set": {
		Run: func(r *repl, cmd string, args []string) error {
			name := r.ctxEntry
			var key, value string

			// with context:
			// set key
			// set key val
			// without context:
			// set name key
			// set name key value

			// Set's args are a special case, they are given from
			// strings.Split not strings.Fields which means there are
			// potentially empty string arguments lurking around.

			syntaxErr := func() error {
				errColor.Println("syntax: set <query> <key> [value]")
				return nil
			}

			if len(args) < 1 || (len(name) == 0 && len(args) < 2) {
				return syntaxErr()
			}

			if len(name) == 0 {
				name = args[0]
				args = args[1:]
			}

			key = args[0]
			args = args[1:]

			if len(name) == 0 || len(key) == 0 {
				return syntaxErr()
			}

			if len(args) == 1 {
				value = args[0]
			} else if len(args) > 1 {
				value = strings.Join(args, " ")
			}

			return r.ctx.set(name, key, value)
		},
	},

	"edit": {
		Run: func(r *repl, cmd string, args []string) error {
			name := r.ctxEntry
			if len(args) < 1 || (len(name) == 0 && len(args) < 2) {
				errColor.Println("syntax: edit <query> <key>")
				return nil
			}

			if len(name) == 0 {
				name = args[0]
				args = args[1:]
			}

			key := args[0]
			return r.ctx.edit(name, key)
		},
	},

	"open": {
		ReadOnly: true,
		Run: func(r *repl, cmd string, args []string) error {
			name := r.ctxEntry
			if len(name) == 0 {
				if len(args) == 0 {
					errColor.Println("syntax: open <query>")
					return nil
				}
				name = args[0]
			}

			return r.ctx.openurl(name)
		},
	},

	"label": {
		Run: func(r *repl, cmd string, args []string) error {
			name := r.ctxEntry
			if len(name) == 0 {
				if len(args) == 0 {
					errColor.Println("syntax: label <query>")
					return nil
				}
				name = args[0]
			}

			return r.ctx.addLabels(name)
		},
	},

	"rmlabel": {
		Run: func(r *repl, cmd string, args []string) error {
			name := r.ctxEntry
			if len(args) < 1 || (len(name) == 0 && len(args) < 2) {
				errColor.Println("syntax: rmlabel <query> <label>")
				return nil
			}

			if len(name) == 0 {
				name = args[0]
				args = args[1:]
			}

			return r.ctx.deleteLabel(name, args[0])
		},
	},

	"labels": {
		ReadOnly: true,
		Run: func(r *repl, cmd string, args []string) error {
			if len(args) == 0 {
				errColor.Println("syntax: labels <label...>")
				return nil
			}

			return r.ctx.listByLabels(args)
		},
	},

	"show": {
		ReadOnly: true,
		Run: func(r *repl, cmd string, args []string) error {
			name := r.ctxEntry
			snapshot := 0
			var err error
			if len(name) == 0 {
				// We need to get a name
				if len(args) == 0 {
					errColor.Println("syntax: show <query> [snapshot]")
					return nil
				}
				name = args[0]
				args = args[1:]

			}
			if len(args) != 0 {
				// The user gave us a snapshot ^_^
				snapshot, err = strconv.Atoi(args[0])
				if err != nil {
					snapshot = 0
				}
			}
			return r.ctx.show(name, snapshot)
		},
	},

	"sync": {
		Run: func(r *repl, cmd string, args []string) error {
			var name string
			if len(args) > 0 {
				name = args[0]
			}

			return r.ctx.sync(name, false, true)
		},
	},

	"addsync": {
		Run: func(r *repl, cmd string, args []string) error {
			if len(args) == 0 {
				errColor.Println("syntax: addsync <kind>")
				return nil
			}
			return r.ctx.addSyncInterruptible(args[0])
		},
	},

	"dump": {
		ReadOnly: true,
		Run: func(r *repl, cmd string, args []string) error {
			name := r.ctxEntry
			if len(name) == 0 {
				if len(args) == 0 {
					errColor.Println("syntax: dump <query>")
					return nil
				}
				name = args[0]
			}

			return r.ctx.dump(name)
		},
	},

	"dumpall": {
		ReadOnly: true,
		Run: func(r *repl, cmd string, args []string) error {
			return r.ctx.dumpall()
		},
	},

	"help": {
		ReadOnly: true,
		Run: func(r *repl, cmd string, args []string) error {
			if len(args) == 0 {
				fmt.Print(replHelp)
			} else if args[0] == "sync" {
				fmt.Print(syncHelp)
			} else if args[0] == "users" {
				fmt.Print(usersHelp)
			} else if args[0] == "other" {
				fmt.Print(otherHelp)
			}
			return nil
		},
	},

	"exit": {
		ReadOnly: true,
		Run: func(r *repl, cmd string, args []string) error {
			return errExit
		},
	},
}

func getCopy(r *repl, cmd string, args []string) error {
	name := r.ctxEntry
	if len(args) < 1 || (len(args) < 2 && len(name) == 0) {
		errColor.Printf("syntax: %s <query> <key> [index]\n", cmd)
		return nil
	}

	if len(name) == 0 {
		name = args[0]
		args = args[1:]
	}

	key := args[0]
	args = args[1:]

	index := -1
	if len(args) != 0 {
		i, err := strconv.Atoi(args[0])
		if err != nil {
			errColor.Println("Index must be an integer")
			return nil
		}
		index = i
	}

	return r.ctx.get(name, key, index, cmd == "cp")
}

func quickCopy(r *repl, cmd string, args []string) error {
	name := r.ctxEntry
	if len(args) < 1 && len(name) == 0 {
		errColor.Printf("syntax: %s <query>\n", cmd)
		return nil
	}

	if len(name) == 0 {
		name = args[0]
		args = args[1:]
	}

	return r.ctx.get(name, cmd, -1, true)
}
