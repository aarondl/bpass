package main

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gookit/color"

	"github.com/aarondl/bpass/blobformat"
	"github.com/chzyer/readline"
	"github.com/davecgh/go-spew/spew"
)

var replHelp = `Commands:
simple commands:
 new <name>   - Create a new entry
 ls [search]  - Search for entries, leave [search] blank to list all entries
 cd [search]  - "cd" into an entry, omit [search] to return to root

cd aware (when cd'd these commands do not require a search argument):
 show <search> [snapshot]    - Dump the entire entry (optionally at a specific snapshot)
 set  <search> <key> <value> - Set a value on an entry
 get  <search> <key>         - Show a specific part of an entry
 cp   <search> <key>         - Copy a specific part of an entry to the clipboard

 note    <search>            - Add a note
 rmnote  <search>            - Delete a note
 label   <search> <label>    - Add a label
 rmlabel <search> <label>    - Remove a label

 Arguments:
   name:   a fully qualified name
   search: a fuzzy search (breaks on / for pseudo-folder structuring)
`

func (u *uiContext) repl() error {
	var contextName string

	for {
		line, err := u.rl.Readline()
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

		splits := strings.Fields(strings.ToLower(line))
		if len(splits) == 0 {
			continue
		}

		cmd := splits[0]
		splits = splits[1:]

		switch cmd {
		case "new":
			if len(splits) < 1 {
				fmt.Println("syntax: new <name>")
				continue
			}
			err = u.addNew(splits[0])

		case "ls":
			search := ""
			if len(splits) != 0 {
				search = splits[0]
			}
			err = u.list(search)

		case "cd":
			switch len(splits) {
			case 0:
				contextName = ""
				readlineResetPrompt(u)
			case 1:
				name, ok := u.singleName(splits[0])
				if !ok {
					continue
				}
				contextName = name
				readlineDirPrompt(u, name)
			default:
				fmt.Println("cd needs an argument")
			}

		case "show":
			name := contextName
			snapshot := 0
			if len(name) == 0 {
				// We need to get a name
				if len(splits) == 0 {
					fmt.Println("syntax: show <name> [snapshot]")
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
			err = u.show(name, snapshot)
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

func (u *uiContext) addNew(name string) error {
	name = strings.ToLower(name)
	_, exist := u.store[name]
	if exist {
		fmt.Printf("%s already exists\n", name)
	}

	user, err := u.getSingleLine("user: ")
	if err != nil {
		return err
	}

	email, err := u.getSingleLine("email: ")
	if err != nil {
		return err
	}

	if len(user) != 0 {
		u.store.Set(name, blobformat.KeyUser, user)
	}
	if len(email) != 0 {
		u.store.Set(name, blobformat.KeyEmail, email)
	}
	pass, err := u.getPassword()
	if err != nil {
		return err
	}
	if len(pass) != 0 {
		u.store.Set(name, blobformat.KeyPass, pass)
	}

	var labels []string
	for {
		label, err := u.getSingleLine("add label: ")
		if err != nil {
			return err
		}

		if len(label) == 0 {
			break
		}

		labels = append(labels, label)
	}
	if len(labels) != 0 {
		u.store.SetLabels(name, labels)
	}

	spew.Dump(u.store)

	return nil
}

func (u *uiContext) getPassword() (string, error) {
	showSetting := func(n int) string {
		switch {
		case n < 0:
			return "off"
		case n == 0:
			return "any"
		}
		return strconv.Itoa(n)
	}
	setSetting := func(splits []string, n *int) {
		if len(splits) == 1 {
			if *n == 0 {
				*n = -1
			} else {
				*n = 0
			}
			return
		}

		i, err := strconv.Atoi(splits[1])
		if err != nil {
			fmt.Println("not an integer input")
			return
		}
		*n = i
	}

	length := 32
	upper, lower, number, basic, extra := 0, 0, 0, 0, 0

	help := func() {
		c := color.FgLightCyan
		c.Println("enter a number to adjust length, a letter to toggle/use a feature\nor a letter followed by a number to ensure at least n of that type")
		c.Printf("  length: %-3d [u]pper: %-3s [l]ower: %-3s\n", length, showSetting(upper), showSetting(lower))
		c.Printf("[n]umber: %-3s [b]asic: %-3s [e]xtra: %-3s\n", showSetting(number), showSetting(basic), showSetting(extra))
		c.Println("[y] accept password, [m] manual password entry, [enter] to regen password, [?] help")
	}
	help()

	for {
		password, err := genPassword(length, upper, lower, number, basic, extra)
		if err == errPasswordImpossible {
			fmt.Println("could not generate password with these requirements")
		} else if err != nil {
			return "", err
		} else {
			fmt.Println("password:", password)
		}

		choice, err := u.getSingleLine("u/l/n/b/e/y/m/enter/?> ")
		if err != nil {
			return "", err
		}

		splits := strings.Fields(choice)

		switch {
		case choice == "":
			// Regen
			continue
		case choice == "y":
			return password, nil
		case choice == "m":
			b, err := u.rl.ReadPassword("enter new password: ")
			return string(b), err
		case choice == "?":
			help()
		case splits[0] == "u":
			setSetting(splits, &upper)
		case splits[0] == "l":
			setSetting(splits, &lower)
		case splits[0] == "n":
			setSetting(splits, &number)
		case splits[0] == "b":
			setSetting(splits, &basic)
		case splits[0] == "e":
			setSetting(splits, &extra)
		default:
			newLen, err := strconv.Atoi(choice)
			if err != nil {
				fmt.Println("new length was not an integer")
				continue
			}
			length = newLen
		}
	}
}

func (u *uiContext) getSingleLine(prompt string) (string, error) {
	u.rl.SetPrompt(prompt)
	line, err := u.rl.Readline()
	if err != nil {
		return "", err
	}
	readlineResetPrompt(u)

	return line, nil
}

func (u *uiContext) list(search string) error {
	names := u.store.Find(search)
	sort.Strings(names)
	fmt.Println(strings.Join(names, "\n"))
	return nil
}

func (u *uiContext) show(search string, snapshot int) error {
	name, ok := u.singleName(search)
	if !ok {
		return nil
	}
	got := u.store.MustFind(name)

	snaps, err := got.NSnapshots()
	if err != nil {
		fmt.Println("failed on snapshots? wtf")
		return err
	}
	if snapshot != 0 {
		if snapshot > snaps {
			fmt.Printf("%s only has %d snapshots", name, snaps)
			return nil
		}

		got, err = got.Snapshot(snapshot)
		if err != nil {
			return err
		}
	}

	width := 8 // Hardcoded max of the known keys, sad, I know
	arbitrary := got.ArbitraryKeys()
	for _, k := range arbitrary {
		if len(k) > width {
			width = len(k) + 1 // +1 for :
		}
	}
	width *= -1

	keyColor := color.FgLightGreen
	passColor := color.New(color.FgYellow, color.BgYellow)
	fmt.Printf("%s %s\n", keyColor.Sprintf("%*s", width, "user:"), got.Get(blobformat.KeyUser))
	fmt.Printf("%s %s\n", keyColor.Sprintf("%*s", width, "email:"), got.Get(blobformat.KeyEmail))
	fmt.Printf("%s %s\n", keyColor.Sprintf("%*s", width, "pass:"), passColor.Sprint(got.Get(blobformat.KeyPass)))
	t, err := got.TwoFactor()
	if err != nil {
		fmt.Println("error retrieving two factor:", err)
	} else if len(t) != 0 {
		fmt.Printf("%s %s\n", keyColor.Sprintf("%*s", width, "totp:"), t)
	}

	labels, err := got.Labels()
	if err != nil {
		fmt.Println("error fetching labels:", err)
	} else if len(labels) > 0 {
		fmt.Printf("%s %s\n", keyColor.Sprintf("%*s", width, "labels:"), strings.Join(labels, ", "))
	}

	notes, err := got.Notes()
	if err != nil {
		fmt.Println("error retrieving notes:", err)
	} else if len(notes) > 0 {
		fmt.Printf("%s\n", keyColor.Sprintf("%*s", width, "notes:"))
		for i, note := range notes {
			// Format it nicely with newlines and indentation
			note = strings.ReplaceAll(note, "\n", "\n    ")
			fmt.Printf("%-4s %s", keyColor.Sprintf("%s", strconv.Itoa(i+1)+":"), note)
		}
		fmt.Println()
	}

	sort.Strings(arbitrary)
	for _, k := range arbitrary {
		fmt.Printf("%s %s\n", keyColor.Sprintf("%*s", width, k+":"), got.Get(k))
	}

	if update := got.Updated(); !update.IsZero() {
		fmt.Printf("%s %s\n", keyColor.Sprintf("%*s", width, "updated:"), update.Format(time.RFC3339))
	}

	return nil
}

// singleName returns false iff it printed an error message to the user
func (u *uiContext) singleName(search string) (string, bool) {
	names := u.store.Find(search)
	switch len(names) {
	case 0:
		fmt.Printf("no matches for search: %s\n", search)
		return "", false
	case 1:
		return names[0], true
	}

	sort.Strings(names)
	fmt.Printf("multiple matches for search (%q):\n%s\n", search, strings.Join(names, "\n"))

	return "", false
}
