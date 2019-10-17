package main

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/gookit/color"

	"github.com/aarondl/bpass/blobformat"
	"github.com/chzyer/readline"
	"github.com/davecgh/go-spew/spew"
)

func (u *uiContext) repl() error {
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

		switch splits[0] {
		case "new":
			if len(splits) < 2 {
				fmt.Println("syntax: new <name>")
				continue
			}
			err = u.addNew(splits[1])
		case "ls":
			search := ""
			if len(splits) >= 2 {
				search = splits[1]
			}
			err = u.list(search)
		case "show":
			if len(splits) < 2 {
				fmt.Println("syntax: show <name>")
				continue
			}
			err = u.show(splits[1])
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

	spew.Dump(u.store)

	return nil
}

func (u *uiContext) getPassword() (string, error) {
	showSetting := func(n int) string {
		if n < 0 {
			return "off"
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

func (u *uiContext) show(search string) error {
	name, ok := u.singleName(search)
	if !ok {
		return nil
	}

	spew.Dump(u.store.MustFind(name))
	return nil
}

// singleName returns false iff it printed an error message to the user
func (u *uiContext) singleName(search string) (string, bool) {
	names := u.store.Find(search)
	if len(names) == 1 {
		return names[0], true
	}

	sort.Strings(names)
	fmt.Printf("Multiple matches:\n%s\n", strings.Join(names, "\n"))

	return "", false
}
