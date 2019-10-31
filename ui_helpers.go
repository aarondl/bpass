package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/aarondl/bpass/pinentry"

	"github.com/aarondl/color"
)

func (u *uiContext) promptPassword(prompt string) (string, error) {
	password, err := pinentry.Password(color.Clean(prompt))
	if err == nil {
		return password, nil
	} else if err != pinentry.ErrNotFound {
		return "", err
	}

	return u.in.LineHidden(prompt)
}

func (u *uiContext) prompt(prompt string) (string, error) {
	line, err := u.in.Line(prompt)
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
	str, err = u.prompt(promptColor.Sprint(key + ": "))
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
	str, err = u.prompt(promptColor.Sprint(key + ": "))
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
		promptColor.Printf(" %d) %s\n", i+1, item)
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
	setSetting := func(name string, splits []string, n *int) {
		if len(splits) == 1 {
			if *n >= 0 {
				*n = -1
				fmt.Fprintf(u.out, "%s: off\n", keyColor.Sprint(name))
			} else {
				*n = 0
				fmt.Fprintf(u.out, "%s: on\n", keyColor.Sprint(name))
			}
			return
		}

		i, err := strconv.Atoi(splits[1])
		if err != nil {
			fmt.Println("Not an integer input")
			return
		}
		*n = i
		fmt.Printf("%s: at least %d\n", keyColor.Sprint(name), i)
	}

	length := 32
	upper, lower, number, basic, extra := 0, 0, 0, 0, 0

	help := func() {
		infoColor.Println("Enter a number to adjust length, a letter to toggle/use a feature\nor a letter followed by a number to ensure at least n of that type")
		infoColor.Printf("  length: %-3d [u]pper: %-3s [l]ower: %-3s\n", length, showSetting(upper), showSetting(lower))
		infoColor.Printf("[n]umber: %-3s [b]asic: %-3s [e]xtra: %-3s\n", showSetting(number), showSetting(basic), showSetting(extra))
		infoColor.Println("[y] accept password, [m] manual password entry, [enter] to regen password, [?] help")
		fmt.Println()
	}
	help()

	var err error
	var choice, password string
	for {
		if choice != "?" {
			password, err = genPassword(length, upper, lower, number, basic, extra)
			if err == errPasswordImpossible {
				errColor.Println("Could not generate password with these requirements")
			} else if err != nil {
				return "", err
			}
		}

		if err == nil {
			fmt.Fprintln(u.out, promptColor.Sprint("password:"), passColor.Sprint(password))
		}

		choice, err = u.prompt(promptColor.Sprint("u/l/n/b/e/y/m/enter/?> "))
		if err != nil {
			return "", err
		}

		splits := strings.Fields(choice)

		switch {
		case choice == "":
			// Regen
		case choice == "y":
			return password, nil
		case choice == "m":
			b, err := u.promptPassword(promptColor.Sprint("enter new password: "))
			return string(b), err
		case choice == "?":
			help()
		case splits[0] == "u":
			setSetting("uppercase", splits, &upper)
		case splits[0] == "l":
			setSetting("lowercase", splits, &lower)
		case splits[0] == "n":
			setSetting("numbers", splits, &number)
		case splits[0] == "b":
			setSetting("basic symbols", splits, &basic)
		case splits[0] == "e":
			setSetting("extra symbols", splits, &extra)
		default:
			newLen, err := strconv.Atoi(choice)
			if err != nil {
				fmt.Println("New length was not an integer")
				continue
			}
			fmt.Printf("%s: %d\n", keyColor.Sprint("length"), newLen)
			length = newLen
		}
	}
}
