package main

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/aarondl/bpass/blobformat"
	"github.com/gookit/color"
	"github.com/pkg/errors"
)

var (
	errColor         = color.FgLightRed
	infoColor        = color.FgLightCyan
	inputPromptColor = color.FgYellow
)

func (u *uiContext) addNewInterruptible(name string) error {
	err := u.addNew(name)
	switch err {
	case nil:
		return nil
	case io.EOF:
		errColor.Println("Aborted")
		u.readlineResetPrompt()
		return nil
	default:
		return err
	}
}

func (u *uiContext) addNew(name string) error {
	_, exist := u.store[name]
	if exist {
		errColor.Printf("%s already exists\n", name)
		return nil
	}

	user, err := u.prompt(inputPromptColor.Sprint("user: "))
	if err != nil {
		return err
	}

	email, err := u.prompt(inputPromptColor.Sprint("email: "))
	if err != nil {
		return err
	}

	pass, err := u.getPassword()
	if err != nil {
		return err
	}

	timestamp := time.Now().Unix()

	var labels []string
	infoColor.Println("Add labels, enter blank line to stop")
	for {
		label, err := u.prompt(inputPromptColor.Sprint("label: "))
		if err != nil {
			return err
		}

		if len(label) == 0 {
			break
		}

		if !validateLabel(labels, label) {
			errColor.Println("Invalid label")
			continue
		}

		labels = append(labels, label)
	}

	// Here we directly add things as the interface allows so that we can
	// avoid creating useless snapshots as we create the initial blob
	newBlob := make(map[string]interface{})

	if len(user) != 0 {
		newBlob[blobformat.KeyUser] = user
	}
	if len(email) != 0 {
		newBlob[blobformat.KeyEmail] = email
	}
	if len(pass) != 0 {
		newBlob[blobformat.KeyPass] = pass
	}
	if len(labels) != 0 {
		uglyConvert := make([]interface{}, len(labels))
		for i := range labels {
			uglyConvert[i] = labels[i]
		}
		newBlob[blobformat.KeyLabels] = uglyConvert
	}
	newBlob[blobformat.KeyUpdated] = timestamp

	// Save the thing
	u.store[name] = newBlob
	return nil
}

func (u *uiContext) list(search string) error {
	names := u.store.Find(search)
	if len(names) == 0 {
		fmt.Println("No entries found")
		return nil
	}
	sort.Strings(names)
	fmt.Println(strings.Join(names, "\n"))
	return nil
}

func (u *uiContext) listByLabels(wantLabels []string) error {
	names := u.store.Find("")
	if len(names) == 0 {
		errColor.Println("No entries found")
		return nil
	}

	var entries []string

	for _, n := range names {
		b := u.store.MustFind(n)
		haveLabels, err := b.Labels()
		if err != nil {
			errColor.Println("failed to retrieve labels for: %s", n)
		}

		found := 0
		for _, w := range wantLabels {
			for _, h := range haveLabels {
				if h != w {
					continue
				}

				found++
				if found == len(wantLabels) {
					break
				}
			}
		}

		if found == len(wantLabels) {
			entries = append(entries, n)
		}
	}

	if len(entries) == 0 {
		errColor.Println("No entries found")
		return nil
	}

	sort.Strings(entries)
	fmt.Println(strings.Join(entries, "\n"))
	return nil
}

func (u *uiContext) set(search, key, value string) error {
	name, ok := u.singleName(search)
	if !ok {
		return nil
	}

	switch key {
	case "label", blobformat.KeyLabels:
		got := u.store.MustFind(name)
		labels, err := got.Labels()
		if err != nil {
			errColor.Println("failed to retrieve labels:", err)
			return nil
		}

		if !validateLabel(labels, value) {
			return nil
		}
		labels = append(labels, value)
		u.store.SetLabels(name, labels)
	case "note", blobformat.KeyNotes:
		got := u.store.MustFind(name)
		notes, err := got.Notes()
		if err != nil {
			errColor.Println("failed to retrieve notes:", err)
			return nil
		}

		notes = append(notes, value)
		u.store.SetNotes(name, notes)
	case blobformat.KeyTwoFactor:
		if err := u.store.SetTwofactor(name, value); err != nil {
			errColor.Println(err)
			return nil
		}
	case blobformat.KeyUpdated:
		errColor.Printf("%s cannot be set manually\n", blobformat.KeySnapshots)
	case blobformat.KeySnapshots:
		errColor.Printf("%s cannot be set manually\n", blobformat.KeySnapshots)
	default:
		u.store.Set(name, key, value)
	}

	return nil
}

func (u *uiContext) addNote(search string) error {
	name, ok := u.singleName(search)
	if !ok {
		return nil
	}

	return u.addNoteToEntry(name)
}

func (u *uiContext) addNoteToEntry(name string) error {
	entry := u.store.MustFind(name)
	notes, err := entry.Notes()
	if err != nil {
		errColor.Println("failed retrieving notes")
		return nil
	}

	infoColor.Println("Enter note text, two blank lines or ctrl-d to stop")
	var lines []string
	oneBlank := false
	for {
		line, err := u.prompt(">> ")
		if err == io.EOF {
			u.readlineResetPrompt()
			break
		} else if err != nil {
			return err
		}

		if len(line) == 0 {
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

	notes = append(notes, strings.Join(lines, "\n"))
	u.store.SetNotes(name, notes)

	return nil
}

func (u *uiContext) addLabels(search string) error {
	name, ok := u.singleName(search)
	if !ok {
		return nil
	}
	entry := u.store.MustFind(name)
	labels, err := entry.Labels()
	if err != nil {
		errColor.Println("failed retrieving labels")
		return nil
	}

	infoColor.Println("Enter labels, blank line or ctrl-d to stop")
	changed := false
	for {
		line, err := u.prompt(">> ")
		if err == io.EOF {
			u.readlineResetPrompt()
			break
		} else if err != nil {
			return err
		}

		if len(line) == 0 {
			break
		}

		if !validateLabel(labels, line) {
			continue
		}

		changed = true
		labels = append(labels, line)
	}

	if changed {
		u.store.SetLabels(name, labels)
	}

	return nil
}

func (u *uiContext) deleteNote(search string, number int) error {
	name, ok := u.singleName(search)
	if !ok {
		return nil
	}

	entry := u.store.MustFind(name)
	notes, err := entry.Notes()
	if err != nil {
		errColor.Println("failed retrieving notes")
		return nil
	}

	index := number - 1

	if index >= len(notes) {
		errColor.Printf("note number %d does not exist", number)
		return nil
	}

	notes[index], notes[len(notes)-1] = notes[len(notes)-1], notes[index]
	notes = notes[:len(notes)-1]
	u.store.SetNotes(name, notes)

	return nil
}

func (u *uiContext) deleteLabel(search string, label string) error {
	name, ok := u.singleName(search)
	if !ok {
		return nil
	}

	entry := u.store.MustFind(name)
	labels, err := entry.Labels()
	if err != nil {
		errColor.Println("failed retrieving labels")
		return nil
	}

	index := -1
	for i, l := range labels {
		if l == label {
			index = i
			break
		}
	}

	if index < 0 {
		errColor.Println("could not find that label")
		return nil
	}

	labels[index], labels[len(labels)-1] = labels[len(labels)-1], labels[index]
	labels = labels[:len(labels)-1]
	u.store.SetLabels(name, labels)
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
	settingColor := color.FgLightGreen
	setSetting := func(name string, splits []string, n *int) {
		if len(splits) == 1 {
			if *n >= 0 {
				*n = -1
				fmt.Printf("%s: off\n", settingColor.Sprint(name))
			} else {
				*n = 0
				fmt.Printf("%s: on\n", settingColor.Sprint(name))
			}
			return
		}

		i, err := strconv.Atoi(splits[1])
		if err != nil {
			fmt.Println("not an integer input")
			return
		}
		*n = i
		fmt.Printf("%s: at least %d\n", settingColor.Sprint(name), i)
	}

	length := 32
	upper, lower, number, basic, extra := 0, 0, 0, 0, 0

	help := func() {
		infoColor.Println("enter a number to adjust length, a letter to toggle/use a feature\nor a letter followed by a number to ensure at least n of that type")
		infoColor.Printf("  length: %-3d [u]pper: %-3s [l]ower: %-3s\n", length, showSetting(upper), showSetting(lower))
		infoColor.Printf("[n]umber: %-3s [b]asic: %-3s [e]xtra: %-3s\n", showSetting(number), showSetting(basic), showSetting(extra))
		infoColor.Println("[y] accept password, [m] manual password entry, [enter] to regen password, [?] help")
		fmt.Println()
	}

	var err error
	var choice, password string
	passwordColor := color.FgLightRed
	for {
		help()

		if choice != "?" {
			password, err = genPassword(length, upper, lower, number, basic, extra)
			if err == errPasswordImpossible {
				errColor.Println("could not generate password with these requirements")
			} else if err != nil {
				return "", err
			}
		}

		if err == nil {
			fmt.Println(inputPromptColor.Sprint("password:"), passwordColor.Sprint(password))
		}

		choice, err = u.prompt(inputPromptColor.Sprint("u/l/n/b/e/y/m/enter/?> "))
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
			b, err := u.rl.ReadPassword(inputPromptColor.Sprint("enter new password: "))
			return string(b), err
		case choice == "?":
			// Do nothing, and don't regen
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
				fmt.Println("new length was not an integer")
				continue
			}
			fmt.Printf("%s: %d\n", settingColor.Sprint("length"), newLen)
			length = newLen
		}
	}
}

func (u *uiContext) show(search string, snapshot int) error {
	name, ok := u.singleName(search)
	if !ok {
		return nil
	}
	got := u.store.MustFind(name)

	snaps, err := got.NSnapshots()
	if err != nil {
		return errors.Wrap(err, "failed to get snapshot count")
	}
	if snapshot != 0 {
		if snapshot > snaps {
			errColor.Printf("%s only has %d snapshots\n", name, snaps)
			return nil
		}

		got, err = got.Snapshot(snapshot)
		if err != nil {
			errColor.Println(err)
			return nil
		}
	}

	width := 8 // Hardcoded max of the known keys, sad, I know
	arbitrary := got.ArbitraryKeys()
	for _, k := range arbitrary {
		if len(k) > width {
			width = len(k) + 1 // +1 for : character
		}
	}
	width *= -1

	kc := color.FgLightGreen
	passColor := color.New(color.FgBlue, color.BgBlue)
	fmt.Printf("%s %s\n", kc.Sprint("name:"), name)
	fmt.Printf("  %s %s\n", kc.Sprintf("%*s", width, "user:"), got.Get(blobformat.KeyUser))
	fmt.Printf("  %s %s\n", kc.Sprintf("%*s", width, "email:"), got.Get(blobformat.KeyEmail))
	fmt.Printf("  %s %s\n", kc.Sprintf("%*s", width, "pass:"), passColor.Sprint(got.Get(blobformat.KeyPass)))
	t, err := got.TwoFactor()
	if err != nil {
		fmt.Println("error retrieving two factor:", err)
	} else if len(t) != 0 {
		fmt.Printf("  %s %s\n", kc.Sprintf("%*s", width, "totp:"), t)
	}

	labels, err := got.Labels()
	if err != nil {
		fmt.Println("error fetching labels:", err)
	} else if len(labels) > 0 {
		fmt.Printf("  %s %s\n", kc.Sprintf("%*s", width, "labels:"), strings.Join(labels, ", "))
	}

	notes, err := got.Notes()
	if err != nil {
		fmt.Println("error retrieving notes:", err)
	} else if len(notes) > 0 {
		fmt.Printf("  %s\n", kc.Sprintf("%*s", width, "notes:"))
		for i, note := range notes {
			// Format it nicely with newlines and indentation
			note = strings.ReplaceAll(note, "\n", "\n        ")
			fmt.Printf("    %s%s\n", kc.Sprintf("%-4s", strconv.Itoa(i+1)+":"), note)
		}
	}

	sort.Strings(arbitrary)
	for _, k := range arbitrary {
		fmt.Printf("  %s %s\n", kc.Sprintf("%*s", width, k+":"), got.Get(k))
	}

	if update := got.Updated(); !update.IsZero() {
		fmt.Printf("  %s %s\n", kc.Sprintf("%*s", width, "updated:"), update.Format(time.RFC3339))
	}

	if snaps > 0 && snapshot == 0 {
		fmt.Printf("  %s %d\n", kc.Sprintf("%*s", width, "snaps:"), snaps)
	}

	return nil
}

func (u *uiContext) prompt(prompt string) (string, error) {
	u.rl.SetPrompt(prompt)
	line, err := u.rl.Readline()
	if err != nil {
		return "", err
	}
	u.readlineResetPrompt()

	return line, nil
}

// singleName returns false iff it printed an error message to the user
func (u *uiContext) singleName(search string) (string, bool) {
	names := u.store.Find(search)
	switch len(names) {
	case 0:
		errColor.Printf("no matches for search: %s\n", search)
		return "", false
	case 1:
		return names[0], true
	}

	sort.Strings(names)
	errColor.Printf("multiple matches for search (%q):", search)
	fmt.Print("\n  ")
	fmt.Println(strings.Join(names, "  \n"))

	return "", false
}

// validateLabel prints an error and returns false if the label was bad
// either a malformed label or a duplicate
func validateLabel(labels []string, label string) bool {
	for _, c := range label {
		if unicode.IsSpace(c) {
			errColor.Println("labels cannot contain spaces")
			return false
		} else if unicode.IsUpper(c) {
			errColor.Println("labels cannot contain uppercase")
			return false
		}
	}

	for _, l := range labels {
		if l == label {
			errColor.Println("label already applied")
			return false
		}
	}

	return true
}
