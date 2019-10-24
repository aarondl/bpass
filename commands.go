package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/aarondl/bpass/crypt"
	"github.com/aarondl/bpass/txblob"

	"github.com/atotto/clipboard"
	"github.com/gookit/color"
)

var (
	errColor         = color.FgLightRed
	infoColor        = color.FgLightMagenta
	inputPromptColor = color.FgYellow
	keyColor         = color.FgLightGreen
	passColor        = color.New(color.FgBlue, color.BgBlue)
)

func (u *uiContext) passwd() error {
	initial, err := u.term.LineHidden(inputPromptColor.Sprint("passphrase: "))
	if err != nil {
		return err
	}

	verify, err := u.term.LineHidden(inputPromptColor.Sprint("verify passphrase: "))
	if err != nil {
		return err
	}

	if initial != verify {
		errColor.Println("passphrase did not match")
		return nil
	}

	u.key, u.salt, err = crypt.DeriveKey(cryptVersion, []byte(initial))
	if err != nil {
		return err
	}

	infoColor.Println("Passphrase updated, file will be re-encrypted with it on exit")
	return nil
}

func (u *uiContext) addNewInterruptible(name string) error {
	err := u.addNew(name)
	switch err {
	case nil:
		return nil
	case ErrEnd:
		errColor.Println("Aborted")
		return nil
	default:
		return err
	}
}

func (u *uiContext) addNew(name string) error {
	newBlob, err := u.store.New(name)
	if err != nil {
		if err == txblob.ErrNameNotUnique {
			errColor.Printf("%q already exists\n", name)
			return nil
		}
		return err
	}

	email, err := u.prompt(inputPromptColor.Sprint("email: "))
	if err != nil {
		return err
	}

	user, err := u.prompt(inputPromptColor.Sprint("user: "))
	if err != nil {
		return err
	}

	pass, err := u.getPassword()
	if err != nil {
		return err
	}

	timestamp := time.Now().UnixNano()

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

	if len(user) != 0 {
		newBlob[txblob.KeyUser] = user
	}
	if len(email) != 0 {
		newBlob[txblob.KeyEmail] = email
	}
	if len(pass) != 0 {
		newBlob[txblob.KeyPass] = pass
	}
	if len(labels) != 0 {
		uglyConvert := make([]interface{}, len(labels))
		for i := range labels {
			uglyConvert[i] = labels[i]
		}
		newBlob[txblob.KeyLabels] = uglyConvert
	}
	newBlob[txblob.KeyUpdated] = timestamp

	// Save the thing
	return u.store.Add(newBlob)
}

func (u *uiContext) rename(src, dst string) error {
	oldUUID, _ := u.store.Find(src)
	if len(oldUUID) == 0 {
		errColor.Println(src, "does not exist")
		return nil
	}

	if err := u.store.Rename(oldUUID, dst); err == txblob.ErrNameNotUnique {
		errColor.Println(dst, "already exists")
		return nil
	} else if err != nil {
		return err
	}

	infoColor.Printf("moved %q => %q\n", src, dst)
	return nil
}

func (u *uiContext) remove(name string) error {
	uuid, _ := u.store.Find(name)
	if len(uuid) == 0 {
		errColor.Printf("%q not found\n", name)
		return nil
	}

	errColor.Printf("WARNING: This will delete all data associated with %q\n", name)
	errColor.Println("Including ALL history irrecoverably, are you sure you wish to proceed?")
	fmt.Println()

	line, err := u.prompt(inputPromptColor.Sprintf("type %q to proceed: ", name))
	if err != nil {
		errColor.Println("Aborted")
		return nil
	}

	if line == name {
		delete(u.store, name)
		errColor.Println("DELETED", name)
	} else {
		errColor.Println("Aborted")
	}

	return nil
}

func (u *uiContext) list(search string) error {
	entries := u.store.Search(search)
	if len(entries) == 0 {
		fmt.Println("No entries found")
		return nil
	}
	names := entries.Names()
	sort.Strings(names)
	fmt.Println(strings.Join(names, "\n"))
	return nil
}

func (u *uiContext) listByLabels(wantLabels []string) error {
	results := u.store.SearchLabels(wantLabels...)
	if len(results) == 0 {
		errColor.Println("No entries found")
		return nil
	}

	names := results.Names()
	sort.Strings(names)
	fmt.Println(strings.Join(names, "\n"))
	return nil
}

func (u *uiContext) get(search, key string, index int, copy bool) error {
	uuid, ok := u.singleName(search)
	if !ok {
		return nil
	}

	entry := u.store.Get(uuid)

	switch key {
	case "label", txblob.KeyLabels:
		labels, err := entry.Labels()
		if err != nil {
			errColor.Println("failed to retrieve labels:", err)
			return nil
		}

		// Single label
		if index > 0 {
			index--
			if index >= len(labels) {
				errColor.Printf("There is only %d labels\n", len(labels))
				return nil
			}

			if copy {
				copyToClipboard(labels[index])
			} else {
				showKeyValue(fmt.Sprintf("label[%d]", index+1), labels[index], 0, 0)
			}
			return nil
		}

		if copy {
			copyToClipboard(strings.Join(labels, ","))
		} else {
			showJoinedSlice("labels", labels, 0, 0)
		}

	case "note", txblob.KeyNotes:
		notes, err := entry.Notes()
		if err != nil {
			errColor.Println("Failed to retrieve notes:", err)
			return nil
		}

		// Single note
		if index > 0 {
			index--
			if index >= len(notes) {
				errColor.Printf("There are only %d notes\n", len(notes))
				return nil
			}

			if copy {
				copyToClipboard(notes[index])
			} else {
				showKeyValue(fmt.Sprintf("note[%d]", index+1), "", 0, 0)
				fmt.Println(notes[index])
			}
			return nil
		}

		if copy {
			copyToClipboard(strings.Join(notes, "\n"))
		} else {
			showNotes(notes, 0, 0)
		}

	case "totp", txblob.KeyTwoFactor:
		val, err := entry.TwoFactor()
		if err != nil {
			errColor.Println(err)
			return nil
		}

		if len(val) == 0 {
			errColor.Println("twofactor is not set for", entry.Name())
		}

		if copy {
			copyToClipboard(val)
		} else {
			showKeyValue("totp", val, 0, 0)
		}
	case txblob.KeyUpdated:
		value := entry.Updated().Format(time.RFC3339)
		if copy {
			copyToClipboard(value)
		} else {
			showKeyValue("updated", value, 0, 0)
		}
	case txblob.KeySnapshots:
		n, err := entry.NSnapshots()
		if err != nil {
			errColor.Println(err)
			return nil
		}
		if copy {
			copyToClipboard(strconv.Itoa(n))
		} else {
			showKeyValue("snaps", strconv.Itoa(n), 0, 0)
		}
	default:
		value := entry.Get(key)
		if len(value) == 0 {
			errColor.Printf("Key %s is not set\n", key)
			return nil
		}

		if copy {
			copyToClipboard(value)
		} else if key == txblob.KeyPass {
			showHidden(key, value, 0, 0)
		} else {
			showKeyValue(key, value, 0, 0)
		}
	}

	return nil
}

func (u *uiContext) set(search, key, value string) error {
	uuid, ok := u.singleName(search)
	if !ok {
		return nil
	}

	entry := u.store.Get(uuid)

	if key == txblob.KeyPass {
		if len(value) == 0 {
			var err error
			value, err = u.getPassword()
			if err != nil {
				return err
			}
		}

		if len(value) != 0 {
			infoColor.Println("Updated password for", entry.Name())
			u.store.Set(uuid, key, value)
		}

		return nil
	}

	switch key {
	case "label", txblob.KeyLabels:
		labels, err := entry.Labels()
		if err != nil {
			errColor.Println("Failed to retrieve labels:", err)
			return nil
		}

		if !validateLabel(labels, value) {
			return nil
		}
		labels = append(labels, value)
		u.store.SetLabels(uuid, labels)
	case "note", txblob.KeyNotes:
		notes, err := entry.Notes()
		if err != nil {
			errColor.Println("Failed to retrieve notes:", err)
			return nil
		}

		notes = append(notes, value)
		u.store.SetNotes(uuid, notes)
	case "totp", txblob.KeyTwoFactor:
		if err := u.store.SetTwofactor(uuid, value); err != nil {
			errColor.Println(err)
			return nil
		}
	case txblob.KeyUpdated, txblob.KeySnapshots, txblob.KeySync,
		txblob.KeyLastSync, txblob.KeyPub, txblob.KeySecret:

		errColor.Printf("%s cannot be set manually\n", key)
	default:
		u.store.Set(uuid, key, value)
	}

	infoColor.Printf("set %s = %s\n", key, value)

	return nil
}

func (u *uiContext) addNote(search string) error {
	uuid, ok := u.singleName(search)
	if !ok {
		return nil
	}

	return u.addNoteToEntry(uuid)
}

func (u *uiContext) addNoteToEntry(uuid string) error {
	entry := u.store.Get(uuid)

	notes, err := entry.Notes()
	if err != nil {
		errColor.Println("Failed retrieving notes")
		return nil
	}

	infoColor.Println("Enter note text, two blank lines or ctrl-d to stop")
	var lines []string
	oneBlank := false
	for {
		line, err := u.prompt(">> ")
		if err == ErrEnd {
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
	u.store.SetNotes(uuid, notes)
	infoColor.Println("Updated notes for", entry.Name())

	return nil
}

func (u *uiContext) addLabels(search string) error {
	uuid, ok := u.singleName(search)
	if !ok {
		return nil
	}
	entry := u.store.Get(uuid)
	labels, err := entry.Labels()
	if err != nil {
		errColor.Println("Failed retrieving labels")
		return nil
	}

	infoColor.Println("Enter labels, blank line or ctrl-d to stop")
	changed := false
	for {
		line, err := u.prompt(">> ")
		if err == ErrEnd {
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
		infoColor.Println("Updated labels for", entry.Name())
		u.store.SetLabels(uuid, labels)
	}
	return nil
}

func (u *uiContext) deleteNote(search string, number int) error {
	uuid, ok := u.singleName(search)
	if !ok {
		return nil
	}

	entry := u.store.Get(uuid)
	notes, err := entry.Notes()
	if err != nil {
		errColor.Println("Failed retrieving notes")
		return nil
	}

	index := number - 1

	if index >= len(notes) {
		errColor.Printf("Note number %d does not exist\n", number)
		return nil
	}

	notes[index], notes[len(notes)-1] = notes[len(notes)-1], notes[index]
	notes = notes[:len(notes)-1]
	u.store.SetNotes(uuid, notes)
	infoColor.Println("Updated notes for", entry.Name())

	return nil
}

func (u *uiContext) deleteLabel(search string, label string) error {
	uuid, ok := u.singleName(search)
	if !ok {
		return nil
	}

	entry := u.store.Get(uuid)
	labels, err := entry.Labels()
	if err != nil {
		errColor.Println("Failed retrieving labels")
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
		errColor.Println("Could not find that label")
		return nil
	}

	labels[index], labels[len(labels)-1] = labels[len(labels)-1], labels[index]
	labels = labels[:len(labels)-1]
	u.store.SetLabels(uuid, labels)
	infoColor.Println("Updated labels for", entry.Name())
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
	setSetting := func(name string, splits []string, n *int) {
		if len(splits) == 1 {
			if *n >= 0 {
				*n = -1
				fmt.Printf("%s: off\n", keyColor.Sprint(name))
			} else {
				*n = 0
				fmt.Printf("%s: on\n", keyColor.Sprint(name))
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
	passwordColor := color.FgLightRed
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
			b, err := u.term.LineHidden(inputPromptColor.Sprint("enter new password: "))
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

func (u *uiContext) show(search string, snapshot int) error {
	uuid, ok := u.singleName(search)
	if !ok {
		return nil
	}
	entry := u.store.Get(uuid)

	snaps, err := entry.NSnapshots()
	if err != nil {
		return fmt.Errorf("failed to get snapshot count: %w", err)
	}
	if snapshot != 0 {
		if snapshot > snaps {
			errColor.Printf("%s only has %d snapshots\n", entry.Name(), snaps)
			return nil
		}

		entry, err = entry.Snapshot(snapshot)
		if err != nil {
			errColor.Println(err)
			return nil
		}
	}

	width := 8 // Hardcoded max of the known keys, sad, I know
	arbitrary := entry.ArbitraryKeys()
	// Add back some known keys because we don't give a crap when they're
	// displayed
	arbitrary = append(arbitrary,
		txblob.KeyPub,
		txblob.KeyPath,
		txblob.KeyHost,
		txblob.KeyPort)
	for _, k := range arbitrary {
		if len(k) > width {
			width = len(k) + 1 // +1 for : character
		}
	}
	width *= -1
	indent := 2

	if snapshot != 0 {
		showKeyValue(txblob.KeyName, entry.Name(), width, indent)
	}
	showKeyValue(txblob.KeyUser, entry.Get(txblob.KeyUser), width, indent)
	showKeyValue(txblob.KeyEmail, entry.Get(txblob.KeyEmail), width, indent)
	showHidden(txblob.KeyPass, entry.Get(txblob.KeyPass), width, indent)
	t, err := entry.TwoFactor()
	if err != nil {
		fmt.Println("Error retrieving two factor:", err)
	} else if len(t) != 0 {
		showKeyValue("totp", t, width, indent)
	}

	labels, err := entry.Labels()
	if err != nil {
		fmt.Println("Error fetching labels:", err)
	} else if len(labels) > 0 {
		showJoinedSlice("labels", labels, width, indent)
	}

	notes, err := entry.Notes()
	if err != nil {
		fmt.Println("Error retrieving notes:", err)
	} else if len(notes) > 0 {
		showNotes(notes, width, indent)
	}

	syncs, err := entry.Sync()
	if err != nil {
		fmt.Println("Error retrieving syncs:", err)
	} else if len(syncs) > 0 {
		showJoinedSlice("sync", syncs, width, indent)
	}

	sort.Strings(arbitrary)
	for _, k := range arbitrary {
		val := entry.Get(k)
		if len(val) == 0 {
			continue
		}
		showKeyValue(k, val, width, indent)
	}

	if update := entry.Updated(); !update.IsZero() {
		showKeyValue("updated", update.Format(time.RFC3339), width, indent)
	}

	if snaps > 0 && snapshot == 0 {
		showKeyValue("snaps", strconv.Itoa(snaps), width, indent)
	}

	return nil
}

func showKeyValue(key, value string, width, indent int) {
	ind := strings.Repeat(" ", indent)
	fmt.Printf("%s%s %s\n", ind, keyColor.Sprintf("%*s", width, key+":"), value)
}

func showHidden(key, value string, width, indent int) {
	ind := strings.Repeat(" ", indent)
	fmt.Printf("%s%s %s\n", ind, keyColor.Sprintf("%*s", width, key+":"), passColor.Sprint(value))
}

func showJoinedSlice(label string, slice []string, width, indent int) {
	ind := strings.Repeat(" ", indent)
	fmt.Printf("%s%s %s\n", ind, keyColor.Sprintf("%*s", width, label+":"), strings.Join(slice, ", "))
}

func showNotes(notes []string, width, indent int) {
	noteIndent := indent * 2
	if noteIndent == 0 {
		noteIndent += 2
	}
	ind := strings.Repeat(" ", indent)

	fmt.Printf("%s%s\n", ind, keyColor.Sprintf("%*s", width, "notes:"))
	for i, note := range notes {
		showNote(i, note, noteIndent)
	}
}

func showNote(number int, note string, indent int) {
	firstInd := strings.Repeat(" ", indent)
	otherInd := strings.Repeat(" ", indent+4)
	for i, line := range strings.Split(note, "\n") {
		if i == 0 {
			fmt.Printf("%s%s%s\n", firstInd, keyColor.Sprintf("%-4s", strconv.Itoa(number+1)+":"), line)
			continue
		}
		fmt.Printf("%s%s\n", otherInd, line)
	}
}

func (u *uiContext) dump(search string) error {
	uuid, ok := u.singleName(search)
	if !ok {
		return nil
	}

	blob := u.store[uuid]
	dumpBlob(blob, 0)

	return nil
}

func dumpBlob(blob map[string]interface{}, indent int) {
	for k, v := range blob {
		switch k {
		case txblob.KeySnapshots:
			slice, ok := v.([]interface{})
			if !ok {
				fmt.Printf("snapshots are the wrong type: %T\n", v)
				break
			}

			for i, snap := range slice {
				snapshot, ok := snap.(map[string]interface{})
				if !ok {
					fmt.Printf("snapshot %d is the wrong type: %T\n", i, snap)
					continue
				}

				fmt.Printf("snapshot[%d]:\n", i)
				dumpBlob(snapshot, indent+2)
			}
		case txblob.KeyNotes, txblob.KeyLabels, txblob.KeySync:
			slice, ok := v.([]interface{})
			if !ok {
				fmt.Printf("%s are the wrong type: %T\n", k, v)
				break
			}
			for i, s := range slice {
				str, ok := s.(string)
				if !ok {
					fmt.Printf("%s %d is the wrong type: %T\n", k, i, s)
				}
				ind := strings.Repeat(" ", indent)
				fmt.Printf("%s%s[%d]:\n%s%s\n", ind, k, i, ind, str)
			}
		default:
			fmt.Printf("%s%s: %#v\n", strings.Repeat(" ", indent), k, v)
		}
	}
}

// validateLabel prints an error and returns false if the label was bad
// either a malformed label or a duplicate
func validateLabel(labels []string, label string) bool {
	for _, c := range label {
		if unicode.IsSpace(c) {
			errColor.Println("Labels cannot contain spaces")
			return false
		} else if unicode.IsUpper(c) {
			errColor.Println("Labels cannot contain uppercase")
			return false
		}
	}

	for _, l := range labels {
		if l == label {
			errColor.Println("Label already applied")
			return false
		}
	}

	return true
}

func copyToClipboard(txt string) {
	err := clipboard.WriteAll(txt)
	if err != nil {
		errColor.Println("Failed to copy text to clipboard")
		return
	}

	infoColor.Println("Copied value to clipboard")
}
