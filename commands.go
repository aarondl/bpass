package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/aarondl/bpass/crypt"
	"github.com/aarondl/bpass/txblob"
	"github.com/aarondl/bpass/txformat"

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

func (u *uiContext) addNew(name string) (err error) {
	return u.store.Do(func() error {
		uuid, err := u.store.New(name)
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

		// Use raw sets here to avoid creating history spam based on timestamp
		// additions
		if len(user) != 0 {
			if err = u.store.Store.Set(uuid, txblob.KeyUser, user); err != nil {
				return err
			}
		}
		if len(email) != 0 {
			if err = u.store.Store.Set(uuid, txblob.KeyEmail, email); err != nil {
				return err
			}
		}
		if len(pass) != 0 {
			if err = u.store.Store.Set(uuid, txblob.KeyPass, pass); err != nil {
				return err
			}
		}

		return nil
	})
}

func (u *uiContext) rename(src, dst string) error {
	oldUUID, _, err := u.store.Find(src)
	if err != nil {
		return err
	}
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

func (u *uiContext) deleteEntry(name string) error {
	uuid, _, err := u.store.Find(name)
	if err != nil {
		return err
	}
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
		if err = u.store.Delete(uuid); err != nil {
			return err
		}
		errColor.Println("DELETED", name)
	} else {
		errColor.Println("Aborted")
	}

	return nil
}

func (u *uiContext) deleteKey(search, key string) error {
	uuid, err := u.findOne(search)
	if err != nil {
		return err
	}
	if len(uuid) == 0 {
		return nil
	}

	blob, err := u.store.Get(uuid)
	if err != nil {
		return err
	}

	_, ok := blob[key]
	if ok {
		err := u.store.DeleteKey(uuid, key)
		if txblob.IsKeyNotAllowed(err) {
			errColor.Println(key, "may not be deleted")
			return nil
		}
	}

	infoColor.Println("deleted", key)
	return nil
}

func (u *uiContext) list(search string) error {
	entries, err := u.store.Search(search)
	if err != nil {
		return err
	}
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
	results, err := u.store.SearchLabels(wantLabels...)
	if err != nil {
		return err
	}
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
	uuid, err := u.findOne(search)
	if err != nil {
		return err
	}
	if len(uuid) == 0 {
		return nil
	}

	blob, err := u.store.Get(uuid)
	if err != nil {
		return err
	}

	switch key {
	case "totp", txblob.KeyTwoFactor:
		val, err := blob.TwoFactor()
		if err != nil {
			errColor.Println(err)
			return nil
		}

		if len(val) == 0 {
			errColor.Println("twofactor is not set for", blob.Name())
		}

		if copy {
			copyToClipboard(val)
		} else {
			showKeyValue("totp", val, 0, 0)
		}
	case txblob.KeyUpdated:
		value, err := blob.Updated()
		if err != nil {
			return err
		}
		val := value.Format(time.RFC3339)
		if copy {
			copyToClipboard(val)
		} else {
			showKeyValue("updated", val, 0, 0)
		}
	case txblob.KeySnapshots:
		n := u.store.NVersions(uuid)
		if copy {
			copyToClipboard(strconv.Itoa(n))
		} else {
			showKeyValue("snaps", strconv.Itoa(n), 0, 0)
		}
	default:
		entry := txformat.Entry(blob)
		kind, ok := entry.Kind(key)
		if !ok {
			errColor.Printf("Key %s is not set\n", key)
			return nil
		}

		switch kind {
		case txformat.EntryKindString:
			value, err := entry.String(key)
			if err != nil {
				return err
			}

			if copy {
				copyToClipboard(value)
			} else if key == txblob.KeyPass {
				showHidden(key, value, 0, 0)
			} else {
				showKeyValue(key, value, 0, 0)
			}

		case txformat.EntryKindList:
			list, err := entry.List(key)
			if err != nil {
				return err
			}

			// Single item
			if index > 0 {
				index--
				if index >= len(list) {
					errColor.Printf("There are only %d items\n", len(list))
					return nil
				}

				if copy {
					copyToClipboard(list[index].Value)
				} else if key == txblob.KeyLabels {
					showKeyValue(fmt.Sprintf("%s[%d]", key, index+1), list[index].Value, 0, 0)
				} else {
					showKeyValue(fmt.Sprintf("%s[%d]", key, index+1), "", 0, 0)
					fmt.Println(list[index].Value)
				}
				return nil
			}

			strs := txformat.ListEntryValues(list)

			if copy && key == txblob.KeyLabels {
				copyToClipboard(strings.Join(strs, ", "))
			} else if copy {
				copyToClipboard(strings.Join(strs, "\n"))
			} else if key == txblob.KeyLabels {
				showJoinedSlice(key, strs, 0, 0)
			} else {
				showLinedSlice(key, strs, 0, 0)
			}
		}
	}

	return nil
}

func (u *uiContext) set(search, key, value string) error {
	uuid, err := u.findOne(search)
	if err != nil {
		return err
	}
	if len(uuid) == 0 {
		return nil
	}

	blob, err := u.store.Get(uuid)
	if err != nil {
		return err
	}

	if key == txblob.KeyPass {
		if len(value) == 0 {
			var err error
			value, err = u.getPassword()
			if err != nil {
				return err
			}
		}

		if len(value) != 0 {
			if err = u.store.Set(uuid, key, value); err != nil {
				return err
			}
			infoColor.Println("Updated password for", blob.Name())
		}

		return nil
	}

	switch key {
	case "label", txblob.KeyLabels:
		labels, err := blob.Labels()
		if err != nil {
			errColor.Println("Failed to retrieve labels:", err)
			return nil
		}

		labelStrs := txformat.ListEntryValues(labels)

		if !validateLabel(labelStrs, value) {
			return nil
		}
		if _, err = u.store.AddLabel(uuid, value); err != nil {
			return err
		}
	case "note", txblob.KeyNotes:
		if _, err = u.store.AddNote(uuid, value); err != nil {
			return err
		}
	case "totp", txblob.KeyTwoFactor:
		if err := u.store.SetTwofactor(uuid, value); err != nil {
			errColor.Println(err)
			return nil
		}
	case txblob.KeyUpdated, txblob.KeySnapshots, txblob.KeySync,
		txblob.KeyLastSync, txblob.KeyPub, txblob.KeySecret:

		errColor.Printf("%s cannot be set manually\n", key)
	default:
		if err = u.store.Set(uuid, key, value); err != nil {
			return err
		}
	}

	infoColor.Printf("set %s = %s\n", key, value)

	return nil
}

func (u *uiContext) addNote(search string) error {
	uuid, err := u.findOne(search)
	if err != nil {
		return err
	}
	if len(uuid) == 0 {
		return nil
	}

	return u.addNoteToEntry(uuid)
}

func (u *uiContext) addNoteToEntry(uuid string) error {
	blob, err := u.store.Get(uuid)
	if err != nil {
		return err
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

	if _, err := u.store.AddNote(uuid, strings.Join(lines, "\n")); err != nil {
		return err
	}
	infoColor.Println("Updated notes for", blob.Name())

	return nil
}

func (u *uiContext) addLabels(search string) error {
	uuid, err := u.findOne(search)
	if err != nil {
		return err
	}
	if len(uuid) == 0 {
		return nil
	}

	blob, err := u.store.Get(uuid)
	if err != nil {
		return err
	}

	labels, err := blob.Labels()
	if err != nil {
		errColor.Println("Failed retrieving labels")
		return nil
	}
	labelStrs := txformat.ListEntryValues(labels)

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

		if !validateLabel(labelStrs, line) {
			continue
		}

		changed = true
		if _, err := u.store.AddLabel(uuid, line); err != nil {
			return err
		}
	}

	if changed {
		infoColor.Println("Updated labels for", blob.Name())
	}
	return nil
}

func (u *uiContext) deleteList(search, key string, number int) error {
	uuid, err := u.findOne(search)
	if err != nil {
		return err
	}
	if len(uuid) == 0 {
		return nil
	}

	blob, err := u.store.Get(uuid)
	if err != nil {
		return err
	}

	list, err := txformat.Entry(blob).List(key)
	if err != nil {
		errColor.Println("Failed retrieving list")
		return nil
	}

	index := number - 1
	if index >= len(list) {
		errColor.Printf("Number %d does not exist (only %d items)\n", number, len(list))
		return nil
	}

	if err = u.store.RemoveList(uuid, key, list[index].UUID); err != nil {
		return err
	}

	infoColor.Printf("Updated %s for %s\n", key, blob.Name())

	return nil
}

func (u *uiContext) deleteLabel(search string, label string) error {
	uuid, err := u.findOne(search)
	if err != nil {
		return err
	}
	if len(uuid) == 0 {
		return nil
	}

	blob, err := u.store.Get(uuid)
	if err != nil {
		return err
	}

	labels, err := blob.Labels()
	if err != nil {
		errColor.Println("Failed retrieving labels")
		return nil
	}

	index := -1
	for i, l := range labels {
		if l.Value == label {
			index = i
			break
		}
	}

	if index < 0 {
		errColor.Println("Could not find that label")
		return nil
	}

	if err = u.store.RemoveLabel(uuid, labels[index].UUID); err != nil {
		return err
	}
	infoColor.Println("Updated labels for", blob.Name())
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
	uuid, err := u.findOne(search)
	if err != nil {
		return err
	}
	if len(uuid) == 0 {
		return nil
	}

	blob, err := u.store.Get(uuid)
	if err != nil {
		return err
	}

	snaps := u.store.NVersions(uuid)
	if snapshot != 0 {
		if snapshot > snaps {
			errColor.Printf("%s only has %d snapshots\n", blob.Name(), snaps)
			return nil
		}

		entry, err := u.store.EntrySnapshotAt(uuid, snapshot)
		if err != nil {
			errColor.Println(err)
			return nil
		}

		blob = txblob.Blob(entry)
	}

	width := 8 // Hardcoded max of the known keys, sad, I know
	arbitrary := blob.ArbitraryKeys()
	// Add back some known keys because we don't give a crap when they're
	// displayed
	arbitrary = append(arbitrary,
		txblob.KeySync,
		txblob.KeySyncKind,
		txblob.KeyKnownHosts,
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
		// We don't use .Name() helper because when digging into history
		// it can end up being nil. But we also don't use Get() here because
		// it's a protected key and can't be reached with that!
		entry := txformat.Entry(blob)
		name, _ := entry.String(txblob.KeyName)
		showKeyValue(txblob.KeyName, name, width, indent)
	}
	showKeyValue(txblob.KeyUser, blob.Get(txblob.KeyUser), width, indent)
	showKeyValue(txblob.KeyEmail, blob.Get(txblob.KeyEmail), width, indent)
	showHidden(txblob.KeyPass, blob.Get(txblob.KeyPass), width, indent)
	t, err := blob.TwoFactor()
	if err != nil {
		fmt.Println("Error retrieving two factor:", err)
	} else if len(t) != 0 {
		showKeyValue("totp", t, width, indent)
	}

	labels, err := blob.Labels()
	if err != nil {
		fmt.Println("Error fetching labels:", err)
	} else if len(labels) > 0 {
		labelStrs := txformat.ListEntryValues(labels)
		showJoinedSlice(txblob.KeyLabels, labelStrs, width, indent)
	}

	notes, err := blob.Notes()
	if err != nil {
		fmt.Println("Error retrieving notes:", err)
	} else if len(notes) > 0 {
		noteStrs := txformat.ListEntryValues(notes)
		showLinedSlice(txblob.KeyNotes, noteStrs, width, indent)
	}

	sort.Strings(arbitrary)
	for _, k := range arbitrary {
		entry := txformat.Entry(blob)

		kind, ok := entry.Kind(k)
		if !ok {
			continue
		}

		switch kind {
		case txformat.EntryKindList:
			val, err := entry.List(k)
			if err != nil {
				return err
			}
			valStrs := txformat.ListEntryValues(val)
			showLinedSlice(k, valStrs, width, indent)
		case txformat.EntryKindString:
			val, err := entry.String(k)
			if err != nil {
				return err
			}
			showKeyValue(k, val, width, indent)
		}

	}

	if update, err := blob.Updated(); err != nil {
		return err
	} else if !update.IsZero() {
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

func showLinedSlice(key string, items []string, width, indent int) {
	lineIndent := indent * 2
	if lineIndent == 0 {
		lineIndent += 2
	}
	ind := strings.Repeat(" ", indent)

	fmt.Printf("%s%s\n", ind, keyColor.Sprintf("%*s", width, key+":"))
	for i, item := range items {
		showLine(i, item, lineIndent)
	}
}

func showLine(number int, item string, indent int) {
	firstInd := strings.Repeat(" ", indent)
	otherInd := strings.Repeat(" ", indent+4)
	for i, line := range strings.Split(item, "\n") {
		if i == 0 {
			fmt.Printf("%s%s%s\n", firstInd, keyColor.Sprintf("%-4s", strconv.Itoa(number+1)+":"), line)
			continue
		}
		fmt.Printf("%s%s\n", otherInd, line)
	}
}

func (u *uiContext) dump(search string) error {
	uuid, err := u.findOne(search)
	if err != nil {
		return err
	}
	if len(uuid) == 0 {
		return nil
	}

	blob, err := u.store.Get(uuid)
	if err != nil {
		return err
	}
	dumpBlob(blob, 0)

	return nil
}

func (u *uiContext) dumpall() error {
	b, err := json.MarshalIndent(u.store.Store, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", b)
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
