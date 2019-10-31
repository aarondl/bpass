package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/aarondl/bpass/crypt"
	"github.com/aarondl/bpass/osutil"
	"github.com/aarondl/bpass/txblob"
	"github.com/aarondl/bpass/txformat"

	"github.com/aarondl/color"
	"github.com/atotto/clipboard"
	uuidpkg "github.com/gofrs/uuid"
)

var (
	errColor    = color.FgBrightRed
	passColor   = color.FgBrightRed
	infoColor   = color.FgBrightMagenta
	promptColor = color.FgYellow
	keyColor    = color.FgBrightGreen
	hideColor   = color.Mix(color.FgBlue, color.BgBlue)
)

func (u *uiContext) passwd() error {
	initial, err := u.promptPassword(promptColor.Sprint("passphrase: "))
	if err != nil {
		return err
	}

	verify, err := u.promptPassword(promptColor.Sprint("verify passphrase: "))
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

		email, err := u.prompt(promptColor.Sprint("email: "))
		if err != nil {
			return err
		}

		user, err := u.prompt(promptColor.Sprint("user: "))
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
			u.store.Store.Set(uuid, txblob.KeyUser, user)
		}
		if len(email) != 0 {
			u.store.Store.Set(uuid, txblob.KeyEmail, email)
		}
		if len(pass) != 0 {
			u.store.Store.Set(uuid, txblob.KeyPass, pass)
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

	line, err := u.prompt(promptColor.Sprintf("type %q to proceed: ", name))
	if err != nil {
		errColor.Println("Aborted")
		return nil
	}

	if line == name {
		u.store.Delete(uuid)
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

	infoColor.Println("deleted", key, "key")
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
	case txblob.KeyTwoFactor:
		val, err := blob.TwoFactor()
		if err != nil {
			errColor.Println(err)
			return nil
		}

		if len(val) == 0 {
			errColor.Println("totp is not set for", blob.Name())
		}

		if copy {
			copyToClipboard(val)
		} else {
			fmt.Println(val)
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
			fmt.Println(val)
		}
	default:
		entry := txformat.Entry(blob)

		value, ok := entry[key]
		if !ok {
			errColor.Printf("%s.%s is not set", blob.Name(), key)
		}

		if copy {
			copyToClipboard(value)
		} else {
			fmt.Println(value)
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

	if key == txblob.KeyPass && len(value) == 0 {
		value, err = u.getPassword()
		if err != nil {
			return err
		}

		return nil
	} else if len(value) == 0 {
		value, err = u.promptMultiline(promptColor.Sprint("> "))
		if err != nil {
			return err
		}
	}

	switch key {
	case txblob.KeyTwoFactor:
		if err := u.store.SetTwofactor(uuid, value); err != nil {
			errColor.Println(err)
			return nil
		}
	default:
		u.store.Set(uuid, key, value)
	}

	infoColor.Printf("set %s = %s\n", key, value)

	return nil
}

func (u *uiContext) edit(search, key string) error {
	uuid, err := u.findOne(search)
	if err != nil {
		return err
	}
	if len(uuid) == 0 {
		return nil
	}

	blob, err := u.store.Get(uuid)
	if err != nil {
		errColor.Println(err)
		return nil
	}

	// Create UUID filename
	fuuid, err := uuidpkg.NewV4()
	if err != nil {
		return err
	}
	fname := filepath.Join(os.TempDir(), "bp"+fuuid.String()+".txt")

	// Open file, ensure it doesn't exist with locked down user perms
	tmp, err := os.OpenFile(fname, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		errColor.Println("failed to open tmp file to edit value")
		return nil
	}

	// Close and delete the file at the end
	defer func() {
		tmp.Close()
		err = os.Remove(fname)
		if err != nil {
			errColor.Println("failed to remove tmp file:", fname)
		}
	}()

	// Write the old value
	oldValue := blob[key]
	if len(oldValue) != 0 {
		if _, err = io.WriteString(tmp, oldValue); err != nil {
			errColor.Println("failed to write to tmp file")
		}
	}
	maxLen := len(oldValue)

	// At this point, we want to ensure that we wipe the file of any
	// data that was inside it. So we write max(len(oldValue),len(newValue))
	// bytes to the file before deletion.
	defer func() {
		if maxLen == 0 {
			return
		}

		if _, err = tmp.Seek(0, os.SEEK_SET); err != nil {
			errColor.Println("failed to seek in file:", err)
			return
		}

		if _, err = tmp.Write(make([]byte, maxLen)); err != nil {
			errColor.Println("failed to zero the tmp file:", err)
		}
	}()

	if err = tmp.Close(); err != nil {
		errColor.Println("failed to close file:", err)
		return nil
	}

	// Run the editor for the OS and wait until it exits
	editExit := 0
	if err = osutil.RunEditor(fname); err != nil {
		e, ok := err.(*exec.ExitError)
		if !ok {
			return err
		}
		editExit = e.ExitCode()
	}

	tmp, err = os.OpenFile(fname, os.O_RDWR, 0600)
	if err != nil {
		errColor.Println("failed to open tmp file to edit value:", err)
		return nil
	}

	if editExit != 0 {
		errColor.Printf("editor exit non-zero (%d), not saving value\n", editExit)
		return nil
	}

	newValue, err := ioutil.ReadAll(tmp)
	if err != nil {
		errColor.Println("failed to read from tmp file:", err)
		return nil
	}

	if len(newValue) > maxLen {
		maxLen = len(newValue)
	}

	if len(newValue) == 0 {
		infoColor.Println("erasing value")
		u.store.DeleteKey(uuid, key)
	} else {
		infoColor.Printf("set %s\n", key)
		u.store.Set(uuid, key, string(newValue))
	}

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

	labelVal := blob[txblob.KeyLabels]
	var labels []string
	if len(labelVal) != 0 {
		labels = strings.Split(labelVal, ",")
	}

	infoColor.Println("Enter labels, blank line, ctrl-d, or . to stop")
	changed := false
	for {
		line, err := u.prompt(promptColor.Sprint("> "))
		if err == ErrEnd {
			break
		} else if err != nil {
			return err
		}

		if len(line) == 0 || line == "." {
			break
		}

		if !validateLabel(labels, line) {
			continue
		}

		changed = true
		labels = append(labels, line)
	}

	if changed {
		u.store.Set(uuid, txblob.KeyLabels, strings.Join(labels, ","))
		infoColor.Println("Updated labels for", blob.Name())
	}
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

	labelVal := blob[txblob.KeyLabels]
	if len(labelVal) == 0 {
		errColor.Println("Could not find that label")
		return nil
	}

	labels := strings.Split(labelVal, ",")
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

	if err = u.store.RemoveLabel(uuid, index); err != nil {
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
			fmt.Println(promptColor.Sprint("password:"), passColor.Sprint(password))
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
			b, err := u.in.LineHidden(promptColor.Sprint("enter new password: "))
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

	// Figure out the max width of the key names
	width := 8
	keys := blob.Keys()
	for _, k := range keys {
		if len(k) > width {
			width = len(k) + 1 // +1 for : character
		}
	}
	width *= -1
	indent := 2

	// Do these first
	ordering := []string{
		txblob.KeyName,
		txblob.KeyUser,
		txblob.KeyEmail,
		txblob.KeyPass,
		txblob.KeyTwoFactor,
		txblob.KeyLabels,
		txblob.KeyNotes,
	}

	// Delete the ordering ones out of keys
	for _, o := range ordering {
		for i, k := range keys {
			if o == k {
				keys[i] = keys[len(keys)-1]
				keys = keys[:len(keys)-1]
				break
			}
		}
	}
	sort.Strings(keys)
	keys = append(ordering, keys...)

	for _, k := range keys {
		if k == txblob.KeyUpdated {
			// Special case, this one shows up at the end
			continue
		}

		entry := txformat.Entry(blob)
		val, ok := entry[k]
		if !ok {
			continue
		}

		switch k {
		case txblob.KeyPass:
			showHidden(u, txblob.KeyPass, blob.Get(txblob.KeyPass), width, indent)
		case txblob.KeyLabels:
			showKeyValue(u, k, strings.ReplaceAll(val, ",", ", "), width, indent)
		case txblob.KeyTwoFactor:
			t, err := blob.TwoFactor()
			if err != nil {
				fmt.Println("Error retrieving two factor:", err)
			} else if len(t) != 0 {
				showKeyValue(u, txblob.KeyTwoFactor, t, width, indent)
			}
		default:
			if strings.ContainsRune(val, '\n') {
				showMultiline(u, k, val, width, indent)
			} else {
				showKeyValue(u, k, val, width, indent)
			}
		}
	}

	if update, err := blob.Updated(); err != nil {
		return err
	} else if !update.IsZero() {
		showKeyValue(u, "updated", update.Format(time.RFC3339), width, indent)
	}

	if snaps > 0 && snapshot == 0 {
		showKeyValue(u, "snaps", strconv.Itoa(snaps), width, indent)
	}

	return nil
}

func showKeyValue(u *uiContext, key, value string, width, indent int) {
	ind := strings.Repeat(" ", indent)
	fmt.Fprintf(u.out, "%s%s %s\n", ind, keyColor.Sprintf("%*s", width, key+":"), value)
}

func showHidden(u *uiContext, key, value string, width, indent int) {
	ind := strings.Repeat(" ", indent)
	fmt.Fprintf(u.out, "%s%s %s\n", ind, keyColor.Sprintf("%*s", width, key+":"), hideColor.Sprint(value))
}

func showMultiline(u *uiContext, key string, val string, width, indent int) {
	lines := strings.Split(val, "\n")

	lineIndent := indent * 2
	if lineIndent == 0 {
		lineIndent += 2
	}
	ind := strings.Repeat(" ", indent)
	lineInd := strings.Repeat(" ", lineIndent)

	fmt.Fprintf(u.out, "%s%s\n", ind, keyColor.Sprintf("%*s", width, key+":"))
	fmt.Fprintln(u.out, lineInd+strings.TrimSpace(strings.Join(lines, "\n"+lineInd)))
}

func (u *uiContext) openurl(search string) error {
	uuid, err := u.findOne(search)
	if err != nil {
		return nil
	}
	if len(uuid) == 0 {
		return nil
	}

	blob, err := u.store.Get(uuid)
	if err != nil {
		return err
	}

	link := blob.Get(txblob.KeyURL)
	if len(link) == 0 {
		errColor.Printf("url not set on %s\n", blob.Name())
		return nil
	}

	_, err = url.Parse(link)
	if err != nil {
		errColor.Printf("url was not a valid url: %v\n", err)
		return nil
	}

	if err = osutil.OpenURL(link); err != nil {
		errColor.Println("failed to open url:", err)
	}

	return nil
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

func dumpBlob(blob map[string]string, indent int) {
	for k, v := range blob {
		fmt.Printf("%s%s: %#v\n", strings.Repeat(" ", indent), k, v)
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
