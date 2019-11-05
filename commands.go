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

	"github.com/aarondl/bpass/blobformat"
	"github.com/aarondl/bpass/crypt"
	"github.com/aarondl/bpass/osutil"
	"github.com/aarondl/bpass/txlogs"

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

func (u *uiContext) passwd(user string) error {
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

	key, salt, err := crypt.DeriveKey(cryptVersion, []byte(initial))
	if err != nil {
		return err
	}

	if len(user) == 0 {
		u.params.Rekey(key, salt)
	} else {
		if err := u.params.RekeyUser(user, key, salt); err == crypt.ErrUnknownUser {
			errColor.Println("unkwon user", user)
			return nil
		} else if err != nil {
			return err
		}
	}

	infoColor.Println("Passphrase updated, bits will be re-encrypted with it on exit")
	return nil
}

func (u *uiContext) adduser(user string) error {
	if !u.params.IsMultiUser() {
		// Error can't occur since there's no other users
		_ = u.params.AddUser(user, u.params.Keys[0], u.params.Salts[0])
		infoColor.Println("converted file into multi-user file")
		infoColor.Printf("re-used your key for user: %s\n", user)
		return nil
	}

	pass, err := u.getPassword()
	if err != nil {
		return err
	}

	key, salt, err := crypt.DeriveKey(cryptVersion, []byte(pass))
	if err != nil {
		return err
	}

	if err := u.params.AddUser(user, key, salt); err != nil {
		errColor.Printf("user %q already exists\n", user)
		return nil
	}

	infoColor.Printf("added user %s: %x\npass: %s\n",
		user,
		u.params.Users[len(u.params.Users)-1],
		pass)

	return nil
}

func (u *uiContext) rmuser(user string) error {
	if err := u.params.RemoveUser(user); err != nil {
		errColor.Println(err)
		return nil
	}

	infoColor.Println("removed user:", user)

	return nil
}

func (u *uiContext) rekey(user string) error {
	key, salt, err := crypt.DeriveKey(cryptVersion, []byte(u.pass))
	if err != nil {
		return err
	}

	u.params.Rekey(key, salt)

	infoColor.Println("Key updated, bits will be re-encrypted with it on exit")
	return nil
}

var rekeyBlurb = `WARNING: This will change ALL user's passwords and print new
ones to the screen. No one will be able to access the file with the old
passwords again after this operation.
`

func (u *uiContext) rekeyAll() error {
	errColor.Println(rekeyBlurb)
	yes, err := u.getYesNo("are you sure you wish to proceed?")
	if err != nil {
		return err
	}

	if !yes {
		return nil
	}

	passwords, err := u.params.RekeyAll(cryptVersion)
	if err != nil {
		return err
	}

	if u.params.IsMultiUser() {
		infoColor.Println("new passwords:")
		for i, user := range u.params.Users {
			infoColor.Printf("  %x %s\n", user, passwords[i])
		}
	} else {
		infoColor.Println("new password:", passwords[0])
	}

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
			if err == blobformat.ErrNameNotUnique {
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
			u.store.DB.Set(uuid, blobformat.KeyUser, user)
		}
		if len(email) != 0 {
			u.store.DB.Set(uuid, blobformat.KeyEmail, email)
		}
		if len(pass) != 0 {
			u.store.DB.Set(uuid, blobformat.KeyPass, pass)
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

	if err := u.store.Rename(oldUUID, dst); err == blobformat.ErrNameNotUnique {
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
		if blobformat.IsKeyNotAllowed(err) {
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
	case blobformat.KeyTwoFactor:
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
	case blobformat.KeyUpdated:
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
		entry := txlogs.Entry(blob)

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

	if key == blobformat.KeyPass && len(value) == 0 {
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
	case blobformat.KeyTwoFactor:
		if err := u.store.SetTwofactor(uuid, value); err != nil {
			errColor.Println(err)
			return nil
		}
	case blobformat.KeyURL:
		uri, err := url.Parse(value)
		if err != nil {
			errColor.Println("not a valid url")
			return nil
		} else if uri.Scheme == "" || uri.Opaque != "" {
			errColor.Println("url must include a scheme like https://")
			return nil
		}

		u.store.Set(uuid, key, value)
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

	labelVal := blob[blobformat.KeyLabels]
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
		u.store.Set(uuid, blobformat.KeyLabels, strings.Join(labels, ","))
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

	labelVal := blob[blobformat.KeyLabels]
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

		blob = blobformat.Blob(entry)
	}

	if len(blob) == 0 {
		infoColor.Println("entry is empty")
		return nil
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
		blobformat.KeyName,
		blobformat.KeyUser,
		blobformat.KeyEmail,
		blobformat.KeyPass,
		blobformat.KeyTwoFactor,
		blobformat.KeyLabels,
		blobformat.KeyNotes,
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
		if k == blobformat.KeyUpdated {
			// Special case, this one shows up at the end
			continue
		}

		entry := txlogs.Entry(blob)
		val, ok := entry[k]
		if !ok {
			continue
		}

		switch k {
		case blobformat.KeyPass:
			showHidden(u, blobformat.KeyPass, blob.Get(blobformat.KeyPass), width, indent)
		case blobformat.KeyLabels:
			showKeyValue(u, k, strings.ReplaceAll(val, ",", ", "), width, indent)
		case blobformat.KeyTwoFactor:
			t, err := blob.TwoFactor()
			if err != nil {
				fmt.Println("Error retrieving two factor:", err)
			} else if len(t) != 0 {
				showKeyValue(u, blobformat.KeyTwoFactor, t, width, indent)
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

	link := blob.Get(blobformat.KeyURL)
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
	b, err := json.MarshalIndent(u.store.DB, "", "  ")
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
