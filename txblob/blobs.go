package txblob

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aarondl/bpass/txformat"

	"github.com/lithammer/fuzzysearch/fuzzy"
	"github.com/pquerna/otp"
)

// Sentinel errors
var (
	ErrNameNotUnique = errors.New("name is not unique")
)

// Blobs exposes operations on special keys in the blob file structure
// All manipulation should be done via this interface or special keys like
// updated and snapshots will probably be mishandled.
type Blobs struct {
	*txformat.Store
}

// SearchResults have helpers to get uuids/names easily
type SearchResults map[string]string

// RenameDuplicates renames names (KeyName) that collide.
// Creates snapshots as it does so. Returns a list of renames that it did.
func (b Blobs) RenameDuplicates() (map[string]string, error) {
	if err := b.UpdateSnapshot(); err != nil {
		return nil, err
	}

	names := make(map[string]struct{})
	renames := make(map[string]string)

	for uuid, entry := range b.Snapshot {
		blob := Blob(entry)
		name := blob.Name()

		_, ok := names[name]
		if !ok {
			names[name] = struct{}{}
			continue
		}

		oldName := name
		for ok {
			name = name + "1"
			_, ok = names[name]
		}

		renames[oldName] = name

		if err := b.touchUpdated(uuid); err != nil {
			return nil, err
		}
		if err := b.Set(uuid, KeyName, name); err != nil {
			return nil, err
		}
	}

	return renames, nil
}

// Search names of entries using fuzzy search and breaks on /
// to help organization. The returned list of names is not sorted.
//
// If search is empty, all results names returned.
//
// Most other commands will require a fully qualified name of an entry to
// manipulate.
func (b Blobs) Search(search string) (entries SearchResults, err error) {
	if err := b.UpdateSnapshot(); err != nil {
		return nil, err
	}

	if len(b.Store.Snapshot) == 0 {
		return nil, nil
	}
	if len(search) == 0 {
		return b.allEntries(), nil
	}

	entries = make(map[string]string)
	fragments := strings.Split(search, "/")
	nFrags := len(fragments)

AllKeys:
	for uuid, entry := range b.Store.Snapshot {
		blob := Blob(entry)

		name := blob.Name()

		if len(fragments) == 1 {
			if !fuzzy.MatchFold(fragments[0], name) {
				continue AllKeys
			}
		} else {
			keyFrags := strings.Split(name, "/")
			if len(keyFrags) < nFrags {
				continue
			}

			for i, f := range fragments {
				if !fuzzy.MatchFold(f, keyFrags[i]) {
					continue AllKeys
				}
			}
		}

		entries[uuid] = blob.Name()
	}

	return entries, nil
}

// SearchLabels searches by finding all entries with all the labels given.
func (b Blobs) SearchLabels(labels ...string) (entries SearchResults, err error) {
	if err := b.UpdateSnapshot(); err != nil {
		return nil, err
	}

	if len(b.Store.Snapshot) == 0 {
		return nil, nil
	}
	if len(labels) == 0 {
		return b.allEntries(), nil
	}

	entries = make(map[string]string)
	for uuid, entry := range b.Store.Snapshot {
		blob := Blob(entry)

		found := 0
		for _, w := range labels {
			haveLabels, err := blob.Labels()
			if err != nil {
				return nil, err
			}

			for _, h := range haveLabels {
				if h.Value != w {
					continue
				}

				found++
				if found == len(labels) {
					break
				}
			}
		}

		if found == len(labels) {
			entries[uuid] = blob.Name()
		}
	}

	return entries, nil
}

// Find a particular blob by name. Returns "", nil if it does not find the
// object searched for. Error does not occur unless something unexpected
// happened.
func (b Blobs) Find(name string) (string, Blob, error) {
	if err := b.UpdateSnapshot(); err != nil {
		return "", nil, err
	}

	for uuid, entry := range b.Store.Snapshot {
		blob := Blob(entry)
		if blob.Name() == name {
			return uuid, blob, nil
		}
	}

	return "", nil, nil
}

// FindByUUID returns nil if it does not find the
// object searched for. Error does not occur unless something unexpected
// happened.
func (b Blobs) FindByUUID(uuid string) (Blob, error) {
	if err := b.UpdateSnapshot(); err != nil {
		return nil, err
	}

	blob, ok := b.Store.Snapshot[uuid]
	if !ok {
		return nil, nil
	}
	return Blob(blob), nil
}

func (b Blobs) allEntries() (entries SearchResults) {
	if len(b.Store.Snapshot) == 0 {
		return nil
	}

	entries = make(map[string]string)
	for uuid, entry := range b.Store.Snapshot {
		blob := Blob(entry)
		entries[uuid] = blob.Name()
	}
	return entries
}

// UUIDs returns a silce of unsorted uuids.
func (s SearchResults) UUIDs() []string {
	if len(s) == 0 {
		return nil
	}
	uuids := make([]string, 0, len(s))
	for uuid := range s {
		uuids = append(uuids, uuid)
	}

	return uuids
}

// Names returns a slice of unsorted names.
func (s SearchResults) Names() []string {
	if len(s) == 0 {
		return nil
	}
	names := make([]string, 0, len(s))
	for _, name := range s {
		names = append(names, name)
	}

	return names
}

// Get named object. Panics if name is not found.
func (b Blobs) Get(uuid string) (Blob, error) {
	if err := b.UpdateSnapshot(); err != nil {
		return nil, err
	}

	obj, ok := b.Store.Snapshot[uuid]
	if !ok {
		panic(uuid + " entry not found")
	}

	return Blob(obj), nil
}

// New creates a new entry. It will return ErrNameNotUnique if the name
// is not unique. The entry is not immediately inserted but instead returned
// so things may be added to it before its stored with the Add function.
func (b Blobs) New(name string) (uuid string, err error) {
	if err = b.UpdateSnapshot(); err != nil {
		return "", err
	}

	for _, entry := range b.Store.Snapshot {
		blob := Blob(entry)
		if name == blob.Name() {
			return "", ErrNameNotUnique
		}
	}

	uuid, err = b.Store.Add()
	if err != nil {
		return "", err
	}
	if err = b.touchUpdated(uuid); err != nil {
		return "", err
	}
	if err = b.Set(uuid, KeyName, name); err != nil {
		return "", err
	}

	return uuid, nil
}

// Rename a specific uuid to a new name, returns ErrNameNotUnique if not
// possible.
func (b Blobs) Rename(uuid, newName string) error {
	if err := b.UpdateSnapshot(); err != nil {
		return err
	}

	for _, entry := range b.Store.Snapshot {
		blob := Blob(entry)
		if blob.Name() == newName {
			return ErrNameNotUnique
		}
	}

	_, ok := b.Store.Snapshot[uuid]
	if !ok {
		return errors.New("uuid not found")
	}

	if err := b.touchUpdated(uuid); err != nil {
		return err
	}
	return b.Set(uuid, KeyName, newName)
}

// Set the key in name to value, properly updates 'updated' and 'snapshots'.
// If the key is value with special meaning it will panic. To update
// things like: labels, notes, twofactor, updated you must use the specific
// setters.
func (b Blobs) Set(uuid, key, value string) error {
	for _, p := range protectedKeys {
		if strings.EqualFold(key, p) {
			panic(fmt.Sprintf("key %s cannot be set with Set()", p))
		}
	}

	if err := b.touchUpdated(uuid); err != nil {
		return err
	}
	return b.Store.Set(uuid, key, value)
}

// SetTwofactor loads the totpURL to ensure it contains a totp secret key
// before setting the value.
//
// This function accepts values in two formats, it may be a simple secret
// key value like JBSWY3DPEHPK3PXP in which case it will coerced into a totp
// url.
//
// Reference for format:
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func (b Blobs) SetTwofactor(uuid, uriOrKey string) error {
	var uri string
	if strings.HasPrefix(uriOrKey, "otpauth://") {
		uri = uriOrKey
	} else {
		vals := make(url.Values)
		vals.Set("secret", uriOrKey)
		uri = fmt.Sprintf("otpauth://totp/%s?%s",
			url.PathEscape("bpass:"+uuid),
			vals.Encode(),
		)
	}

	_, err := otp.NewKeyFromURL(uri)
	if err != nil {
		return fmt.Errorf("could not set two factor key, uri wouldn't parse: %w", err)
	}

	if err = b.touchUpdated(uuid); err != nil {
		return err
	}

	if err := b.touchUpdated(uuid); err != nil {
		return err
	}
	return b.Store.Set(uuid, KeyTwoFactor, uri)
}

// AddNote to entry.
func (b Blobs) AddNote(uuid string, note string) (index string, err error) {
	return b.Append(uuid, KeyNotes, note)
}

// AddLabel to entry.
func (b Blobs) AddLabel(uuid string, label string) (index string, err error) {
	return b.Append(uuid, KeyLabels, label)
}

// NewSync creates a new blob with a unique name to have values set on it before
// calling Add() to add it to the store.
//
// AddSync can be called afterwards to add it to the list of automatic syncs
// in the master
func (b Blobs) NewSync(kind string) (uuid string, err error) {
	// Find a unique name
	newName := syncPrefix + kind
	for {
		uuid, err = b.New(newName)
		if err == nil {
			break
		} else if err != ErrNameNotUnique {
			return "", err
		}

		newName += "1"
	}

	return uuid, nil
}

// AddSync adds a uuid to the sync master list
func (b Blobs) AddSync(uuid string) error {
	// Find updates the snapshot
	masterUUID, blob, err := b.Find(syncMaster)
	if err != nil {
		return err
	}

	if len(masterUUID) == 0 {
		// We have to create a new one
		masterUUID, err = b.New(syncMaster)
		if err != nil {
			return err
		}

		return err
	} else {
		list, err := blob.Sync()
		if err != nil {
			return err
		}

		// Check that we don't have it already
		for _, l := range list {
			if l.Value == uuid {
				return nil
			}
		}
	}

	_, err = b.Append(masterUUID, KeySync, uuid)
	return nil
}

// RemoveSync removes a synchronization key from the list of master syncs.
// Returns true if it actually found something to remove
func (b Blobs) RemoveSync(uuid string) (bool, error) {
	// Find updates the snapshot
	masterUUID, blob, err := b.Find(syncMaster)
	if err != nil {
		return false, err
	}
	if len(masterUUID) == 0 {
		// There is no master, we have nothing to remove
		return false, nil
	}

	list, err := blob.Sync()
	if err != nil {
		return false, err
	}

	// Delete it if we have it
	for _, l := range list {
		if l.Value == uuid {
			return true, b.DeleteList(masterUUID, KeySync, l.UUID)
		}
	}

	return false, nil
}

// touchUpdated refreshes the updated timestamp for the given item
func (b Blobs) touchUpdated(uuid string) error {
	return b.Set(uuid, KeyUpdated, strconv.FormatInt(time.Now().UnixNano(), 10))
}
