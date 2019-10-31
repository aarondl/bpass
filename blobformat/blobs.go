package blobformat

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aarondl/bpass/fuzzy"
	"github.com/aarondl/bpass/txlogs"

	"github.com/pquerna/otp"
)

// Sentinel errors
var (
	ErrNameNotUnique = errors.New("name is not unique")
	ErrKeyNotAllowed = errors.New("key is not allowed")
)

type keyNotAllowed string

func (k keyNotAllowed) Error() string {
	return fmt.Sprintf("%q may not be set", k)
}

// IsKeyNotAllowed checks if the error is a key error (some keys cannot
// be altered by humans)
func IsKeyNotAllowed(err error) bool {
	_, ok := err.(keyNotAllowed)
	return ok
}

// Blobs exposes operations on special keys in the blob file structure
// All manipulation should be done via this interface or special keys like
// updated and snapshots will probably be mishandled.
type Blobs struct {
	*txlogs.DB
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

		b.touchUpdated(uuid)
		b.Set(uuid, KeyName, name)
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

	if len(b.DB.Snapshot) == 0 {
		return nil, nil
	}
	if len(search) == 0 {
		return b.allEntries(), nil
	}

	entries = make(map[string]string)
	fragments := strings.Split(search, "/")
	nFrags := len(fragments)

AllKeys:
	for uuid, entry := range b.DB.Snapshot {
		blob := Blob(entry)
		name := blob.Name()

		if len(fragments) == 1 {
			if !fuzzy.Match(name, fragments[0]) {
				continue AllKeys
			}
		} else {
			keyFrags := strings.Split(name, "/")
			if len(keyFrags) < nFrags {
				continue
			}

			for i, f := range fragments {
				if !fuzzy.Match(keyFrags[i], f) {
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

	if len(b.DB.Snapshot) == 0 {
		return nil, nil
	}
	if len(labels) == 0 {
		return b.allEntries(), nil
	}

	entries = make(map[string]string)
	for uuid, entry := range b.DB.Snapshot {
		blob := Blob(entry)

		lblVal := blob[KeyLabels]
		if len(lblVal) == 0 {
			continue
		}

		haveLabels := strings.Split(lblVal, ",")

		found := 0
		for _, want := range labels {
			for _, have := range haveLabels {
				if have != want {
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

	for uuid, entry := range b.DB.Snapshot {
		blob := Blob(entry)
		if blob.Name() == name {
			return uuid, blob, nil
		}
	}

	return "", nil, nil
}

// FindByUUID returns nil if it does not find the object searched for.
// Error does not occur unless something unexpected happened. This is slightly
// useful because it calls UpdateSnapshot for you which does not happen
// when accessing the map directly.
func (b Blobs) FindByUUID(uuid string) (Blob, error) {
	if err := b.UpdateSnapshot(); err != nil {
		return nil, err
	}

	blob, ok := b.DB.Snapshot[uuid]
	if !ok {
		return nil, nil
	}
	return Blob(blob), nil
}

func (b Blobs) allEntries() (entries SearchResults) {
	if len(b.DB.Snapshot) == 0 {
		return nil
	}

	entries = make(map[string]string)
	for uuid, entry := range b.DB.Snapshot {
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

	obj, ok := b.DB.Snapshot[uuid]
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

	for _, entry := range b.DB.Snapshot {
		blob := Blob(entry)
		if name == blob.Name() {
			return "", ErrNameNotUnique
		}
	}

	uuid, err = b.DB.Add()
	if err != nil {
		return "", err
	}
	b.touchUpdated(uuid)
	b.DB.Set(uuid, KeyName, name)

	return uuid, nil
}

// Rename a specific uuid to a new name, returns ErrNameNotUnique if not
// possible.
func (b Blobs) Rename(uuid, newName string) error {
	if err := b.UpdateSnapshot(); err != nil {
		return err
	}

	for _, entry := range b.DB.Snapshot {
		blob := Blob(entry)
		if blob.Name() == newName {
			return ErrNameNotUnique
		}
	}

	_, ok := b.DB.Snapshot[uuid]
	if !ok {
		return errors.New("uuid not found")
	}

	b.touchUpdated(uuid)
	b.DB.Set(uuid, KeyName, newName)
	return nil
}

// Set the key in name to value, properly updates 'updated' and 'snapshots'.
// returns keyNotAllowed error if a protected key is attempted to be set.
// To update protected keys like: labels, notes, twofactor, updated you must
// use the specific setters.
func (b Blobs) Set(uuid, key, value string) error {
	for _, p := range protectedKeys {
		if strings.EqualFold(key, p) {
			return keyNotAllowed(key)
		}
	}

	b.touchUpdated(uuid)
	b.DB.Set(uuid, key, value)
	return nil
}

// DeleteKey from an entry, follows the rules of Set() for protected keys.
func (b Blobs) DeleteKey(uuid, key string) error {
	switch key {
	case KeyName, KeyUpdated:
		return keyNotAllowed(key)
	}

	b.touchUpdated(uuid)
	b.DB.DeleteKey(uuid, key)
	return nil
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

	b.touchUpdated(uuid)
	b.DB.Set(uuid, KeyTwoFactor, uri)
	return nil
}

// AddLabel to entry.
func (b Blobs) AddLabel(uuid, label string) (err error) {
	entry, err := b.Get(uuid)
	if err != nil {
		return err
	}

	labelVal := entry[KeyLabels]
	if len(labelVal) == 0 {
		labelVal = label
	} else {
		labels := strings.Split(labelVal, ",")
		labels = append(labels, label)
		labelVal = strings.Join(labels, ",")
	}

	b.touchUpdated(uuid)
	return b.Set(uuid, KeyLabels, labelVal)
}

// RemoveLabel from uuid using the list element's index
func (b Blobs) RemoveLabel(uuid string, index int) (err error) {
	entry, err := b.Get(uuid)
	if err != nil {
		return err
	}

	labels := strings.Split(entry[KeyLabels], ",")
	if index >= len(labels) {
		return errors.New("index out of range")
	}

	if len(labels) == 1 {
		b.DB.DeleteKey(uuid, KeyLabels)
		return nil
	}

	copy(labels[index:], labels[index+1:])
	labels = labels[len(labels)-1:]

	b.touchUpdated(uuid)
	b.DB.Set(uuid, KeyLabels, strings.Join(labels, ","))
	return nil
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

// touchUpdated refreshes the updated timestamp for the given item
func (b Blobs) touchUpdated(uuid string) {
	b.DB.Set(uuid, KeyUpdated, strconv.FormatInt(time.Now().UnixNano(), 10))
}
