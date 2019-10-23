package blobformat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	uuidpkg "github.com/gofrs/uuid"
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
type Blobs map[string]interface{}

// SearchResults have helpers to get uuids/names easily
type SearchResults map[string]string

// New loads the format into a manipulatable structure
func New(serialized []byte) (Blobs, error) {
	blobs := make(map[string]interface{})

	dec := json.NewDecoder(bytes.NewReader(serialized))
	dec.UseNumber()
	if err := dec.Decode(&blobs); err != nil {
		return nil, err
	}

	return blobs, nil
}

// RenameDuplicates renames names (KeyName) that collide.
// Creates snapshots as it does so. Returns a list of renames that it did.
func (b Blobs) RenameDuplicates() map[string]string {
	names := make(map[string]struct{})
	renames := make(map[string]string)

	for _, blobIntf := range b {
		blob := Blob(blobIntf.(map[string]interface{}))
		name := blob.Name()

		_, ok := names[name]
		if ok {
			oldName := name
			for ok {
				name = name + "1"
				_, ok = names[name]
			}

			renames[oldName] = name

			blob.addSnapshot()
			blob.touchUpdated()
			blob[KeyName] = name
		}

		names[name] = struct{}{}
	}

	return renames
}

// Save the blobs to bytes
func (b Blobs) Save() ([]byte, error) {
	return json.Marshal(b)
}

// Search names of entries using fuzzy search and breaks on /
// to help organization. The returned list of names is not sorted.
//
// If search is empty, all results names returned.
//
// Most other commands will require a fully qualified name of an entry to
// manipulate.
func (b Blobs) Search(search string) (entries SearchResults) {
	if len(b) == 0 {
		return nil
	}
	if len(search) == 0 {
		return b.allEntries()
	}

	entries = make(map[string]string)

	fragments := strings.Split(search, "/")
	nFrags := len(fragments)

AllKeys:
	for uuid, blobIntf := range b {
		blob := Blob(blobIntf.(map[string]interface{}))

		if blob.Deleted() {
			continue
		}

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

	return entries
}

// SearchLabels searches by finding all entries with all the labels given.
func (b Blobs) SearchLabels(labels ...string) (entries SearchResults) {
	if len(b) == 0 {
		return nil
	}
	if len(labels) == 0 {
		return b.allEntries()
	}

	entries = make(map[string]string)
	for uuid, blobIntf := range b {
		blob := Blob(blobIntf.(map[string]interface{}))

		found := 0
		for _, w := range labels {
			haveLabels, err := blob.Labels()
			if err != nil {
				fmt.Fprintln(os.Stderr, "failed to parse labels for entry", uuid)
				return nil
			}

			for _, h := range haveLabels {
				if h != w {
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

	return entries
}

// Find a particular blob by name. Returns "", nil if it does not find the
// object searched for.
func (b Blobs) Find(name string) (string, Blob) {
	for uuid, blobIntf := range b {
		blob := Blob(blobIntf.(map[string]interface{}))
		if blob.Name() == name {
			return uuid, blob
		}
	}

	return "", nil
}

func (b Blobs) allEntries() (entries SearchResults) {
	if len(b) == 0 {
		return nil
	}

	entries = make(map[string]string)
	for uuid, blobIntf := range b {
		blob := Blob(blobIntf.(map[string]interface{}))
		if blob.Deleted() {
			continue
		}
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
func (b Blobs) Get(uuid string) Blob {
	obj, ok := b[uuid]
	if !ok {
		panic(uuid + " entry not found")
	}

	mpintf, ok := obj.(map[string]interface{})
	if !ok {
		panic(uuid + " entry was not in the correct format")
	}

	return mpintf
}

// New creates a new entry with, it will return ErrNameNotUnique if the name
// is not unique. The entry is not immediately inserted but instead returned
// so things may be added to it before its stored with the Add function.
func (b Blobs) New(name string) (Blob, error) {
	for _, blobIntf := range b {
		blob := Blob(blobIntf.(map[string]interface{}))
		if name == blob.Name() {
			return nil, ErrNameNotUnique
		}
	}

	uuidObj, err := uuidpkg.NewV4()
	if err != nil {
		return nil, err
	}
	uuid := uuidObj.String()

	blob := Blob{
		KeyUUID:    uuid,
		KeyName:    name,
		KeyUpdated: time.Now().Unix(),
	}
	return blob, nil
}

// Add will error if name/uuid is not set, or if either of them are not unique
func (b Blobs) Add(blob Blob) error {
	uuid := blob.Get(KeyUUID)
	name := blob.Get(KeyName)

	if len(uuid) == 0 {
		return errors.New("uuid cannot be empty")
	}
	if len(name) == 0 {
		return errors.New("name cannot be empty")
	}

	_, ok := b[uuid]
	if ok {
		return errors.New("uuid is not unique")
	}

	for _, blobIntf := range b {
		searchBlob := Blob(blobIntf.(map[string]interface{}))
		if name == searchBlob.Name() {
			return ErrNameNotUnique
		}
	}

	b[uuid] = map[string]interface{}(blob)
	return nil
}

// Rename a specific UUID to a new name, returns ErrNameNotUnique if not
// possible
func (b Blobs) Rename(srcUUID, dstName string) error {
	hasUUID, _ := b.Find(dstName)
	if len(hasUUID) != 0 {
		return ErrNameNotUnique
	}

	blobIntf, ok := b[srcUUID]
	if !ok {
		return errors.New("uuid not found")
	}

	blob := Blob(blobIntf.(map[string]interface{}))
	blob.addSnapshot()
	blob.touchUpdated()
	blob[KeyName] = dstName
	return nil
}

// Set the key in name to value, properly updates 'updated' and 'snapshots'.
// If the key is value with special meaning it will panic. To update
// things like: labels, notes, twofactor, updated you must use the specific
// setters. Panics if uuid is not found.
func (b Blobs) Set(uuid, key, value string) {
	for _, p := range protectedKeys {
		if strings.EqualFold(key, p) {

			panic(fmt.Sprintf("key %s cannot be set with Set()", p))
		}
	}

	blob := b.Get(uuid)
	blob.addSnapshot()
	blob.touchUpdated()
	blob[key] = value
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
	blob := b.Get(uuid)

	var uri string
	if strings.HasPrefix(uriOrKey, "otpauth://") {
		uri = uriOrKey
	} else {
		vals := make(url.Values)
		vals.Set("secret", uriOrKey)
		uri = fmt.Sprintf("otpauth://totp/%s?%s",
			url.PathEscape("bpass:"+blob.Name()),
			vals.Encode(),
		)
	}

	_, err := otp.NewKeyFromURL(uri)
	if err != nil {
		return fmt.Errorf("could not set two factor key, uri wouldn't parse: %w", err)
	}

	blob.addSnapshot()
	blob.touchUpdated()
	blob[KeyTwoFactor] = uri
	return nil
}

// SetNotes on name. Records a snapshot and sets updated.
func (b Blobs) SetNotes(uuid string, notes []string) {
	b.setSlice(uuid, KeyNotes, notes)
}

// SetLabels on name. Records a snapshot and sets updated.
func (b Blobs) SetLabels(uuid string, labels []string) {
	b.setSlice(uuid, KeyLabels, labels)
}

// NewSync creates a new blob with a unique name to have values set on it before
// calling Add() to add it to the store.
//
// AddSync can be called afterwards to add it to the list of automatic syncs
// in the master
func (b Blobs) NewSync(kind string) (Blob, error) {
	// Find a unique name
	newName := syncPrefix + kind
	var blob Blob
	var err error
	for {
		blob, err = b.New(newName)
		if err == nil {
			break
		} else if err != ErrNameNotUnique {
			return nil, err
		}

		newName += "1"
	}

	return blob, nil
}

// AddSync adds a uuid to the sync master list
func (b Blobs) AddSync(uuid string) error {
	masterUUID, blob := b.Find(syncMaster)
	if len(masterUUID) == 0 {
		// We have to create a new one
		blob, err := b.New(syncMaster)
		if err != nil {
			return err
		}
		blob[KeySync] = []interface{}{uuid}
		return b.Add(blob)
	}

	// If there's no KeySync just add it and go away
	syncsIntf := blob[KeySync]
	if syncsIntf == nil {
		blob[KeySync] = []interface{}{uuid}
		return nil
	}

	// Don't use helpers to avoid snapshotting
	syncs := syncsIntf.([]interface{})
	syncs = append(syncs, uuid)
	blob[KeySync] = syncs

	return nil
}

// RemoveSync removes a synchronization key from the list of master syncs.
// Returns true if it actually found something to remove
func (b Blobs) RemoveSync(uuid string) (bool, error) {
	masterUUID, blob := b.Find(syncMaster)
	if len(masterUUID) == 0 {
		// There is no master, we have nothing to remove
		return false, nil
	}

	syncsIntf := blob[KeySync]
	if syncsIntf == nil {
		return false, nil
	}

	syncs, ok := syncsIntf.([]interface{})
	if !ok {
		return false, fmt.Errorf("sync list was not the correct type: %T", syncsIntf)
	}
	for i, s := range syncs {
		str, ok := s.(string)
		if !ok {
			return false, fmt.Errorf("sync list item was not the correct type: %T", s)
		}

		if str == uuid {
			syncs[len(syncs)-1], syncs[i] = syncs[i], syncs[len(syncs)-1]
			syncs = syncs[:len(syncs)-1]
			blob[KeySync] = syncs
			return true, nil
		}
	}

	return false, nil
}

func (b Blobs) setSlice(uuid, key string, slice []string) {
	blob := b.Get(uuid)

	var uglyConversion []interface{}
	for _, s := range slice {
		uglyConversion = append(uglyConversion, s)
	}

	blob.addSnapshot()
	blob.touchUpdated()
	blob[key] = uglyConversion
}
