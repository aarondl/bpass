// Package blobformat deals with loading, storing, manipulating and querying
// the the data structure
//
// The data structure is simply json and looks something like this:
//
//    "name": {
//       // any arbitrary key value may be stored, but it is only string:string
//       "key": "value"
//
//       // special keys
//       "user": "abc",
//       "pass": "pass",
//       "twofactor": "somelongsecretkey",
//       "notes": ["note"],
//       "labels": ["label"],
//       // Unix timestamp
//       "updated": 1310669017
//
//       // chronological order
//       "snapshots": [
//         {
//           // all fields except snapshots itself are stored here on each edit
//           // in order to make sure we never lose information
//         }
//       ]
//    }
package blobformat

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/lithammer/fuzzysearch/fuzzy"
	"github.com/pkg/errors"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Keys for the map
const (
	KeyUser      = "user"
	KeyEmail     = "email"
	KeyPass      = "pass"
	KeyTwoFactor = "twofactor"
	KeyNotes     = "notes"
	KeyLabels    = "labels"
	KeyUpdated   = "updated"
	KeySnapshots = "snapshots"
)

var (
	// protectedKeys is a list of keys that cannot be set to a string value
	protectedKeys = []string{
		KeyTwoFactor, KeyNotes, KeyUpdated, KeyLabels, KeySnapshots,
	}
)

// Blobs exposes operations on special keys in the blob file structure
// All manipulation should be done via this interface or special keys like
// updated and snapshots will probably be mishandled.
type Blobs map[string]interface{}

// Blob is a context of a single blob
type Blob struct {
	Name string
	B    map[string]interface{}
}

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

// Save the blobs to bytes
func (b Blobs) Save() ([]byte, error) {
	return json.Marshal(b)
}

// Find searches names of entries using fuzzy search and breaks on /
// to help organization. The returned list of names is not sorted.
//
// If search is empty, all results names returned.
//
// Most other commands will require a fully qualified name of an entry to
// manipulate.
func (b Blobs) Find(search string) (names []string) {
	if len(search) == 0 {
		return b.names()
	}

	fragments := strings.Split(search, "/")
	nFrags := len(fragments)

AllKeys:
	for k := range b {
		if len(fragments) == 1 {
			if !fuzzy.MatchFold(fragments[0], k) {
				continue AllKeys
			}
		} else {
			keyFrags := strings.Split(k, "/")
			if len(keyFrags) < nFrags {
				continue
			}

			for i, f := range fragments {
				if !fuzzy.MatchFold(f, keyFrags[i]) {
					continue AllKeys
				}
			}
		}

		names = append(names, k)
	}

	return names
}

func (b Blobs) names() (names []string) {
	for n := range b {
		names = append(names, n)
	}
	return names
}

// MustFind the entire named object. Panics if name is not found.
func (b Blobs) MustFind(name string) Blob {
	obj := b.get(name)
	return Blob{B: obj, Name: name}
}

// TwoFactor returns an authentication code if a secret key has been set.
// If a secret key has not been set for name, then the returned string will
// be empty but err will also be nil. If the otp library returns an error
// it will be propagated here.
//
// This uses the TOTP algorithm (Google-Authenticator like).
func (b Blob) TwoFactor() (string, error) {
	twoFactorURIIntf := b.B[KeyTwoFactor]

	if twoFactorURIIntf == nil {
		return "", nil
	}

	twoFactorURI := twoFactorURIIntf.(string)
	key, err := otp.NewKeyFromURL(twoFactorURI)
	if err != nil {
		return "", errors.Wrapf(err, "failed to parse two factor uri for %s", b.Name)
	}

	// There's no constant for totp here
	if key.Type() != "totp" {
		return "", errors.Errorf("two factor key for %s was not a totp key", b.Name)
	}

	code, err := totp.GenerateCode(key.Secret(), time.Now().UTC())
	if err != nil {
		return "", err
	}

	return code, nil
}

// Notes for the blob, returns nil if not set
func (b Blob) Notes() (notes []string, err error) {
	return b.getSlice(KeyNotes)
}

// Labels for the blob, nil if none set.
func (b Blob) Labels() (labels []string, err error) {
	return b.getSlice(KeyLabels)
}

func (b Blob) getSlice(keyname string) (out []string, err error) {
	intf := b.B[keyname]
	if intf == nil {
		return nil, nil
	}

	intfSlice, ok := intf.([]interface{})
	if !ok {
		return nil, errors.Errorf("%s for %s is not in the right format", keyname, b.Name)
	}

	for i, intf := range intfSlice {
		s, ok := intf.(string)
		if !ok {
			return nil, errors.Errorf("%s[%d] for %s is not in the right format", keyname, i, b.Name)
		}

		out = append(out, s)
	}

	return out, nil
}

// Updated timestamp, if not set or invalid will be the zero value for time
func (b Blob) Updated(name string) time.Time {
	updatedIntf := b.B[KeyUpdated]
	if updatedIntf == nil {
		return time.Time{}
	}

	var integer int64
	switch t := updatedIntf.(type) {
	case json.Number:
		var err error
		integer, err = t.Int64()
		if err != nil {
			return time.Time{}
		}
	case int64:
		integer = t
	case int:
		integer = int64(t)
	case float64:
		integer = int64(t)
	default:
		return time.Time{}
	}

	return time.Unix(integer, 0)
}

// Snapshot fetches a snapshot of the blob for name where index is
// "how many snapshots ago". The 0th is always the most recent.
//
// Returns an error if there are no snapshots, if index is out of range
// or if snapshots is in the wrong format.
func (b Blob) Snapshot(index int) (snapBlob Blob, err error) {
	snapsIntf := b.B[KeySnapshots]
	if snapsIntf == nil {
		return snapBlob, errors.Errorf("snapshot called on %s which has no snapshots", b.Name)
	}

	snaps, ok := snapsIntf.([]interface{})
	if !ok {
		return snapBlob, errors.Errorf("snapshots for %s are stored in the wrong format", b.Name)
	}

	if index < 0 || index >= len(snaps) {
		return snapBlob, errors.Errorf("%s has %d snapshot entries but given index: %d", b.Name, len(snaps), index)
	}

	index = len(snaps) - 1 - index
	snap, ok := snaps[index].(map[string]interface{})
	if !ok {
		return snapBlob, errors.Errorf("snapshot %d is stored in the wrong format for: %s", index, b.Name)
	}

	return Blob{B: snap, Name: b.Name + fmt.Sprintf(":snap%d", index)}, nil
}

// NSnapshots returns the number of snapshots saved for the blob. Panics if name
// is not found or snapshots is not an array of objects.
func (b Blob) NSnapshots() (int, error) {
	snapsIntf := b.B[KeySnapshots]
	if snapsIntf == nil {
		return 0, nil
	}

	snaps, ok := snapsIntf.([]interface{})
	if !ok {
		return 0, errors.Errorf("snapshots are stored in the wrong format for %s" + b.Name)
	}

	return len(snaps), nil
}

// Get a specific value. Panics if name is not found. Special keys require the
// use of specific getters: labels, notes, twofactor, updated etc.
func (b Blobs) Get(name, key, value string) string {
	key = strings.ToLower(key)
	for _, p := range protectedKeys {
		if key == p {
			panic(fmt.Sprintf("key %s cannot be set with Set()", p))
		}
	}

	blob := b.MustFind(name)
	return blob.B[key].(string)
}

// Set the key in name to value, properly updates 'updated' and 'snapshots'.
// If the key is value with special meaning it will panic. To update
// things like: labels, notes, twofactor, updated you must use the specific
// setters.
func (b Blobs) Set(name, key, value string) {
	key = strings.ToLower(key)
	for _, p := range protectedKeys {
		if key == p {
			panic(fmt.Sprintf("key %s cannot be set with Set()", p))
		}
	}

	blobIntf, ok := b[name]
	var blob Blob
	if ok {
		blob = Blob{B: blobIntf.(map[string]interface{}), Name: name}
		blob.addSnapshot()
	} else {
		blob = Blob{B: make(map[string]interface{}), Name: name}
		b[name] = blob.B
	}

	blob.touchUpdated()
	blob.B[key] = value
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
func (b Blobs) SetTwofactor(name, uriOrKey string) error {
	blob := b.MustFind(name)

	var uri string
	if strings.HasPrefix(uriOrKey, "otpauth://") {
		uri = uriOrKey
	} else {
		vals := make(url.Values)
		vals.Set("secret", uriOrKey)
		uri = fmt.Sprintf("otpauth://totp/%s?%s",
			url.PathEscape("bpass:"+name),
			vals.Encode(),
		)
	}

	_, err := otp.NewKeyFromURL(uri)
	if err != nil {
		return errors.Wrap(err, "could not set two factor key, uri wouldn't parse")
	}

	blob.addSnapshot()
	blob.touchUpdated()
	blob.B[KeyTwoFactor] = uri
	return nil
}

// SetNotes on name. Records a snapshot and sets updated.
func (b Blobs) SetNotes(name string, notes []string) {
	blob := b.MustFind(name)

	var uglyConversion []interface{}
	for _, s := range notes {
		uglyConversion = append(uglyConversion, s)
	}

	blob.touchUpdated()
	blob.B[KeyNotes] = uglyConversion
}

// SetLabels on name. Does not record a snapshot, but does update 'updated'.
// This is because labels are considered part of metadata that's uninteresting
// and isn't worth a snapshot.
func (b Blobs) SetLabels(name string, labels []string) {
	blob := b.MustFind(name)

	var uglyConversion []interface{}
	for _, s := range labels {
		uglyConversion = append(uglyConversion, s)
	}

	blob.touchUpdated()
	blob.B[KeyLabels] = uglyConversion
}

// get retrieves an entire object without a copy and panics if name is not found
// or if the data structure is the wrong type
func (b Blobs) get(name string) map[string]interface{} {
	obj, ok := b[name]
	if !ok {
		panic(name + " entry not found")
	}

	mpintf, ok := obj.(map[string]interface{})
	if !ok {
		panic(name + " entry was not in the correct format")
	}

	return mpintf
}

// touchUpdated refreshes the updated timestamp
func (b Blob) touchUpdated() {
	now := time.Now().Unix()
	b.B[KeyUpdated] = now
}

// addSnapshot adds a new snapshot containing all the current values into
// the blob's snapshot list
func (b Blob) addSnapshot() {
	var snaps []interface{}
	snapsIntf, ok := b.B[KeySnapshots]
	if !ok {
		snaps = make([]interface{}, 0, 1)
	} else {
		snaps, ok = snapsIntf.([]interface{})
	}

	snaps = append(snaps, b.snapshot())
	b.B[KeySnapshots] = snaps
}

// snapshot creates a deep copy of a map[string]interface{} excluding the
// 'snapshots' key.
//
// The only types that are copied here are string, []string, int64/float64
func (b Blob) snapshot() map[string]interface{} {
	clone := make(map[string]interface{}, len(b.B))
	for k, v := range b.B {
		// Do not include snapshots in the new snapshot
		if k == KeySnapshots {
			continue
		}

		switch val := v.(type) {
		case json.Number:
			clone[k] = val
		case string:
			clone[k] = val
		case float64:
			clone[k] = val
		case int64:
			clone[k] = val
		case []interface{}:
			// This is assumed to be a []string, so there should be no problem
			// with a copy here
			slice := make([]interface{}, len(val))
			copy(slice, val)
			clone[k] = slice
		}
	}

	return clone
}
