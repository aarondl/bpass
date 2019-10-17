package blobformat

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/lithammer/fuzzysearch/fuzzy"
	"github.com/pkg/errors"
	"github.com/pquerna/otp"
)

// Blobs exposes operations on special keys in the blob file structure
// All manipulation should be done via this interface or special keys like
// updated and snapshots will probably be mishandled.
type Blobs map[string]interface{}

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
