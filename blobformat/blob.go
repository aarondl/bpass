package blobformat

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Blob is a context of a single blob
type Blob struct {
	Name string
	B    map[string]interface{}
}

// Keys returns all the keys known about
func (b Blob) Keys() (keys []string) {
	for k := range b.B {
		keys = append(keys, k)
	}
	return keys
}

// ArbitraryKeys returns all keys that are unknown to this package
func (b Blob) ArbitraryKeys() (keys []string) {
	for k := range b.B {
		found := false
		for _, search := range knownKeys {
			if search == k {
				found = true
				break
			}
		}

		if !found {
			keys = append(keys, k)
		}
	}

	return keys
}

// Get a specific value. Panics if name is not found. Special keys require the
// use of specific getters: labels, notes, twofactor, updated etc.
func (b Blob) Get(key string) string {
	key = strings.ToLower(key)
	for _, p := range protectedKeys {
		if key == p {
			panic(fmt.Sprintf("key %s cannot be retrieved with Get()", p))
		}
	}

	intf, ok := b.B[key]
	if !ok {
		return ""
	}

	return intf.(string)
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
		return "", fmt.Errorf("failed to parse two factor uri for %s: %w", b.Name, err)
	}

	// There's no constant for totp here
	if key.Type() != "totp" {
		return "", fmt.Errorf("two factor key for %s was not a totp key", b.Name)
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
		return nil, fmt.Errorf("%s for %s is not in the right format", keyname, b.Name)
	}

	for i, intf := range intfSlice {
		s, ok := intf.(string)
		if !ok {
			return nil, fmt.Errorf("%s[%d] for %s is not in the right format", keyname, i, b.Name)
		}

		out = append(out, s)
	}

	return out, nil
}

// Updated timestamp, if not set or invalid will be the zero value for time
func (b Blob) Updated() time.Time {
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
		return snapBlob, fmt.Errorf("snapshot called on %s which has no snapshots", b.Name)
	}

	snaps, ok := snapsIntf.([]interface{})
	if !ok {
		return snapBlob, fmt.Errorf("snapshots for %s are stored in the wrong format", b.Name)
	}

	if index < 0 || index > len(snaps) {
		return snapBlob, fmt.Errorf("%s has %d snapshot entries but given index: %d", b.Name, len(snaps), index)
	}

	index = len(snaps) - index
	snap, ok := snaps[index].(map[string]interface{})
	if !ok {
		return snapBlob, fmt.Errorf("snapshot %d is stored in the wrong format for: %s", index, b.Name)
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
		return 0, fmt.Errorf("snapshots are stored in the wrong format for %s" + b.Name)
	}

	return len(snaps), nil
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
