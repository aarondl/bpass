package txblob

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aarondl/bpass/txformat"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Blob is a context of a single blob
type Blob txformat.Entry

// Keys returns all the keys known about
func (b Blob) Keys() (keys []string) {
	for k := range b {
		keys = append(keys, k)
	}
	return keys
}

// ArbitraryKeys returns all keys that are unknown to this package
func (b Blob) ArbitraryKeys() (keys []string) {
	for k := range b {
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

// Name returns the name of the blob. Panics if the key is not found.
func (b Blob) Name() string {
	name, ok := b[KeyName]
	if !ok {
		panic("name was not set")
	}

	return name.(string)
}

// Get a specific value. Panics if name is not found. Special keys require the
// use of specific getters: labels, notes, twofactor, updated etc.
func (b Blob) Get(key string) string {
	for _, p := range protectedKeys {
		if strings.EqualFold(key, p) {
			panic(fmt.Sprintf("key %s cannot be retrieved with Get()", p))
		}
	}

	intf, ok := b[key]
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
	twoFactorURIIntf := b[KeyTwoFactor]

	if twoFactorURIIntf == nil {
		return "", nil
	}

	twoFactorURI := twoFactorURIIntf.(string)
	key, err := otp.NewKeyFromURL(twoFactorURI)
	if err != nil {
		return "", fmt.Errorf("failed to parse two factor uri for %s: %w", b.Name(), err)
	}

	// There's no constant for totp here
	if key.Type() != "totp" {
		return "", fmt.Errorf("two factor key for %s was not a totp key", b.Name())
	}

	code, err := totp.GenerateCode(key.Secret(), time.Now().UTC())
	if err != nil {
		return "", err
	}

	return code, nil
}

// Notes for the blob, returns nil if not set
func (b Blob) Notes() (notes []txformat.ListEntry, err error) {
	notes, err = txformat.Entry(b).List(KeyNotes)
	if err != nil && txformat.IsKeyNotFound(err) {
		err = nil
	}
	return notes, err
}

// Labels for the blob, nil if none set.
func (b Blob) Labels() (labels []txformat.ListEntry, err error) {
	labels, err = txformat.Entry(b).List(KeyLabels)
	if err != nil && txformat.IsKeyNotFound(err) {
		err = nil
	}
	return labels, err
}

// Sync for the blob, returns nil if not set
func (b Blob) Sync() (sync []txformat.ListEntry, err error) {
	sync, err = txformat.Entry(b).List(KeySync)
	if err != nil && txformat.IsKeyNotFound(err) {
		err = nil
	}
	return sync, err
}

// Updated timestamp, if not set it will be time's zero value, returns an error
// if the underlying type was wrong.
func (b Blob) Updated() (time.Time, error) {
	return b.getTimestamp(KeyUpdated)
}

// LastSync timestamp, if not set it will be time's zero value, returns an error
// if the underlying type was wrong.
func (b Blob) LastSync() (time.Time, error) {
	return b.getTimestamp(KeyLastSync)
}

func (b Blob) getTimestamp(key string) (time.Time, error) {
	timestamp, err := txformat.Entry(b).String(key)
	if err != nil {
		if txformat.IsKeyNotFound(err) {
			return time.Time{}, nil
		}

		return time.Time{}, err
	}

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	return time.Unix(0, ts), nil
}
