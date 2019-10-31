package blobformat

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aarondl/bpass/txlogs"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Blob is a context of a single blob
type Blob txlogs.Entry

// Keys returns all the keys known about
func (b Blob) Keys() (keys []string) {
	for k := range b {
		keys = append(keys, k)
	}
	return keys
}

// Name returns the name of the blob. Panics if the key is not found.
func (b Blob) Name() string {
	name, ok := b[KeyName]
	if !ok {
		panic("name was not set")
	}

	return name
}

// Get a specific value. Panics if name is not found. Special keys require the
// use of specific getters: labels, notes, twofactor, updated etc.
func (b Blob) Get(key string) string {
	for _, p := range protectedKeys {
		if strings.EqualFold(key, p) {
			panic(fmt.Sprintf("key %s cannot be retrieved with Get()", p))
		}
	}

	return b[key]
}

// TwoFactor returns an authentication code if a secret key has been set.
// If a secret key has not been set for name, then the returned string will
// be empty but err will also be nil. If the otp library returns an error
// it will be propagated here.
//
// This uses the TOTP algorithm (Google-Authenticator like).
func (b Blob) TwoFactor() (string, error) {
	twoFactorURI := b[KeyTwoFactor]

	if len(twoFactorURI) == 0 {
		return "", nil
	}

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

// Labels for the blob
func (b Blob) Labels() []string {
	labelVal := b[KeyLabels]
	if len(labelVal) == 0 {
		return nil
	}

	return strings.Split(labelVal, ",")
}

// Updated timestamp, if not set it will be time's zero value, returns an error
// if the underlying type was wrong.
func (b Blob) Updated() (time.Time, error) {
	return b.getTimestamp(KeyUpdated)
}

func (b Blob) getTimestamp(key string) (time.Time, error) {
	timestamp, ok := txlogs.Entry(b)[key]
	if !ok {
		return time.Time{}, nil
	}

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	return time.Unix(0, ts), nil
}
