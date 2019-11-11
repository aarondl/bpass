// Package blobformat wraps txlogs with password managery domain stuff
package blobformat

// Keys for the map
const (
	// System level keys (things that allow the system to work)
	KeyName    = "name"
	KeyUpdated = "updated"

	// User level known keys
	KeyUser      = "user"
	KeyEmail     = "email"
	KeyURL       = "url"
	KeyPass      = "pass"
	KeyTwoFactor = "totp"
	KeyNotes     = "notes"
	KeyLabels    = "labels"

	// Synchronization keys in user data
	KeySync       = "sync"
	KeyPriv       = "privkey"
	KeyPub        = "pubkey"
	KeyKnownHosts = "knownhosts"

	// User keys
	KeyIV   = "iv"
	KeySalt = "salt"
	KeyMKey = "mkey"
)

const (
	syncPrefix = "sync/"
	userPrefix = "user/"
)

var (
	// known keys is a list of all known keys
	knownKeys = []string{
		KeyName,
		KeyUpdated,

		KeyUser,
		KeyEmail,
		KeyPass,
		KeyTwoFactor,
		KeyNotes,
		KeyLabels,

		KeySync,
		KeyPriv,
		KeyPub,
		KeyKnownHosts,
	}

	// protectedKeys is a list of keys that cannot be set to a string value
	protectedKeys = []string{
		// Special setters
		KeyTwoFactor,

		// Forbidden
		KeyName,
		KeyIV,
		KeySalt,
		KeyMKey,

		// Dates
		KeyUpdated,
	}
)
