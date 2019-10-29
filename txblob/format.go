// Package txblob wraps txformat with password managery domain stuff
package txblob

// Keys for the map
const (
	// System level keys (things that allow the system to work)
	KeyName      = "name"
	KeyDeleted   = "deleted"
	KeyUpdated   = "updated"
	KeySnapshots = "snapshots"

	// User level known keys
	KeyUser      = "user"
	KeyEmail     = "email"
	KeyURL       = "url"
	KeyPass      = "pass"
	KeyTwoFactor = "twofactor"
	KeyNotes     = "notes"
	KeyLabels    = "labels"

	// Synchronization keys in user data
	KeySync       = "sync"
	KeyPriv       = "privkey"
	KeyPub        = "pubkey"
	KeyKnownHosts = "knownhosts"
)

const (
	syncPrefix = "sync/"
)

var (
	// known keys is a list of all known keys
	knownKeys = []string{
		KeyName,
		KeyDeleted,
		KeyUpdated,
		KeySnapshots,

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
		KeySnapshots,

		// Dates
		KeyUpdated,
	}
)
