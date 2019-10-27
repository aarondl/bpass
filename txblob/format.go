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
	KeyPass      = "pass"
	KeyTwoFactor = "twofactor"
	KeyNotes     = "notes"
	KeyLabels    = "labels"

	// Synchronization keys in user data
	KeySync       = "sync"
	KeySyncKind   = "synckind"
	KeyPriv       = "privkey"
	KeyPub        = "pubkey"
	KeyHost       = "host"
	KeyPort       = "port"
	KeyPath       = "path"
	KeyKnownHosts = "knownhosts"
	KeyLastSync   = "lastsync"
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
		KeySyncKind,
		KeyPriv,
		KeyPub,
		KeyHost,
		KeyPort,
		KeyPath,
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

		// Slices
		KeyNotes, KeyLabels, KeyKnownHosts,
	}
)
