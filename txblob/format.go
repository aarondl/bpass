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
	KeySecret     = "secretkey"
	KeyPub        = "pubkey"
	KeyHost       = "host"
	KeyPort       = "port"
	KeyPath       = "path"
	KeyKnownHosts = "knownhosts"
	KeyLastSync   = "lastsync"
)

const (
	syncPrefix = "sync/"
	syncMaster = syncPrefix + "master"
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
		KeySecret,
		KeyPub,
		KeyHost,
		KeyPort,
		KeyPath,
		KeyKnownHosts,
		KeyLastSync,
	}

	// protectedKeys is a list of keys that cannot be set to a string value
	protectedKeys = []string{
		KeyTwoFactor, KeyNotes, KeyUpdated, KeyLabels, KeySnapshots,
		KeySync, KeyLastSync,
	}
)
