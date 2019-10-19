// Package blobformat deals with loading, storing, manipulating and querying
// the the data structure
//
// The data structure is simply json and looks something like this:
//
//    "90cc0328-302b-4b0e-b060-d2abd407c4e9": {
//       // duplicates the key above, mostyl to show to the user?
//       "uuid": "90cc0328-302b-4b0e-b060-d2abd407c4e9"
//       "name": "name"
//       // Unix timestamp
//       "deleted": 1310669017
//
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

// Keys for the map
const (
	// System level keys (things that allow the system to work)
	KeyUUID      = "uuid"
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
)

var (
	// known keys is a list of all known keys
	knownKeys = []string{
		KeyUUID,
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
	}

	// protectedKeys is a list of keys that cannot be set to a string value
	protectedKeys = []string{
		KeyName, KeyTwoFactor, KeyNotes, KeyUpdated, KeyLabels, KeySnapshots,
	}
)
