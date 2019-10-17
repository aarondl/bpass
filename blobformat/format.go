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
	// known keys is a list of all known keys
	knownKeys = []string{
		KeyUser,
		KeyEmail,
		KeyPass,
		KeyTwoFactor,
		KeyNotes,
		KeyLabels,
		KeyUpdated,
		KeySnapshots,
	}

	// protectedKeys is a list of keys that cannot be set to a string value
	protectedKeys = []string{
		KeyTwoFactor, KeyNotes, KeyUpdated, KeyLabels, KeySnapshots,
	}
)
