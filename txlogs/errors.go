package txlogs

import "fmt"

// KeyNotFound occurs when a key is not found.
// The UUID refers to the object's uuid, the key is the key in the object, and
// the index refers to a uuid of a list item that was being searched for.
//
// There must be exactly 1 of these non-empty.
type KeyNotFound struct {
	UUID  string
	Key   string
	Index string
}

// Error interface
func (k KeyNotFound) Error() string {
	var str string
	var obj string
	if len(k.UUID) != 0 {
		str += k.UUID
		obj = "entry"
	}
	if len(k.Key) != 0 {
		if len(str) != 0 {
			str += ":"
		}
		str += k.Key
		obj = "key"
	}
	if len(k.Index) != 0 {
		if len(str) != 0 {
			str += ":"
		}
		str += k.Index
		obj = "list index"
	}
	return fmt.Sprintf("%s %s was not found", str, obj)
}

// UUIDNotFound occurs when a uuid (entry) is not found
type UUIDNotFound string

func (u UUIDNotFound) Error() string {
	return string(u) + " was not found"
}

// IsKeyNotFound checks if the error is a key not found error
func IsKeyNotFound(err error) bool {
	_, ok := err.(KeyNotFound)
	return ok
}

// IsUUIDNotFound checks if the error is a uuid not found error
func IsUUIDNotFound(err error) bool {
	_, ok := err.(UUIDNotFound)
	return ok
}
