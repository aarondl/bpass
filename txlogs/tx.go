package txlogs

// TxKind enum type
type TxKind string

// Transaction Kinds
const (
	// Add and Delete correspond to entries
	TxAdd    TxKind = "add"
	TxDelete TxKind = "del"

	// Set and Delete key correspond to key's on entries
	TxSetKey    TxKind = "setk"
	TxDeleteKey TxKind = "delk"
)

// Tx is a transaction that changes an Entry in some way
type Tx struct {
	// These fields are metadata about the change
	Time int64  `msgpack:"time,omitempty" json:"time,omitempty"`
	Kind TxKind `msgpack:"kind,omitempty" json:"kind,omitempty"`

	// The fields below relate to the object being changed
	// UUID = The object's id
	// Key = The name of the property being changed
	// Value = The value to change to
	UUID  string `msgpack:"uuid,omitempty" json:"uuid,omitempty"`
	Key   string `msgpack:"key,omitempty" json:"key,omitempty"`
	Value string `msgpack:"value,omitempty" json:"value,omitempty"`
}

// conflict types
const (
	// ConflictKindDeleteSet occurs when an entry has been deleted
	// but then an operation was performed on the deleted item.
	ConflictKindDeleteSet = iota + 1
	// ConflictKindRoot occurs when there is no shared history between
	// the two histories.
	ConflictKindRoot
)

// conflict resolutions
const (
	resolveNone = iota
	resolveDiscardInitial
	resolveDiscardConflict
	resolveForce
)

// Conflict occurs when a set occurs after a delete (meaning one sync'd copy
// added data to one that was deleted in the past)
type Conflict struct {
	Kind int

	Initial  Tx
	Conflict Tx

	resolution int
}

// DiscardConflict discards the transaction that conflicts with initial.
func (c *Conflict) DiscardConflict() {
	c.resolution = resolveDiscardConflict
}

// DiscardInitial discards the initial that created the state where the
// conflict could occur.
func (c *Conflict) DiscardInitial() {
	c.resolution = resolveDiscardInitial
}

// Force mangles the file to accept the conflicting problems.
// This only works for ConflictKindRoot.
func (c *Conflict) Force() {
	c.resolution = resolveForce
}
