package txformat

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

// conflict resolutions
const (
	conflictNone = iota
	conflictDelete
	conflictRestore
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

// Conflict occurs when a set occurs after a delete (meaning one sync'd copy
// added data to one that was deleted in the past)
type Conflict struct {
	DeleteTx Tx
	SetTx    Tx

	resolution int
}

// Delete discards the set transaction from the log
func (c *Conflict) Delete() {
	c.resolution = conflictDelete
}

// Restore discards the delete transaction from the log
func (c *Conflict) Restore() {
	c.resolution = conflictRestore
}
