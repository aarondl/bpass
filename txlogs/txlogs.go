// Package txlogs manages a key-value database built with a transactional log.
package txlogs

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	uuidpkg "github.com/gofrs/uuid"
)

// DB contains a transaction log, and a snapshot at a particular version.
// The transaction logs are made up of Txs. You can see all the kinds possible
// on the documentation for Tx.
//
// On-disk it will look like this (uuids truncated for readability):
//
//   {
//     "version": 5,
//     "snapshot": {
//       "d6f...": {
//         "test1": "notvalue"
//       }
//     },
//     "log": [
//       { "time": 1571887976, "kind": "add", "uuid": "d6f..." },
//       { "time": 1571887977, "kind": "set", "uuid": "d6f...", "key": "test1", "value": "value" },
//       { "time": 1571887978, "kind": "set", "uuid": "d6f...", "key": "test2", "value": "value" },
//       { "time": 1571887979, "kind": "set", "uuid": "d6f...", "key": "test1", "value": "notvalue" },
//       { "time": 1571887979, "kind": "delkey", "uuid": "d6f...", "key": "test2" }
//     ]
//   }
type DB struct {
	// Version of the snapshot
	Version uint `msgpack:"version,omitempty" json:"version,omitempty"`
	// Snapshot of the data at a specific version
	Snapshot map[string]Entry `msgpack:"snapshot,omitempty" json:"snapshot,omitempty"`
	// Log of all transactions.
	Log []Tx `msgpack:"log,omitempty" json:"log,omitempty"`

	txPoint int
}

// Entry is a cached entry in the store, it holds the values as currently
// known.
type Entry map[string]string

type storeNoSnapshot struct {
	Log []Tx `msgpack:"log,omitempty" json:"log,omitempty"`
}

// New takes a json blob and unmarshals it into a DB
func New(data []byte) (*DB, error) {
	s := new(DB)
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}

	return s, nil
}

// NewLog parses the same data as New() but only returns the log
func NewLog(data []byte) ([]Tx, error) {
	s := new(storeNoSnapshot)
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}

	return s.Log, nil
}

// Save marshals as json blob
func (s *DB) Save() ([]byte, error) {
	if s.txPoint != 0 {
		return nil, errors.New("refusing to save while transaction active")
	}

	return json.Marshal(s)
}

// Add a new entry
func (s *DB) Add() (uuid string, err error) {
	uuidObj, err := uuidpkg.NewV4()
	if err != nil {
		return "", err
	}

	// Does not use appendLog so ID/Time must be filled out by hand
	s.Log = append(s.Log,
		Tx{
			Time: time.Now().UnixNano(),
			Kind: TxAdd,
			UUID: uuidObj.String(),
		},
	)

	return uuidObj.String(), nil
}

// Set k=v for a uuid
func (s *DB) Set(uuid, key, value string) {
	s.appendLog(
		Tx{
			Kind:  TxSetKey,
			UUID:  uuid,
			Key:   key,
			Value: value,
		},
	)
}

// Delete an entry
func (s *DB) Delete(uuid string) {
	s.appendLog(
		Tx{
			Kind: TxDelete,
			UUID: uuid,
		},
	)
}

// DeleteKey deletes a key from an entry
func (s *DB) DeleteKey(uuid, key string) {
	s.appendLog(
		Tx{
			Kind: TxDeleteKey,
			UUID: uuid,
			Key:  key,
		},
	)
}

// appendLog creates a new UUID for tx.ID and appends the log
func (s *DB) appendLog(tx Tx) {
	tx.Time = time.Now().UnixNano()
	s.Log = append(s.Log, tx)
}

// Begin a transaction, will panic if commit/rollback have not been issued
// after a previous Begin.
//
// We add 1 to the length to keep the 0 valid as a "no transaction started"
// sentinel value.
func (s *DB) Begin() {
	s.txPoint = len(s.Log) + 1
}

// Commit the transactions to the log
func (s *DB) Commit() {
	if s.txPoint == 0 {
		panic("commit called before begin")
	}
	s.txPoint = 0
}

// Rollback to the last begin point, invalidates the snapshot if necessary
func (s *DB) Rollback() {
	if s.txPoint == 0 {
		panic("rollback called before begin")
	}

	if s.Version > uint(s.txPoint) {
		s.ResetSnapshot()
	}

	s.Log = s.Log[:s.txPoint-1]
	s.txPoint = 0
}

// Do a transaction, if an error is returned by the lambda then
// the transaction is rolled back.
func (s *DB) Do(fn func() error) error {
	s.Begin()
	err := fn()
	if err != nil {
		s.Rollback()
	} else {
		s.Commit()
	}
	return err
}

// RollbackN undoes the last N transactions and invalidates the snapshot
// if necessary.
func (s *DB) RollbackN(n uint) error {
	if n == 0 {
		return nil
	}

	ln := uint(len(s.Log))
	if n > ln {
		return errors.New("cannot rollback past the beginning")
	}

	if s.Version > ln-n {
		s.ResetSnapshot()
	}

	s.Log = s.Log[:ln-n]

	return nil
}

// ResetSnapshot clears the current snapshot out of memory
func (s *DB) ResetSnapshot() {
	s.Version = 0
	s.Snapshot = nil
}

// UpdateSnapshot applies all outstanding transactions in the log to the
// snapshot.
func (s *DB) UpdateSnapshot() error {
	if s.Version >= uint(len(s.Log)) {
		return nil
	}

	if s.Snapshot == nil {
		s.Snapshot = make(map[string]Entry)
	}

	for ; s.Version < uint(len(s.Log)); s.Version++ {
		if err := applyTx(s.Snapshot, s.Log[s.Version]); err != nil {
			return err
		}
	}

	return nil
}

// SnapshotAt creates a new snapshot of a particular entry versionsAgo
// in the past.
func (s *DB) SnapshotAt(versionsAgo int) (map[string]Entry, error) {
	if versionsAgo > len(s.Log) {
		return nil, errors.New("there are not that many versions")
	}

	stopVersion := len(s.Log) - 1 - versionsAgo
	snap := make(map[string]Entry)
	for i := 0; i <= stopVersion; i++ {
		if err := applyTx(snap, s.Log[i]); err != nil {
			return nil, err
		}
	}

	return snap, nil
}

// EntrySnapshotAt creates a new snapshot of a particular entry versionsAgo
// in the past. If history past the existence of the entry is requested
// a KeyNotFound error may be present.
func (s *DB) EntrySnapshotAt(uuid string, versionsAgo int) (Entry, error) {
	if versionsAgo >= len(s.Log) {
		return nil, errors.New("there are not that many versions")
	}

	entryTxIndicies := make([]int, 0)
	for i := 0; i < len(s.Log); i++ {
		if s.Log[i].UUID != uuid {
			continue
		}

		entryTxIndicies = append(entryTxIndicies, i)
	}

	if versionsAgo > len(entryTxIndicies) {
		return nil, errors.New("there are not that many versions for the entry")
	}

	stopVersion := len(entryTxIndicies) - 1 - versionsAgo
	snap := make(map[string]Entry, 1)
	for i := 0; i <= stopVersion; i++ {
		index := entryTxIndicies[i]
		if err := applyTx(snap, s.Log[index]); err != nil {
			return nil, err
		}
	}

	if entry, ok := snap[uuid]; ok {
		return entry, nil
	}

	return nil, KeyNotFound{UUID: uuid}
}

// NVersions returns the number of versions we have recorded about an item
func (s *DB) NVersions(uuid string) (versions int) {
	for _, l := range s.Log {
		if l.UUID == uuid {
			versions++
		}
	}

	return versions
}

// LastUpdated returns the unix nanosecond timestamp for when the entry was
// updated last. Will be -1 if the entry is not found.
func (s *DB) LastUpdated(uuid string) (last int64) {
	last = -1

	for i := len(s.Log) - 1; i >= 0; i-- {
		if s.Log[i].UUID == uuid {
			last = s.Log[i].Time
			break
		}
	}

	return last
}

// Merge logs together. The standard case for merging is that the logs proceed
// in order with the same uuids.
//
// There is a no-fork fast-path in which a is returned if lengths are the same
// and they start and end with the same transaction ids.
//
// When a fork occurs the logs need to be reconciled. The reconciliation is
// done by accepting each change in order deterministically, it sorts first
// by timestamp, then by uuid as a fallback in case the changes (unlikely)
// happened inside the timestamps max resolution.
//
// The only conflicting situation is where an event occurs on an item after
// it has been deleted. In this case the conflicts are returned and must
// be resolved and passed back into this method for it to complete.
//
// If conflicts have not been resolved the same set of conflicts will simply
// be returned.
func Merge(a, b []Tx, resolved []Conflict) (c []Tx, conflicts []Conflict) {
	for _, r := range resolved {
		if r.resolution == resolveNone {
			return nil, resolved
		}
	}

	lena := len(a)
	lenb := len(b)

	if lena == lenb &&
		a[0].Time == b[0].Time && a[lena-1].Time == b[lenb-1].Time {
		// These are the same list of events
		// There can be no possible fork that has happened if they
		// 1. Are not of differing length
		// 2. Start at the unique ID
		// 3. End at the unique ID
		return a, nil
	}

	most := lena
	if lenb > most {
		most = lenb
	}

	c = make([]Tx, 0, most)
	deleted := make(map[string]int)

	// CheckConflict checks the last thing that was appended to c to see
	// if there's a conflict with having added that event.
	// It creates a single conflict per uuid/delete combo.
	//
	// In the event that there's a resolution for this particular conflict
	// it will be applied here by deleting the deletion event off the end of c
	// or by deleting the sets that conflicted with it off of c
	checkConflict := func() {
		last := len(c) - 1
		ind, wasDeleted := deleted[c[last].UUID]
		// If we haven't been marked as deleted, and we're a delete event
		// mark it as such. If we haven't been marked as deleted before
		// and we're not a delete event, it doesn't matter.
		if !wasDeleted {
			if c[last].Kind != TxDelete {
				return
			}

			// Before we mark ourselves as deleted, make sure we aren't
			// part of a resolution.
			for _, res := range resolved {
				if res.Initial.Time != c[last].Time {
					continue
				}

				// We are part of this resolution
				if res.resolution == resolveDiscardInitial {
					// We delete ourselves
					c = c[:last]
					return
				}
			}

			deleted[c[last].UUID] = last
			return
		}

		// We've previously been deleted and have found an add/set operation of
		// some kind, this is a conflict.
		deleteTx := c[ind]
		// Check if its resolved
		for _, res := range resolved {
			if res.Initial.Time == deleteTx.Time {
				// Assert for the impossible, and delete ourselves off the end
				// This is impossible because if it was resolved in the other
				// way it should have been handled above.
				if res.resolution != resolveDiscardConflict {
					panic("impossible situation")
				}
				c = c[:last]
				return
			}
		}

		// Make sure we haven't noted this one already first
		for _, con := range conflicts {
			if con.Initial.Time == deleteTx.Time {
				return
			}
		}

		// Add it
		conflicts = append(conflicts, Conflict{
			Kind:     ConflictKindDeleteSet,
			Initial:  deleteTx,
			Conflict: c[last],
		})
	}

	i, j := 0, 0
	for {
		if i >= lena || j >= lenb {
			break
		}

		// If ids are the same, append and move on, haven't reached fork
		if a[i].Time == b[j].Time {
			if a[i].Kind == TxDelete {
				deleted[a[i].UUID] = i
			}

			c = append(c, a[i])
			i++
			j++
			continue
		}

		// We've forked.
		// If the fork happens and we have not moved either i or j
		// that means that there is no common ancestry and this is likely a
		// mistake to be syncing these. Create a conflict. This will always
		// be the first conflict.
		if i == 0 && j == 0 {
			// Check if it's been resolved
			if len(resolved) == 0 || resolved[0].resolution != resolveForce {
				conflicts = append(conflicts, Conflict{
					Kind:     ConflictKindRoot,
					Initial:  a[i],
					Conflict: b[j],
				})
			}
		}

		// Compare the txs
		if a[i].Time < b[j].Time {
			c = append(c, a[i])
			i++
		} else {
			c = append(c, b[j])
			j++
		}

		checkConflict()
	}

	// Append the rest of the events
	for ; i < lena; i++ {
		c = append(c, a[i])
		checkConflict()
	}
	for ; j < lenb; j++ {
		c = append(c, b[j])
		checkConflict()
	}

	if len(conflicts) != 0 {
		return nil, conflicts
	}

	return c, nil
}

// applyTx applies the src transactions to the destination snapshot
func applyTx(dst map[string]Entry, tx Tx) error {
	switch tx.Kind {
	case TxAdd:
		if _, ok := dst[tx.UUID]; ok {
			return fmt.Errorf("%s already exists in snapshot", tx.UUID)
		}
		dst[tx.UUID] = make(Entry)
	case TxDelete:
		_, ok := dst[tx.UUID]
		if !ok {
			return fmt.Errorf("%s was not in the snapshot", tx.UUID)
		}

		delete(dst, tx.UUID)
	case TxSetKey:
		entry, err := getEntry(dst, tx.UUID)
		if err != nil {
			return err
		}

		entry[tx.Key] = tx.Value
	case TxDeleteKey:
		entry, err := getEntry(dst, tx.UUID)
		if err != nil {
			return err
		}

		delete(entry, tx.Key)
	}

	return nil
}

func getEntry(obj map[string]Entry, uuid string) (Entry, error) {
	entry, ok := obj[uuid]
	if !ok {
		return nil, fmt.Errorf("%s was not in the snapshot", uuid)
	}

	return entry, nil
}
