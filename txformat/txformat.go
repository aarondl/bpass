// Package txformat works on a json-encoded blob. For an example on the on-disk
// data structure see the Store documentation.
package txformat

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	uuidpkg "github.com/gofrs/uuid"
)

// Store contains a transaction log, and a snapshot at a particular version.
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
//       { "id": "4c4...", "time": 1571887976, "kind": "add", "uuid": "d6f..." },
//       { "id": "a7c...", "time": 1571887977, "kind": "set", "uuid": "d6f...", "key": "test1", "value": "value" },
//       { "id": "5f0...", "time": 1571887978, "kind": "set", "uuid": "d6f...", "key": "test2", "value": "value" },
//       { "id": "b7b...", "time": 1571887979, "kind": "set", "uuid": "d6f...", "key": "test1", "value": "notvalue" },
//       { "id": "035...", "time": 1571887979, "kind": "delkey", "uuid": "d6f...", "key": "test2" }
//     ]
//   }
type Store struct {
	// Version of the snapshot
	Version uint `msgpack:"version,omitempty" json:"version,omitempty"`
	// Snapshot of the data at a specific version
	Snapshot map[string]Entry `msgpack:"snapshot,omitempty" json:"snapshot,omitempty"`
	// Log of all transactions.
	Log []Tx `msgpack:"log,omitempty" json:"log,omitempty"`

	txPoint int
}

type storeNoSnapshot struct {
	Log []Tx `msgpack:"log,omitempty" json:"log,omitempty"`
}

// New takes a json blob and unmarshals it into a Store
func New(data []byte) (*Store, error) {
	s := new(Store)
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
func (s *Store) Save() ([]byte, error) {
	if s.txPoint != 0 {
		return nil, errors.New("refusing to save while transaction active")
	}

	return json.Marshal(s)
}

// Add a new entry
func (s *Store) Add() (uuid string, err error) {
	idObj, err := uuidpkg.NewV4()
	if err != nil {
		return "", err
	}

	uuidObj, err := uuidpkg.NewV4()
	if err != nil {
		return "", err
	}

	// Does not use appendLog so ID/Time must be filled out by hand
	s.Log = append(s.Log,
		Tx{
			ID:   idObj.String(),
			Time: time.Now().UnixNano(),
			Kind: TxAdd,
			UUID: uuidObj.String(),
		},
	)

	return uuidObj.String(), nil
}

// Set k=v for a uuid
func (s *Store) Set(uuid, key, value string) error {
	return s.appendLog(
		Tx{
			Kind:  TxSet,
			UUID:  uuid,
			Key:   key,
			Value: value,
		},
	)
}

// Append to a list key
func (s *Store) Append(uuid, key, value string) (index string, err error) {
	indexObj, err := uuidpkg.NewV4()
	if err != nil {
		return "", err
	}

	return indexObj.String(), s.appendLog(
		Tx{
			Kind:  TxAddList,
			UUID:  uuid,
			Key:   key,
			Index: indexObj.String(),
			Value: value,
		},
	)
}

// Delete an entry
func (s *Store) Delete(uuid string) error {
	return s.appendLog(
		Tx{
			Kind: TxDelete,
			UUID: uuid,
		},
	)
}

// DeleteKey deletes a key from an entry
func (s *Store) DeleteKey(uuid, key string) error {
	return s.appendLog(
		Tx{
			Kind: TxDeleteKey,
			UUID: uuid,
			Key:  key,
		},
	)
}

// DeleteList deletes a list item
func (s *Store) DeleteList(uuid, key, listUUID string) error {
	return s.appendLog(
		Tx{
			Kind:  TxDeleteList,
			UUID:  uuid,
			Key:   key,
			Index: listUUID,
		},
	)
}

// appendLog creates a new UUID for tx.ID and appends the log
func (s *Store) appendLog(tx Tx) error {
	uuidObj, err := uuidpkg.NewV4()
	if err != nil {
		return err
	}
	tx.ID = uuidObj.String()
	tx.Time = time.Now().UnixNano()
	s.Log = append(s.Log, tx)
	return nil
}

// Begin a transaction, will panic if commit/rollback have not been issued
// after a previous Begin.
//
// We add 1 to the length to keep the 0 valid as a "no transaction started"
// sentinel value.
func (s *Store) Begin() {
	s.txPoint = len(s.Log) + 1
}

// Commit the transactions to the log
func (s *Store) Commit() {
	if s.txPoint == 0 {
		panic("commit called before begin")
	}
	s.txPoint = 0
}

// Rollback to the last begin point, invalidates the snapshot if necessary
func (s *Store) Rollback() {
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
func (s *Store) Do(fn func() error) error {
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
func (s *Store) RollbackN(n uint) error {
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
func (s *Store) ResetSnapshot() {
	s.Version = 0
	s.Snapshot = nil
}

// UpdateSnapshot applies all outstanding transactions in the log to the
// snapshot.
func (s *Store) UpdateSnapshot() error {
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
func (s *Store) SnapshotAt(versionsAgo int) (map[string]Entry, error) {
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
func (s *Store) EntrySnapshotAt(uuid string, versionsAgo int) (Entry, error) {
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
func (s *Store) NVersions(uuid string) (versions int) {
	for _, l := range s.Log {
		if l.UUID == uuid {
			versions++
		}
	}

	return versions
}

// LastUpdated returns the unix nanosecond timestamp for when the entry was
// updated last. Will be -1 if the entry is not found.
func (s *Store) LastUpdated(uuid string) (last int64) {
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
		if r.resolution == conflictNone {
			return nil, resolved
		}
	}

	lena := len(a)
	lenb := len(b)

	if lena == lenb &&
		a[0].ID == b[0].ID && a[lena-1].ID == b[lenb-1].ID {
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
				if res.DeleteTx.ID != c[last].ID {
					continue
				}

				// We are part of this resolution
				if res.resolution == conflictRestore {
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
			if res.DeleteTx.ID == deleteTx.ID {
				// Assert for the impossible, and delete ourselves off the end
				if res.resolution != conflictDelete {
					panic("impossible situation")
				}
				c = c[:last]
				return
			}
		}

		// Make sure we haven't noted this one already first
		for _, con := range conflicts {
			if con.DeleteTx.ID == deleteTx.ID {
				return
			}
		}

		// Add it
		conflicts = append(conflicts, Conflict{
			DeleteTx: deleteTx,
			SetTx:    c[last],
		})
	}

	i, j := 0, 0
	for {
		if i >= lena || j >= lenb {
			break
		}

		// If ids are the same, append and move on, haven't reached fork
		if a[i].ID == b[j].ID {
			if a[i].Kind == TxDelete {
				deleted[a[i].UUID] = i
			}

			c = append(c, a[i])
			i++
			j++
			continue
		}

		// Compare the txs
		if a[i].Time < b[j].Time || (a[i].Time == b[j].Time && a[i].UUID < b[j].UUID) {
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
		dst[tx.UUID] = make(map[string]interface{})
	case TxSet:
		entry, err := getEntry(dst, tx.UUID)
		if err != nil {
			return err
		}

		entry[tx.Key] = tx.Value
	case TxAddList:
		entry, err := getEntry(dst, tx.UUID)
		if err != nil {
			return err
		}

		list, err := entry.List(tx.Key)
		if err != nil {
			if !IsKeyNotFound(err) {
				return err
			}
			list = make([]ListEntry, 0, 1)
		}

		list = append(list, ListEntry{UUID: tx.Index, Value: tx.Value})
		entry.SetList(tx.Key, list)
	case TxDelete:
		_, ok := dst[tx.UUID]
		if !ok {
			return fmt.Errorf("%s was not in the snapshot", tx.UUID)
		}

		delete(dst, tx.UUID)
	case TxDeleteKey:
		entry, err := getEntry(dst, tx.UUID)
		if err != nil {
			return err
		}

		delete(entry, tx.Key)
	case TxDeleteList:
		entry, err := getEntry(dst, tx.UUID)
		if err != nil {
			return err
		}

		list, err := entry.List(tx.Key)
		if err != nil {
			if k, ok := err.(KeyNotFound); ok {
				k.UUID = tx.UUID
				return k
			}
			return err
		}

		found := false
		for i, e := range list {
			if e.UUID == tx.Index {
				// Delete in a stable manner to preserve ordering
				// of things
				found = true
				for j := i; j < len(list)-1; j++ {
					list[j] = list[j+1]
				}
				list = list[:len(list)-1]
				break
			}
		}

		if !found {
			return KeyNotFound{UUID: tx.UUID, Key: tx.Key, Index: tx.Index}
		}

		entry.SetList(tx.Key, list)
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
