package txformat

import (
	"errors"
	"math/rand"
	"reflect"
	"testing"
	"time"

	uuidpkg "github.com/gofrs/uuid"
)

func TestBasic(t *testing.T) {
	t.Parallel()

	store := new(Store)
	uuid, err := store.Add()
	must(t, err)

	store.Set(uuid, "test1", "value")
	store.Set(uuid, "test2", "value")
	store.Set(uuid, "test3", "value")

	// Overwrite
	store.Set(uuid, "test1", "notvalue")
	// Delete a key
	store.DeleteKey(uuid, "test2")

	// Update the snapshot
	must(t, store.UpdateSnapshot())

	entry, ok := store.Snapshot[uuid]
	if !ok {
		t.Fatal(uuid, "was never added to snapshot")
	}
	if got := entry["test1"]; got != "notvalue" {
		t.Error("test1 was wrong:", got)
	}
	if _, ok := entry["test2"]; ok {
		t.Error("test2 should be gone")
	}
	if got := entry["test3"]; got != "value" {
		t.Error("test3 was wrong:", got)
	}

	store.Delete(uuid)
	must(t, store.UpdateSnapshot())

	_, ok = store.Snapshot[uuid]
	if ok {
		t.Error("object should have been deleted")
	}
}

func TestHistory(t *testing.T) {
	t.Parallel()

	store := new(Store)
	uuid, err := store.Add()
	must(t, err)
	uuid2, err := store.Add()
	must(t, err)

	// Intermingle updates that have nothing to do with uuid
	store.Set(uuid, "test1", "value")
	store.Set(uuid2, "test1", "value")
	store.Set(uuid, "test2", "value")
	store.Set(uuid2, "test2", "value")
	store.Set(uuid, "test3", "notvalue")
	store.Set(uuid2, "test3", "notvalue")

	// This isn't necessary for the tests below, just trying to ensure that
	// it has no bearing on results below
	must(t, store.UpdateSnapshot())

	t.Run("Zero", func(t *testing.T) {
		t.Parallel()

		snap, err := store.SnapshotAt(0)
		must(t, err)

		if !reflect.DeepEqual(store.Snapshot, snap) {
			t.Errorf("snapshots were not equal:\nwant:\n%#v\ngot:\n%#v",
				store.Snapshot, snap)
		}
	})

	t.Run("One", func(t *testing.T) {
		t.Parallel()

		snap, err := store.SnapshotAt(1)
		must(t, err)

		entry1, ok := snap[uuid]
		if !ok {
			t.Fatal("object not created")
		}
		if entry1["test3"] != "notvalue" {
			t.Error("value wrong:", entry1["test3"])
		}

		entry2, ok := snap[uuid2]
		if !ok {
			t.Fatal("object not created")
		}
		_, ok = entry2["test3"]
		if ok {
			t.Error("should not exist")
		}
	})

	t.Run("All", func(t *testing.T) {
		t.Parallel()

		snap, err := store.SnapshotAt(8)
		must(t, err)
		if _, ok := snap[uuid]; ok {
			t.Fatal("object should not be created")
		}
	})

	t.Run("EntryOne", func(t *testing.T) {
		t.Parallel()

		entry, err := store.EntrySnapshotAt(uuid, 1)
		must(t, err)

		if entry["test2"] != "value" {
			t.Error("value wrong:", entry["test3"])
		}
		_, ok := entry["test3"]
		if ok {
			t.Error("should not exist")
		}
	})

	t.Run("EntryAll", func(t *testing.T) {
		t.Parallel()

		_, err := store.EntrySnapshotAt(uuid, 4)
		if !IsKeyNotFound(err) {
			t.Error("it should be a key not found error:", err)
		}
	})

	t.Run("EntryZero", func(t *testing.T) {
		t.Parallel()

		entry, err := store.EntrySnapshotAt(uuid, 0)
		must(t, err)

		if !reflect.DeepEqual(store.Snapshot[uuid], entry) {
			t.Errorf("snapshots were not equal:\nwant:\n%#v\ngot:\n%#v",
				store.Snapshot, entry)
		}
	})
}

func TestMarshal(t *testing.T) {
	t.Parallel()

	store := new(Store)
	uuid, err := store.Add()
	must(t, err)
	store.Set(uuid, "test1", "value")
	store.Set(uuid, "test2", "value")
	store.Set(uuid, "test1", "notvalue")
	store.DeleteKey(uuid, "test2")
	must(t, store.UpdateSnapshot())

	b, err := store.Save()
	must(t, err)

	t.Logf("%s\n", b)

	store, err = New(b)
	must(t, err)

	entry, ok := store.Snapshot[uuid]
	if !ok {
		t.Error("snapshot did not contain", uuid)
	}
	if got := entry["test1"]; got != "notvalue" {
		t.Error("test1 was wrong:", got)
	}
	if _, ok := entry["test2"]; ok {
		t.Error("test2 should be gone")
	}
}

func TestMerge(t *testing.T) {
	t.Parallel()

	t.Run("NoDiff", func(t *testing.T) {
		t.Parallel()

		logA := []Tx{
			{Time: 1, Kind: TxAdd, UUID: "1"},
			{Time: 2, Kind: TxAdd, UUID: "2"},
		}
		logB := []Tx{
			{Time: 1, Kind: TxAdd, UUID: "1"},
			{Time: 2, Kind: TxAdd, UUID: "2"},
		}

		merged, conflicts := Merge(logA, logB, nil)
		if len(conflicts) != 0 {
			t.Errorf("conflicts should be empty: %#v", conflicts)
		}
		if !reflect.DeepEqual(logA, merged) {
			t.Errorf("merged differs: %#v", merged)
		}
	})

	t.Run("AppendFork", func(t *testing.T) {
		t.Parallel()

		logA := []Tx{
			{Time: 1, Kind: TxAdd, UUID: "1"},
			{Time: 2, Kind: TxAdd, UUID: "2"},
			{Time: 3, Kind: TxAdd, UUID: "3"},
		}
		logB := []Tx{
			{Time: 1, Kind: TxAdd, UUID: "1"},
			{Time: 2, Kind: TxAdd, UUID: "2"},
		}

		merged, conflicts := Merge(logA, logB, nil)
		if len(conflicts) != 0 {
			t.Errorf("conflicts should be empty: %#v", conflicts)
		}
		if !reflect.DeepEqual(logA, merged) {
			t.Errorf("merged differs: %#v", merged)
		}
	})

	t.Run("CompareFork", func(t *testing.T) {
		t.Parallel()

		logA := []Tx{
			{Time: 1, Kind: TxAdd, UUID: "1"},
			{Time: 2, Kind: TxAdd, UUID: "2"},
			{Time: 3, Kind: TxAdd, UUID: "3"},
			{Time: 5, Kind: TxAdd, UUID: "5"},
		}
		logB := []Tx{
			{Time: 1, Kind: TxAdd, UUID: "1"},
			{Time: 2, Kind: TxAdd, UUID: "2"},
			{Time: 4, Kind: TxAdd, UUID: "4"},
			{Time: 6, Kind: TxAdd, UUID: "6"},
		}
		logC := []Tx{
			{Time: 1, Kind: TxAdd, UUID: "1"},
			{Time: 2, Kind: TxAdd, UUID: "2"},
			{Time: 3, Kind: TxAdd, UUID: "3"},
			{Time: 4, Kind: TxAdd, UUID: "4"},
			{Time: 5, Kind: TxAdd, UUID: "5"},
			{Time: 6, Kind: TxAdd, UUID: "6"},
		}

		merged, conflicts := Merge(logA, logB, nil)
		if len(conflicts) != 0 {
			t.Errorf("conflicts should be empty: %#v", conflicts)
		}
		if !reflect.DeepEqual(logC, merged) {
			t.Errorf("merged differs: %#v", merged)
		}
	})

	t.Run("ConflictsBasic", func(t *testing.T) {
		t.Parallel()

		logA := []Tx{
			{Time: 1, Kind: TxAdd, UUID: "1"},
			{Time: 3, Kind: TxSetKey, UUID: "1", Key: "a", Value: "b"},
		}
		logB := []Tx{
			{Time: 2, Kind: TxDelete, UUID: "1"},
		}
		logDelete := []Tx{
			{Time: 1, Kind: TxAdd, UUID: "1"},
			{Time: 2, Kind: TxDelete, UUID: "1"},
		}

		merged, conflicts := Merge(logA, logB, nil)
		if len(merged) != 0 {
			t.Error("merged should not be returned")
		}

		if len(conflicts) != 1 {
			t.Error("there was", len(conflicts), "conflicts")
		}

		c := conflicts[0]
		if c.DeleteTx.Time != logB[0].Time {
			t.Error("delete tx wrong")
		}
		if c.SetTx.Time != logA[1].Time {
			t.Error("set tx wrong")
		}

		// This prevents overwriting
		restore := make([]Conflict, len(conflicts))
		deletem := make([]Conflict, len(conflicts))
		copy(restore, conflicts)
		copy(deletem, conflicts)

		restore[0].Restore()
		merged, conflicts = Merge(logA, logB, restore)
		if len(conflicts) != 0 {
			t.Errorf("conflicts should be empty: %#v", conflicts)
		}
		if !reflect.DeepEqual(logA, merged) {
			t.Errorf("merged differs: %#v", merged)
		}

		deletem[0].Delete()
		merged, conflicts = Merge(logA, logB, deletem)
		if len(conflicts) != 0 {
			t.Errorf("conflicts should be empty: %#v", conflicts)
		}
		if !reflect.DeepEqual(logDelete, merged) {
			t.Errorf("merged differs: %#v", merged)
		}
	})

	t.Run("ConflictsMulti", func(t *testing.T) {
		t.Parallel()

		logA := []Tx{
			{Time: 1, Kind: TxAdd, UUID: "1"},
			{Time: 2, Kind: TxAdd, UUID: "2"},

			// Do two sets to see if we get a conflict for each set
			{Time: 5, Kind: TxSetKey, UUID: "1", Key: "a", Value: "b"},
			{Time: 6, Kind: TxSetKey, UUID: "1", Key: "a", Value: "b"},

			{Time: 6, Kind: TxSetKey, UUID: "2", Key: "a", Value: "b"},
			{Time: 7, Kind: TxSetKey, UUID: "2", Key: "a", Value: "b"},
		}
		logB := []Tx{
			{Time: 3, Kind: TxDelete, UUID: "1"},
			{Time: 4, Kind: TxDelete, UUID: "2"},
		}
		logDelete := []Tx{
			{Time: 1, Kind: TxAdd, UUID: "1"},
			{Time: 2, Kind: TxAdd, UUID: "2"},
			{Time: 3, Kind: TxDelete, UUID: "1"},
			{Time: 4, Kind: TxDelete, UUID: "2"},
		}

		merged, conflicts := Merge(logA, logB, nil)
		if len(merged) != 0 {
			t.Error("merged should not be returned")
		}
		if len(conflicts) != 2 {
			t.Error("there was", len(conflicts), "conflicts")
		}
		if conflicts[0].DeleteTx.Time != 3 {
			t.Error("delete id was wrong")
		}
		if conflicts[0].SetTx.Time != logA[2].Time {
			t.Error("set tx was wrong")
		}
		if conflicts[1].DeleteTx.Time != 4 {
			t.Error("delete id was wrong")
		}
		if conflicts[1].SetTx.Time != logA[4].Time {
			t.Error("set tx was wrong")
		}

		// This prevents overwriting
		restore := make([]Conflict, len(conflicts))
		deletem := make([]Conflict, len(conflicts))
		copy(restore, conflicts)
		copy(deletem, conflicts)

		for i := range restore {
			restore[i].Restore()
		}
		merged, conflicts = Merge(logA, logB, restore)
		if len(conflicts) != 0 {
			t.Errorf("conflicts should be empty: %#v", conflicts)
		}
		if !reflect.DeepEqual(logA, merged) {
			t.Errorf("merged differs: %#v", merged)
		}

		for i := range restore {
			deletem[i].Delete()
		}
		merged, conflicts = Merge(logA, logB, deletem)
		if len(conflicts) != 0 {
			t.Errorf("conflicts should be empty: %#v", conflicts)
		}
		if !reflect.DeepEqual(logDelete, merged) {
			t.Errorf("merged differs: %#v", merged)
		}
	})
}

func TestTransactions(t *testing.T) {
	t.Parallel()

	store := new(Store)
	store.Begin()

	uuid, err := store.Add()
	must(t, err)
	store.Set(uuid, "test1", "value")
	store.Set(uuid, "test2", "value")

	if len(store.Log) != 3 {
		t.Error("should have 3 txs")
	}

	store.Rollback()
	if len(store.Log) != 0 {
		t.Error("should have 0 txs")
	}

	store.Begin()
	uuid, err = store.Add()
	must(t, err)
	store.Set(uuid, "test1", "value")
	store.Set(uuid, "test2", "value")

	if len(store.Log) != 3 {
		t.Error("should have 3 txs")
	}

	store.Commit()
	if len(store.Log) != 3 {
		t.Error("should have 3 txs")
	}
	if store.txPoint != 0 {
		t.Error("transaction should be ended")
	}
}

func TestTransactionsDo(t *testing.T) {
	t.Parallel()

	store := new(Store)

	err := store.Do(func() error {
		uuid, err := store.Add()
		must(t, err)
		store.Set(uuid, "test1", "value")
		store.Set(uuid, "test2", "value")

		must(t, store.UpdateSnapshot())
		if store.Snapshot == nil {
			t.Error("snap shot should be updated")
		}

		return errors.New("fail")
	})
	if err == nil {
		t.Error("should have gotten an error")
	}

	if store.Snapshot != nil {
		t.Error("snapshot should have been cleared")
	}
	if len(store.Log) != 0 {
		t.Error("should have 0 txs")
	}

	err = store.Do(func() error {
		uuid, err := store.Add()
		must(t, err)
		store.Set(uuid, "test1", "value")
		store.Set(uuid, "test2", "value")

		return nil
	})
	if err != nil {
		t.Error("should have gotten an error")
	}
	if len(store.Log) != 3 {
		t.Error("should have 3 txs")
	}
}

func TestRollbackN(t *testing.T) {
	t.Parallel()

	store := new(Store)
	uuid, err := store.Add()
	must(t, err)
	store.Set(uuid, "test1", "value")
	store.Set(uuid, "test2", "value")

	must(t, store.UpdateSnapshot())

	store.Set(uuid, "test1", "notvalue")

	if err := store.RollbackN(5); err == nil {
		t.Error("expected an error stopping us from rolling back past beginning")
	}

	must(t, store.RollbackN(1))
	if len(store.Log) != 3 {
		t.Error("log should have been truncated by 1 event")
	}
	if store.Snapshot == nil {
		t.Error("it should not have invalidated snapshot")
	}

	must(t, store.RollbackN(1))
	if len(store.Log) != 2 {
		t.Error("log should have been truncated by 1 event")
	}
	if store.Snapshot != nil {
		t.Error("it should have invalidated snapshot")
	}

	must(t, store.UpdateSnapshot())
	if got := store.Snapshot[uuid]["test1"]; got != "value" {
		t.Error("the rollback didn't rollback the set, got:", got)
	}
	_, ok := store.Snapshot[uuid]["test2"]
	if ok {
		t.Error("this key should not be in the snapshot")
	}
}

func TestNVersions(t *testing.T) {
	t.Parallel()

	store := new(Store)

	if store.NVersions("") != 0 {
		t.Error("it should have no versions")
	}

	uuid, err := store.Add()
	must(t, err)

	if store.NVersions(uuid) != 1 {
		t.Error("it should have 1 version")
	}

	_, err = store.Add()
	must(t, err)

	if store.NVersions(uuid) != 1 {
		t.Error("it should have 1 version")
	}

	store.Set(uuid, "test1", "value")

	if store.NVersions(uuid) != 2 {
		t.Error("it should have 1 version")
	}
}

func TestLastUpdated(t *testing.T) {
	t.Parallel()

	store := new(Store)

	if store.LastUpdated("") != -1 {
		t.Error("it should not have been found")
	}

	uuid, err := store.Add()
	must(t, err)

	if store.LastUpdated(uuid) > time.Now().UnixNano() {
		t.Error("it should have been updated at least now ns ago")
	}
}

func randomStore() *Store {
	s := new(Store)

	items := make([]string, 20)
	for i := range items {
		uuid, err := s.Add()
		if err != nil {
			panic(err)
		}
		items[i] = uuid
	}

	keys := make([]string, 30)
	for i := range keys {
		uuid := uuidpkg.Must(uuidpkg.NewV4())
		keys[i] = uuid.String()
	}

	addedKeys := make(map[string][]string)

	for i := 0; i < 50000; i++ {
	Switch:
		switch rand.Intn(10) {
		default:
			item := items[rand.Intn(len(items))]
			key := keys[rand.Intn(len(keys))]
			value := uuidpkg.Must(uuidpkg.NewV4()).String()

			s.Set(item, key, value)

			akeys, ok := addedKeys[item]
			if !ok {
				addedKeys[item] = []string{key}
				continue
			}

			for _, a := range akeys {
				if a == key {
					break Switch
				}
			}

			addedKeys[item] = append(akeys, key)
		case 9:
			item := items[rand.Intn(len(items))]

			akeys := addedKeys[item]
			if len(akeys) == 0 {
				continue
			}
			index := rand.Intn(len(akeys))
			akey := akeys[index]
			akeys[index], akeys[len(akeys)-1] = akeys[len(akeys)-1], akeys[index]
			addedKeys[item] = akeys[:len(akeys)-1]
			s.DeleteKey(item, akey)
		}
	}

	return s
}

func BenchmarkLong(b *testing.B) {
	s := randomStore()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := s.UpdateSnapshot(); err != nil {
			panic(err)
		}
		s.ResetSnapshot()
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
