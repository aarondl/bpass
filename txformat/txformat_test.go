package txformat

import (
	"reflect"
	"testing"
)

func TestBasic(t *testing.T) {
	t.Parallel()

	store := new(Store)
	uuid, err := store.Add()
	must(t, err)

	must(t, store.Set(uuid, "test1", "value"))
	must(t, store.Set(uuid, "test2", "value"))
	must(t, store.Set(uuid, "test3", "value"))
	list1value1, err := store.Append(uuid, "list1", "value1")
	must(t, err)
	_, err = store.Append(uuid, "list1", "value2")
	must(t, err)

	// Overwrite
	must(t, store.Set(uuid, "test1", "notvalue"))
	// Delete a key
	must(t, store.DeleteKey(uuid, "test2"))
	// Delete from a list
	must(t, store.DeleteList(uuid, "list1", list1value1))

	// Update the snapshot
	must(t, store.UpdateSnapshot())

	entry, ok := store.Snapshot[uuid]
	if !ok {
		t.Fatal(uuid, "was never added to snapshot")
	}
	if got := entry["test1"].(string); got != "notvalue" {
		t.Error("test1 was wrong:", got)
	}
	if _, ok := entry["test2"]; ok {
		t.Error("test2 should be gone")
	}
	if got := entry["test3"].(string); got != "value" {
		t.Error("test3 was wrong:", got)
	}

	must(t, store.Delete(uuid))
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
	must(t, store.Set(uuid, "test1", "value"))
	must(t, store.Set(uuid2, "test1", "value"))
	must(t, store.Set(uuid, "test2", "value"))
	must(t, store.Set(uuid2, "test2", "value"))
	must(t, store.Set(uuid, "test3", "value"))
	must(t, store.Set(uuid2, "test3", "value"))
	_, err = store.Append(uuid, "list1", "value1")
	must(t, err)
	_, err = store.Append(uuid, "list1", "value2")
	must(t, err)

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

		entry, ok := snap[uuid]
		if !ok {
			t.Fatal("object not created")
		}
		entries, err := entry.List("list1")
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Error("entries should only be 1 length:", len(entries))
		}
		if entries[0].Value != "value1" {
			t.Error("entry wrong:", entries[0].Value)
		}
	})

	t.Run("All", func(t *testing.T) {
		t.Parallel()

		snap, err := store.SnapshotAt(10)
		must(t, err)
		if _, ok := snap[uuid]; ok {
			t.Fatal("object should not be created")
		}
	})

	t.Run("EntryOne", func(t *testing.T) {
		t.Parallel()

		entry, err := store.EntrySnapshotAt(uuid, 1)
		must(t, err)
		entries, err := entry.List("list1")
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Error("entries should only be 1 length:", len(entries))
		}
		if entries[0].Value != "value1" {
			t.Error("entry wrong:", entries[0].Value)
		}
	})

	t.Run("EntryAll", func(t *testing.T) {
		t.Parallel()

		_, err := store.EntrySnapshotAt(uuid, 6)
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
	must(t, store.Set(uuid, "test1", "value"))
	must(t, store.Set(uuid, "test2", "value"))
	must(t, store.Set(uuid, "test1", "notvalue"))
	must(t, store.DeleteKey(uuid, "test2"))
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
	if got := entry["test1"].(string); got != "notvalue" {
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
			{ID: "1", Time: 1, Kind: TxAdd, UUID: "1"},
			{ID: "2", Time: 2, Kind: TxAdd, UUID: "2"},
		}
		logB := []Tx{
			{ID: "1", Time: 1, Kind: TxAdd, UUID: "1"},
			{ID: "2", Time: 2, Kind: TxAdd, UUID: "2"},
		}

		merged, conflicts := merge(logA, logB, nil)
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
			{ID: "1", Time: 1, Kind: TxAdd, UUID: "1"},
			{ID: "2", Time: 2, Kind: TxAdd, UUID: "2"},
			{ID: "3", Time: 3, Kind: TxAdd, UUID: "3"},
		}
		logB := []Tx{
			{ID: "1", Time: 1, Kind: TxAdd, UUID: "1"},
			{ID: "2", Time: 2, Kind: TxAdd, UUID: "2"},
		}

		merged, conflicts := merge(logA, logB, nil)
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
			{ID: "1", Time: 1, Kind: TxAdd, UUID: "1"},
			{ID: "2", Time: 2, Kind: TxAdd, UUID: "2"},
			{ID: "3", Time: 3, Kind: TxAdd, UUID: "3"},
			{ID: "5", Time: 5, Kind: TxAdd, UUID: "5"},
		}
		logB := []Tx{
			{ID: "1", Time: 1, Kind: TxAdd, UUID: "1"},
			{ID: "2", Time: 2, Kind: TxAdd, UUID: "2"},
			{ID: "4", Time: 4, Kind: TxAdd, UUID: "4"},
			{ID: "6", Time: 5 /* intentional */, Kind: TxAdd, UUID: "6"},
		}
		logC := []Tx{
			{ID: "1", Time: 1, Kind: TxAdd, UUID: "1"},
			{ID: "2", Time: 2, Kind: TxAdd, UUID: "2"},
			{ID: "3", Time: 3, Kind: TxAdd, UUID: "3"},
			{ID: "4", Time: 4, Kind: TxAdd, UUID: "4"},
			{ID: "5", Time: 5, Kind: TxAdd, UUID: "5"},
			{ID: "6", Time: 5 /* intentional */, Kind: TxAdd, UUID: "6"},
		}

		merged, conflicts := merge(logA, logB, nil)
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
			{ID: "1", Time: 1, Kind: TxAdd, UUID: "1"},
			{ID: "3", Time: 3, Kind: TxSet, UUID: "1", Key: "a", Value: "b"},
		}
		logB := []Tx{
			{ID: "2", Time: 2, Kind: TxDelete, UUID: "1"},
		}
		logDelete := []Tx{
			{ID: "1", Time: 1, Kind: TxAdd, UUID: "1"},
			{ID: "2", Time: 2, Kind: TxDelete, UUID: "1"},
		}

		merged, conflicts := merge(logA, logB, nil)
		if len(merged) != 0 {
			t.Error("merged should not be returned")
		}

		if len(conflicts) != 1 {
			t.Error("there was", len(conflicts), "conflicts")
		}

		c := conflicts[0]
		if c.DeleteTx.ID != logB[0].ID {
			t.Error("delete tx wrong")
		}
		if c.SetTx.ID != logA[1].ID {
			t.Error("set tx wrong")
		}

		// This prevents overwriting
		restore := make([]Conflict, len(conflicts))
		deletem := make([]Conflict, len(conflicts))
		copy(restore, conflicts)
		copy(deletem, conflicts)

		restore[0].Restore()
		merged, conflicts = merge(logA, logB, restore)
		if len(conflicts) != 0 {
			t.Errorf("conflicts should be empty: %#v", conflicts)
		}
		if !reflect.DeepEqual(logA, merged) {
			t.Errorf("merged differs: %#v", merged)
		}

		deletem[0].Delete()
		merged, conflicts = merge(logA, logB, deletem)
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
			{ID: "1", Time: 1, Kind: TxAdd, UUID: "1"},
			{ID: "2", Time: 2, Kind: TxAdd, UUID: "2"},

			// Do two sets to see if we get a conflict for each set
			{ID: "5", Time: 5, Kind: TxSet, UUID: "1", Key: "a", Value: "b"},
			{ID: "6", Time: 6, Kind: TxSet, UUID: "1", Key: "a", Value: "b"},

			{ID: "7", Time: 6, Kind: TxSet, UUID: "2", Key: "a", Value: "b"},
			{ID: "8", Time: 7, Kind: TxSet, UUID: "2", Key: "a", Value: "b"},
		}
		logB := []Tx{
			{ID: "3", Time: 3, Kind: TxDelete, UUID: "1"},
			{ID: "4", Time: 4, Kind: TxDelete, UUID: "2"},
		}
		logDelete := []Tx{
			{ID: "1", Time: 1, Kind: TxAdd, UUID: "1"},
			{ID: "2", Time: 2, Kind: TxAdd, UUID: "2"},
			{ID: "3", Time: 3, Kind: TxDelete, UUID: "1"},
			{ID: "4", Time: 4, Kind: TxDelete, UUID: "2"},
		}

		merged, conflicts := merge(logA, logB, nil)
		if len(merged) != 0 {
			t.Error("merged should not be returned")
		}
		if len(conflicts) != 2 {
			t.Error("there was", len(conflicts), "conflicts")
		}
		if conflicts[0].DeleteTx.ID != "3" {
			t.Error("delete id was wrong")
		}
		if conflicts[0].SetTx.ID != logA[2].ID {
			t.Error("set tx was wrong")
		}
		if conflicts[1].DeleteTx.ID != "4" {
			t.Error("delete id was wrong")
		}
		if conflicts[1].SetTx.ID != logA[4].ID {
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
		merged, conflicts = merge(logA, logB, restore)
		if len(conflicts) != 0 {
			t.Errorf("conflicts should be empty: %#v", conflicts)
		}
		if !reflect.DeepEqual(logA, merged) {
			t.Errorf("merged differs: %#v", merged)
		}

		for i := range restore {
			deletem[i].Delete()
		}
		merged, conflicts = merge(logA, logB, deletem)
		if len(conflicts) != 0 {
			t.Errorf("conflicts should be empty: %#v", conflicts)
		}
		if !reflect.DeepEqual(logDelete, merged) {
			t.Errorf("merged differs: %#v", merged)
		}
	})
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
