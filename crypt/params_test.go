package crypt

import (
	"bytes"
	"strings"
	"testing"
)

var (
	testKey  = []byte{0}
	testSalt = []byte{1}
)

func TestParamsSetSingleUser(t *testing.T) {
	t.Parallel()

	var p Params
	p.SetSingleUser(testKey, testSalt)

	if p.NUsers != 0 {
		t.Error("nusers wrong")
	}

	if len(p.Keys) != 1 {
		t.Error("keys was wrong length")
	}
	if len(p.Salts) != 1 {
		t.Error("salts was wrong length")
	}
	if p.Keys[0][0] != 0 {
		t.Error("key was wrong")
	}
	if p.Salts[0][0] != 1 {
		t.Error("salt was wrong")
	}
}

func TestParamsAddUser(t *testing.T) {
	t.Parallel()

	var p Params
	p.SetSingleUser(testKey, testSalt)
	// This just converts it to a multi-file, still should be 1 user
	testMust(p.AddUser("user", testKey, testSalt))

	checkParamLengths(t, p, 1)
	testMust(p.AddUser("user2", testKey, testSalt))
	checkParamLengths(t, p, 2)
}

func TestParamsRemoveUser(t *testing.T) {
	t.Parallel()

	var p Params
	testMust(p.AddUser("user1", testKey, testSalt))
	testMust(p.AddUser("user2", testKey, testSalt))

	checkParamLengths(t, p, 2)
	testMust(p.RemoveUser("user2"))
	checkParamLengths(t, p, 1)
	testMust(p.RemoveUser("user1"))
	if len(p.Keys) != 1 {
		t.Error("keys was wrong length")
	}
	if len(p.Salts) != 1 {
		t.Error("salts was wrong length")
	}
	if len(p.Users) != 0 {
		t.Error("users was wrong length")
	}
	if len(p.IVs) != 0 {
		t.Error("ivs was wrong length")
	}
	if len(p.MKeys) != 0 {
		t.Error("mkeys was wrong length")
	}
}

func TestParamsRekey(t *testing.T) {
	t.Parallel()

	var p Params
	testMust(p.AddUser("user1", testKey, testSalt))
	testMust(p.AddUser("user2", testKey, testSalt))

	p.IVs = [][]byte{testKey, testKey}
	p.MKeys = [][]byte{testKey, testKey}

	// Should rekey 0 index atm
	p.Rekey([]byte{2}, []byte{3})
	if err := p.RekeyUser("user2", []byte{4}, []byte{5}); err != nil {
		t.Fatal(err)
	}

	if p.IVs[0] != nil {
		t.Error("did not reset ivs[0]")
	}
	if p.IVs[1] != nil {
		t.Error("did not reset ivs[1]")
	}
	if p.MKeys[0] != nil {
		t.Error("did not reset mkeys[0]")
	}
	if p.MKeys[1] != nil {
		t.Error("did not reset mkeys[1]")
	}

	if p.Keys[0][0] != 2 {
		t.Error("user1 key was wrong")
	}
	if p.Salts[0][0] != 3 {
		t.Error("user1 salt was wrong")
	}
	if p.Keys[1][0] != 4 {
		t.Error("user2 key was wrong")
	}
	if p.Salts[1][0] != 5 {
		t.Error("user2 salt was wrong")
	}
}

func TestParamsRekeyAllSingle(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping long test")
	}

	var p Params
	p.SetSingleUser(testKey, testSalt)
	pwds, err := p.RekeyAll(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(pwds) != 1 {
		t.Error("not enough passwords:", pwds)
	}
	if bytes.Equal(p.Keys[0], testKey) {
		t.Error("key was not regenerated")
	}
	if bytes.Equal(p.Salts[0], testSalt) {
		t.Error("salt was not regenerated")
	}
}

func TestParamsRekeyAllMulti(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping long test")
	}

	var p Params
	testMust(p.AddUser("user1", testKey, testSalt))
	testMust(p.AddUser("user2", testKey, testSalt))

	p.IVM = []byte("ultranonce")
	p.Master = []byte("supersecret")

	pwds, err := p.RekeyAll(1)
	if err != nil {
		t.Fatal(err)
	}

	if len(pwds) != 2 {
		t.Error("not enough passwords:", pwds)
	}
	t.Log(pwds)

	for _, pwd := range pwds {
		for _, c := range pwd {
			if !strings.ContainsRune(alphabet, c) {
				t.Error("password was not made with alphabet:", pwd)
			}
		}
	}

	if bytes.Equal(p.Keys[0], testKey) {
		t.Error("key was not regenerated")
	}
	if bytes.Equal(p.Keys[1], testKey) {
		t.Error("key was not regenerated")
	}
	if bytes.Equal(p.Salts[0], testSalt) {
		t.Error("salt was not regenerated")
	}
	if bytes.Equal(p.Salts[1], testSalt) {
		t.Error("salt was not regenerated")
	}

	if p.IVs[0] != nil {
		t.Error("did not reset ivs[0]")
	}
	if p.IVs[1] != nil {
		t.Error("did not reset ivs[1]")
	}
	if p.MKeys[0] != nil {
		t.Error("did not reset mkeys[0]")
	}
	if p.MKeys[1] != nil {
		t.Error("did not reset mkeys[1]")
	}

	if p.IVM != nil {
		t.Error("did not clear IVM")
	}
	if p.Master != nil {
		t.Error("did not clear master key")
	}
}

func TestParamsDiff(t *testing.T) {
	t.Parallel()

	t.Run("SingleNone", func(t *testing.T) {
		t.Parallel()

		var p, other Params
		p.SetSingleUser(testKey, testSalt)
		other.SetSingleUser(testKey, testSalt)

		if p.Diff(other) != nil {
			t.Error("should be no differences")
		}
	})
	t.Run("SingleRekeySelf", func(t *testing.T) {
		t.Parallel()

		var p, other Params
		p.SetSingleUser(testKey, testSalt)
		other.SetSingleUser(testKey, []byte{10})

		diffs := p.Diff(other)
		if len(diffs) != 1 {
			t.Error("should be 1 diff")
		}
		if diffs[0].Kind != ParamDiffRekeySelf {
			t.Error("should have been a self rekey")
		}
	})
	t.Run("MultiToSingle", func(t *testing.T) {
		t.Parallel()

		var p, other Params
		testMust(p.AddUser("user", testKey, testSalt))
		other.SetSingleUser(testKey, testSalt)

		diffs := p.Diff(other)
		if len(diffs) != 1 {
			t.Error("should be 1 diff")
		}
		if diffs[0].Kind != ParamDiffSingleFile {
			t.Error("diff 0 should have been a self rekey")
		}
	})
	t.Run("SingleToMulti", func(t *testing.T) {
		t.Parallel()

		var p, other Params
		p.SetSingleUser(testKey, testSalt)
		testMust(other.AddUser("user", testKey, testSalt))

		diffs := p.Diff(other)
		if len(diffs) != 2 {
			t.Error("should be 2 diffs, got:", len(diffs))
		}
		if diffs[0].Kind != ParamDiffMultiFile {
			t.Error("diff 0 should have been a multi file change")
		}
		if diffs[1].Kind != ParamDiffAddUser {
			t.Error("diff 1 should have been an add user")
		}
		if !bytes.Equal(diffs[1].SHA, other.Users[0]) {
			t.Error("diff 1 should have pointed to the correct user")
		}
	})
	t.Run("AddsRemoves", func(t *testing.T) {
		t.Parallel()

		var p, other Params
		testMust(p.AddUser("user1", testKey, testSalt))
		testMust(p.AddUser("user2", testKey, testSalt))
		testMust(other.AddUser("user1", testKey, testSalt))
		testMust(other.AddUser("user3", testKey, testSalt))

		diffs := p.Diff(other)
		if len(diffs) != 2 {
			t.Error("should be 4 diffs, got:", len(diffs))
		}

		if diffs[0].Kind != ParamDiffAddUser {
			t.Error("diff 0 should have been an add user")
		}
		if diffs[0].Index != 1 {
			t.Error("index was wrong:", diffs[0].Index)
		}
		if !bytes.Equal(diffs[0].SHA, other.Users[1]) {
			t.Error("the sha should have been the second user in the list")
		}
		if diffs[1].Kind != ParamDiffDelUser {
			t.Error("diff 1 should have been an del user")
		}
		if diffs[1].Index != 1 {
			t.Error("index was wrong:", diffs[1].Index)
		}
		if !bytes.Equal(diffs[1].SHA, p.Users[1]) {
			t.Error("the sha should have been the second user in the list")
		}
	})
	t.Run("RekeysMaster", func(t *testing.T) {
		t.Parallel()

		var p, other Params
		testMust(p.AddUser("user1", testKey, testSalt))
		testMust(p.AddUser("user2", testKey, testSalt))
		testMust(p.AddUser("user3", testKey, testSalt))
		testMust(other.AddUser("user1", testKey, testSalt))
		testMust(other.AddUser("user2", testKey, testSalt))
		testMust(other.AddUser("user3", testKey, testSalt))

		// 0 and 1 have been rekeyed, 2 remains the same
		p.MKeys[0] = []byte{1}
		p.MKeys[1] = []byte{2}
		p.MKeys[2] = []byte{3}
		other.MKeys[0] = []byte{1 + 1}
		other.MKeys[1] = []byte{2 + 2}
		other.MKeys[2] = []byte{3}

		diffs := p.Diff(other)
		if len(diffs) != 2 {
			t.Error("should be 2 diffs, got:", len(diffs))
		}

		// First diff should be a rekey of ourselves (p/other.User == 0)
		if diffs[0].Kind != ParamDiffRekeySelf {
			t.Error("kind of diff should be rekey self")
		}
		if diffs[0].Index != 0 {
			t.Error("index was wrong:", diffs[0].Index)
		}
		if !bytes.Equal(diffs[0].SHA, p.Users[0]) {
			t.Error("the sha should have been the first user in the list")
		}

		// Second diff should be a rekey of some other guy
		if diffs[1].Kind != ParamDiffRekeyUser {
			t.Error("kind of diff should be rekey user")
		}
		if diffs[1].Index != 1 {
			t.Error("index was wrong:", diffs[1].Index)
		}
		if !bytes.Equal(diffs[1].SHA, p.Users[1]) {
			t.Error("the sha should have been the second user in the list")
		}
	})
	t.Run("RekeysSalt", func(t *testing.T) {
		t.Parallel()

		var p, other Params
		testMust(p.AddUser("user1", testKey, []byte{1}))
		testMust(p.AddUser("user2", testKey, []byte{2}))
		testMust(p.AddUser("user3", testKey, []byte{3}))
		testMust(other.AddUser("user1", testKey, []byte{1 + 1}))
		testMust(other.AddUser("user2", testKey, []byte{2 + 2}))
		testMust(other.AddUser("user3", testKey, []byte{3}))

		diffs := p.Diff(other)
		if len(diffs) != 2 {
			t.Error("should be 2 diffs, got:", len(diffs))
		}

		// First diff should be a rekey of ourselves (p/other.User == 0)
		if diffs[0].Kind != ParamDiffRekeySelf {
			t.Error("kind of diff should be rekey self")
		}
		if diffs[0].Index != 0 {
			t.Error("index was wrong:", diffs[0].Index)
		}
		if !bytes.Equal(diffs[0].SHA, p.Users[0]) {
			t.Error("the sha should have been the first user in the list")
		}

		// Second diff should be a rekey of some other guy
		if diffs[1].Kind != ParamDiffRekeyUser {
			t.Error("kind of diff should be rekey user")
		}
		if diffs[1].Index != 1 {
			t.Error("index was wrong:", diffs[1].Index)
		}
		if !bytes.Equal(diffs[1].SHA, p.Users[1]) {
			t.Error("the sha should have been the second user in the list")
		}
	})
}

func testMust(err error) {
	if err != nil {
		panic(err)
	}
}

func checkParamLengths(t *testing.T, p Params, n int) {
	t.Helper()
	if p.NUsers != n {
		t.Error("nusers wrong:", p.NUsers)
	}
	if len(p.Keys) != n {
		t.Error("keys wrong length:", len(p.Keys))
	}
	if len(p.Salts) != n {
		t.Error("salts wrong length:", len(p.Salts))
	}
	if len(p.IVs) != n {
		t.Error("ivs wrong length:", len(p.IVs))
	}
	if len(p.MKeys) != n {
		t.Error("mkeys wrong length:", len(p.MKeys))
	}
}
