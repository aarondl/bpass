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
