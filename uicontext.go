package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/aarondl/bpass/blobformat"
	"github.com/aarondl/bpass/crypt"
)

type uiContext struct {
	// Input
	in LineEditor
	// Output
	out io.Writer

	created       bool
	filename      string
	shortFilename string

	// Decrypted and decoded storage
	store blobformat.Blobs

	// save user & password for syncing later
	user string
	pass string

	// These encryption params that come out of decrypt()
	// are saved. We need these to tell if we're a multi-user file
	// as well as provide fast-path decryption for sync'd copies.
	key, salt, master, ivm []byte
}

func (u *uiContext) makeParams() *crypt.Params {
	if len(u.master) == 0 {
		return &crypt.Params{
			Keys:  [][]byte{u.key},
			Salts: [][]byte{u.salt},
		}
	}

	var p crypt.Params

	users, err := u.store.Users()
	if err != nil {
		panic(err)
	}

	index := 0
	for uuid, name := range users {
		name = blobformat.SplitUsername(name)
		if len(name) == 0 {
			panic("name was not a username")
		}

		username := sha256.Sum256([]byte(name))

		blob, err := u.store.MustFind(uuid)
		if err != nil {
			panic("could not find user we just found")
		}

		salt, err := hex.DecodeString(blob[blobformat.KeySalt])
		if err != nil {
			panic("user entry had bad salt")
		}
		iv, err := hex.DecodeString(blob[blobformat.KeyIV])
		if err != nil {
			panic("user entry had bad iv")
		}
		mkey, err := hex.DecodeString(blob[blobformat.KeyMKey])
		if err != nil {
			panic("user entry had bad mkey")
		}

		fmt.Println(u.user, name)
		if u.user == name {
			p.User = index
			p.Keys = append(p.Keys, u.key)
		} else {
			p.Keys = append(p.Keys, nil)
		}
		p.Users = append(p.Users, username[:])
		p.Salts = append(p.Salts, salt)
		p.IVs = append(p.IVs, iv)
		p.MKeys = append(p.MKeys, mkey)
		p.NUsers++
		index++
	}

	p.IVM = u.ivm
	p.Master = u.master

	return &p
}
