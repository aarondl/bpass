package crypt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// Params for encryption.
//
// For encryption for a single user the following must be provided:
// Key, Salt
//
// For encryption for multiple users all fields must be provided.
type Params struct {
	// This version is stored by Decrypt() so we know if we're
	// encrypting the same version or not.
	version int

	// Users is how many users exist where User is which user is selected
	// In a single-user file all of these will be 0
	NUsers int
	// User is the active user and the index
	// into the fields used for Salts/IVs/MKeys to perform encryptions with.
	User int

	// Keys are the user's keys (DeriveKey(password, Salts[User]))
	Keys [][]byte
	// Salts for all users
	Salts [][]byte

	// The following fields are nil when NUsers = 0
	// Users is the sha256 of all the usernames in the file
	Users [][]byte
	// IVs for all users (to decrypt master keys). If an IV is nil it will
	// be generated.
	IVs [][]byte
	// MKeys for all users (encrypted master key blobs). If entries
	// are nil then the key/iv will be attempt to be used to encrypt master
	// with it.
	MKeys [][]byte

	// These fields are also nil when NUsers = 0
	// IVM is the iv for decoding the master key
	// If IVM is nil, it will be generated, this requires a complete redo
	// of MKeys and thus requires all Keys and all IVs for all users.
	IVM []byte
	// Master is the master key, decrypted from one of the master key blocks
	// If the master key is nil, it will be generated.
	Master []byte
}

// IsMultiUser checks to see if the encryption parameters are multi-user
func (p *Params) IsMultiUser() bool {
	return p.NUsers != 0
}

// SetSingleUser sets up the params to be a single user encryption scheme
// using the key and salt (usually created by DeriveKey)
func (p *Params) SetSingleUser(key, salt []byte) {
	p.Keys = [][]byte{key}
	p.Salts = [][]byte{salt}

	p.NUsers, p.User = 0, 0
	p.Users, p.IVs, p.MKeys, p.IVM, p.Master = nil, nil, nil, nil, nil
}

// AddUser adds a user to the parameters. Key and Salt may be created
// using DeriveKey. If the current file is not a multi-user file, this simply
// changes it into one.
//
// Keys[0],Salt[0] may be passed in to avoid another call to DeriveKey
// in this case.
//
// Returns an error if the user name has already been used
func (p *Params) AddUser(username string, key, salt []byte) error {
	if p.NUsers == 0 {
		// Wipe out the single user parameters
		p.Keys = nil
		p.Salts = nil
		p.IVs = nil
	}

	sum := sha256.Sum256([]byte(username))
	hash := sum[:]

	for _, u := range p.Users {
		if bytes.Equal(u, hash) {
			return errors.New("user already added")
		}
	}

	p.Users = append(p.Users, hash)
	p.Keys = append(p.Keys, key)
	p.Salts = append(p.Salts, salt)
	p.IVs = append(p.IVs, nil)     // force generation
	p.MKeys = append(p.MKeys, nil) // force generation

	p.NUsers++
	return nil
}

// CopyUser copies the parameters of the user at index of other into p.
// Can return an error if the user name has already been used.
func (p *Params) CopyUser(index int, other Params) error {
	for _, u := range p.Users {
		if bytes.Equal(u, other.Users[index]) {
			return errors.New("user already added")
		}
	}

	p.Users = append(p.Users, other.Users[index])
	p.Salts = append(p.Salts, other.Salts[index])
	p.IVs = append(p.IVs, other.IVs[index])
	p.MKeys = append(p.MKeys, other.MKeys[index])
	p.NUsers++
	return nil
}

// RemoveUser from the parameters.
//
// Returns ErrUnknownUser if user is not found.
//
// If the user is the last user, it will remove him and convert the file
// to a single user file.
//
// If the user to-be-removed user is not the last one and
// was the one to open the file, it will return an error to prevent the user
// from locking himself out, he must be removed by a different user.
func (p *Params) RemoveUser(username string) error {
	sum := sha256.Sum256([]byte(username))
	return p.RemoveUserHash(sum[:])
}

// RemoveUserHash deletes a user by their hash instead of username
func (p *Params) RemoveUserHash(user []byte) error {
	index := -1
	for i, u := range p.Users {
		if bytes.Equal(user, u) {
			index = i
			break
		}
	}

	if index < 0 {
		return ErrUnknownUser
	}

	if p.NUsers == 1 {
		p.SetSingleUser(p.Keys[0], p.Salts[0])
		return nil
	}

	if p.User == index {
		return errors.New("cannot remove user who opened the file unless they are the last")
	}

	// Keep the ordering, delete from each slice
	copy(p.Keys[index:], p.Keys[index+1:])
	p.Keys = p.Keys[:len(p.Keys)-1]

	copy(p.Salts[index:], p.Salts[index+1:])
	p.Salts = p.Salts[:len(p.Salts)-1]

	copy(p.Users[index:], p.Users[index+1:])
	p.Users = p.Users[:len(p.Users)-1]

	copy(p.IVs[index:], p.IVs[index+1:])
	p.IVs = p.IVs[:len(p.IVs)-1]

	copy(p.MKeys[index:], p.MKeys[index+1:])
	p.MKeys = p.MKeys[:len(p.MKeys)-1]

	p.NUsers--

	return nil
}

// UserKeys returns the key and salt for the user that decrypted the file.
func (p *Params) UserKeys() (key, salt []byte) {
	if p.NUsers == 0 {
		return p.Keys[0], p.Salts[0]
	}
	return p.Keys[p.User], p.Salts[p.User]
}

// Rekey rekeys the user who opened the file
func (p *Params) Rekey(key, salt []byte) {
	p.rekeyIndex(key, salt, p.User)
}

// RekeyUser by name. Return ErrUnknownUser if the user is not found.
func (p *Params) RekeyUser(username string, key, salt []byte) error {
	sum := sha256.Sum256([]byte(username))
	index := -1
	for i, u := range p.Users {
		if bytes.Equal(sum[:], u) {
			index = i
			break
		}
	}

	if index < 0 {
		return ErrUnknownUser
	}

	p.rekeyIndex(key, salt, index)
	return nil
}

// RekeyAll is a massively destructive operation that will delete everybody's
// current keys, generate new passwords for them, derive those into keys
// and set them. This process is extremely expensive.
//
// Consequently it's impossible for us to know (thanks hashing) who these
// passwords belong to, I hope you remember the order of the people who
// are in the file!
func (p *Params) RekeyAll(version int) ([]string, error) {
	if p.NUsers == 0 {
		pwd, err := getRandomPassphrase()
		if err != nil {
			return nil, err
		}

		key, salt, err := DeriveKey(version, pwd)
		if err != nil {
			return nil, err
		}
		p.SetSingleUser(key, salt)
		return []string{string(pwd)}, nil
	}

	passwords := make([]string, p.NUsers)

	for i := 0; i < p.NUsers; i++ {
		pwd, err := getRandomPassphrase()
		if err != nil {
			return nil, err
		}

		key, salt, err := DeriveKey(version, pwd)
		if err != nil {
			return nil, err
		}

		passwords[i] = string(pwd)

		p.Keys[i] = key
		p.Salts[i] = salt
		p.IVs[i] = nil
		p.MKeys[i] = nil
	}
	p.IVM = nil
	p.Master = nil

	return passwords, nil
}

var alphabet = `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`

func getRandomPassphrase() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}

	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}

	return b, nil
}

func (p *Params) rekeyIndex(key, salt []byte, index int) {
	p.Keys[index] = key
	p.Salts[index] = salt

	if p.NUsers == 0 {
		return
	}

	// Force regeneration
	p.IVs[index] = nil
	p.MKeys[index] = nil
}

// validate the encryption params for encrypting
func (p Params) validate(c config) error {
	if len(p.Keys) == 0 {
		return errors.New("must have at least one key")
	}
	if len(p.Salts) == 0 {
		return errors.New("must have at least one salt")
	}
	for i, key := range p.Keys {
		if len(key) != 0 && len(key) != c.keySize {
			return fmt.Errorf("keys[%d] must be %d bytes", i, c.keySize)
		}
	}
	for i, salt := range p.Salts {
		if len(salt) != c.saltSize {
			return fmt.Errorf("salts[%d] must be %d bytes", i, c.saltSize)
		}
	}

	if p.NUsers == 0 {
		return nil
	}

	if len(p.Keys) != p.NUsers {
		return errors.New("must have at least one key")
	}
	if len(p.Salts) != p.NUsers {
		return errors.New("must have at least one salt")
	}

	if p.User < 0 || p.User >= p.NUsers {
		return errors.New("user should be an index of 0 <= user < nUsers")
	}

	if len(p.Users) != p.NUsers {
		return errors.New("users must be the same length as nusers")
	}
	for i, user := range p.Users {
		if len(user) != sha256.Size {
			return fmt.Errorf("users[%d] must be %d bytes", i, sha256.Size)
		}
	}
	if len(p.IVs) != p.NUsers {
		return errors.New("ivs must be the same length as nusers")
	}
	for i, iv := range p.IVs {
		if iv == nil {
			continue
		}
		if len(iv) != c.blockSize {
			return fmt.Errorf("ivs[%d] must be %d bytes", i, c.blockSize)
		}
	}
	if len(p.MKeys) != p.NUsers {
		return errors.New("mkeys must be the same length as nusers")
	}
	for i, mkey := range p.MKeys {
		if mkey == nil {
			continue
		}
		if len(mkey) != c.keySize {
			return fmt.Errorf("mkeys[%d] must be %d bytes", i, c.keySize)
		}
	}

	if p.IVM != nil && len(p.IVM) != c.blockSize {
		return fmt.Errorf("ivm must be %d bytes", c.blockSize)
	}
	if p.Master != nil && len(p.Master) != c.keySize {
		return fmt.Errorf("master key must be %d bytes", c.keySize)
	}

	return nil
}

// Different ways two sets of parameters can differ.
const (
	// ParamDiffAddedUser has a sha & index in other
	ParamDiffAddUser = iota
	// ParamDiffDelUser has a sha & index in p
	ParamDiffDelUser
	// ParamDiffDelSelf has a sha & index in p
	ParamDiffDelSelf
	// ParamDiffRekeyUser has a sha & index in p
	ParamDiffRekeyUser
	// ParamDiffRekeySelf has a sha & index in p
	ParamDiffRekeySelf

	// ParamDiffMultiFile appears when p is single and other is multi
	ParamDiffMultiFile
	// ParamDiffSingleFile appears when p is multi and other is single
	ParamDiffSingleFile
)

// ParamDiff is a difference between two crypt parameter sets
type ParamDiff struct {
	Kind  int
	Index int
	SHA   []byte
}

func (p ParamDiff) String() string {
	return fmt.Sprintf("%d %d %x", p.Kind, p.Index, p.SHA)
}

// Diff compares p to other producing a list of changes. The changes are
// from the perspective of what you would need to do to p to arrive at other.
func (p Params) Diff(other Params) (diffs []ParamDiff) {
	pIsMulti := p.NUsers != 0
	otherIsMulti := other.NUsers != 0

	if !pIsMulti && !otherIsMulti {
		if bytes.Equal(p.Salts[0], other.Salts[0]) {
			// Single-user file with same salt means there's no
			// diffs to be found.
			return nil
		}

		return []ParamDiff{
			{Kind: ParamDiffRekeySelf},
		}
	}

	// Find changes between file types
	if !pIsMulti && otherIsMulti {
		diffs = append(diffs, ParamDiff{Kind: ParamDiffMultiFile})
	} else if pIsMulti && !otherIsMulti {
		// In this case, none of the remaining checks can't really apply
		// given that a multi -> single is somewhat nuclear, and by the time
		// we know this we've already decrypted the file which means our
		// passphrase/salt is unchanged and there's no reason to diff further.
		diffs = append(diffs, ParamDiff{Kind: ParamDiffSingleFile})
		return diffs
	}

	// Find additions
Adds:
	for i, theirUser := range other.Users {
		for _, ourUser := range p.Users {
			if bytes.Equal(theirUser, ourUser) {
				continue Adds
			}
		}

		// We don't have a user they do, so we would
		// need to add the user.
		diffs = append(diffs, ParamDiff{
			Kind:  ParamDiffAddUser,
			Index: i,
			SHA:   theirUser,
		})
	}

	// Find removals
Removes:
	for i, ourUser := range p.Users {
		for _, theirUser := range other.Users {
			if bytes.Equal(theirUser, ourUser) {
				continue Removes
			}
		}

		// They don't have a user we do, so we would need to remove that
		// user.
		kind := ParamDiffDelUser
		if i == p.User && otherIsMulti {
			kind = ParamDiffDelSelf
		}
		diffs = append(diffs, ParamDiff{
			Kind:  kind,
			Index: i,
			SHA:   ourUser,
		})
	}

	// Special case for rekeyself, note that if is !otherIsMulti
	// is true then we know from checks above that pIsMulti and all we care
	// about is checking if we were rekeyed, nothing else matters past this
	if !otherIsMulti {
		if !bytes.Equal(p.Salts[p.User], other.Salts[0]) {
			diffs = append(diffs, ParamDiff{
				Kind:  ParamDiffRekeySelf,
				Index: p.User,
				SHA:   p.Users[p.User],
			})
		}
		return diffs
	}

	// Past this point it's true that pIsMulti && otherIsMulti

	// Find rekeys
UserRekeys:
	for i, ourUser := range p.Users {
		for j, theirUser := range other.Users {
			if !bytes.Equal(ourUser, theirUser) {
				continue
			}

			// if master != master && salt != salt =  rekey
			// if master != master && salt == salt -> password change
			// either way master blobs changing are what matters
			// it's possible that master blobs are nil if we recently
			// added a user in this session in which case we can only test salts
			// which cannot be nil

			// Pay close attention to the parens here
			hasBeenRekeyed :=
				(len(p.MKeys[i]) != 0 && len(other.MKeys[j]) != 0) &&
					!bytes.Equal(p.MKeys[i], other.MKeys[j])

			hasBeenRekeyed = hasBeenRekeyed ||
				!bytes.Equal(p.Salts[i], other.Salts[j])

			if !hasBeenRekeyed {
				continue UserRekeys
			}

			kind := ParamDiffRekeyUser
			if i == p.User {
				kind = ParamDiffRekeySelf
			}
			diffs = append(diffs, ParamDiff{
				Kind:  kind,
				Index: i,
				SHA:   p.Users[i],
			})

			break
		}
	}

	return diffs
}
