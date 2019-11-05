package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aarondl/bpass/blobformat"
	"github.com/aarondl/bpass/crypt"
	"github.com/aarondl/bpass/scpsync"
	"github.com/aarondl/bpass/txlogs"

	"golang.org/x/crypto/ssh"
)

const (
	syncSCP   = "scp"
	syncLocal = "file"
)

var (
	errNotFound = errors.New("not found")
)

func (u *uiContext) sync(name string, auto, push bool) error {
	err := u.store.UpdateSnapshot()
	if err != nil {
		return err
	}

	var syncs []string
	if len(name) != 0 {
		uuid, _, err := u.store.Find(name)
		if err != nil {
			return err
		}

		if len(uuid) == 0 {
			errColor.Printf("could not find entry with name: %q\n", name)
			return nil
		}

		syncs = []string{uuid}
	} else {
		syncs, err = collectSyncs(u.store)
		if err != nil {
			return err
		}
	}

	// From here on we need to avoid updating the store snapshot until we're
	// done syncing all the accounts, otherwise we run the risk of downloading
	// and running a new sync partway through and that's unexpected behavior

	// From this point on we don't worry about key's not being present for
	// the most part since collectSyncs should only return valid things
	hosts := make(map[string]string)
	logs := make([][]txlogs.Tx, 0, len(syncs))
	cryptParams := make(map[string]crypt.Params)
	for i, uuid := range syncs {
		entry := u.store.Snapshot[uuid]
		name, _ := entry[blobformat.KeyName]

		infoColor.Println("pull:", name)

		ct, hostentry, err := pullBlob(u, uuid)

		// Add to known hosts
		if len(hostentry) != 0 {
			hosts[uuid] = hostentry
		}

		if err != nil {
			if err != errNotFound {
				errColor.Printf("error pulling %q: %v\n", name, err)
				syncs[i] = ""
			}
			continue
		}

		params, pt, err := decryptBlob(u, name, ct)
		if err != nil {
			errColor.Printf("failed to decode %q: %v\n", name, err)
			syncs[i] = ""
			continue
		}

		log, err := txlogs.NewLog(pt)
		if err != nil {
			errColor.Printf("failed parsing log %q: %v\n", name, err)
			syncs[i] = ""
			continue
		}

		cryptParams[name] = params
		logs = append(logs, log)
	}

	if err = mergeParams(u, cryptParams); err != nil {
		errColor.Println("aborting sync, failed to merge users:", err)
		return nil
	}

	out, err := mergeLogs(u, u.store.Log, logs)
	if err != nil {
		errColor.Println("aborting sync, failed to merge logs:", err)
		return nil
	}

	u.store.ResetSnapshot()
	u.store.Log = out
	if err = u.store.UpdateSnapshot(); err != nil {
		errColor.Println("failed to rebuild snapshot, poisoned by sync:", err)
		errColor.Println("exiting to avoid corrupting local file")
		os.Exit(1)
	}

	if err = saveHosts(u.store.DB, hosts); err != nil {
		return err
	}

	if !push {
		return nil
	}

	// Save & encrypt in memory
	var pt, ct []byte
	if pt, err = u.store.Save(); err != nil {
		return err
	}
	if ct, err = crypt.Encrypt(cryptVersion, u.params, pt); err != nil {
		return err
	}

	// Push back to other machines
	hosts = make(map[string]string)
	for _, uuid := range syncs {
		if len(uuid) == 0 {
			// This is a signal that pulling did not work so don't attempt
			// to push here.
			continue
		}

		entry := u.store.Snapshot[uuid]
		name, _ := entry[blobformat.KeyName]

		infoColor.Println("push:", name)

		hostentry, err := pushBlob(u, uuid, ct)
		if err != nil {
			errColor.Printf("error pushing to %q: %v\n", name, err)
		}

		if len(hostentry) != 0 {
			hosts[uuid] = hostentry
		}
	}

	if err = saveHosts(u.store.DB, hosts); err != nil {
		return err
	}

	return nil
}

func saveHosts(store *txlogs.DB, newHosts map[string]string) error {
	for uuid, hostentry := range newHosts {
		entry := store.Snapshot[uuid]
		hosts := entry[blobformat.KeyKnownHosts]
		if len(hosts) == 0 {
			store.Set(uuid, blobformat.KeyKnownHosts, hostentry)
			continue
		}

		hostLines := strings.Split(hosts, "\n")
		hostLines = append(hostLines, hostentry)
		store.Set(uuid, blobformat.KeyKnownHosts, strings.Join(hostLines, "\n"))
	}

	return store.UpdateSnapshot()
}

// collectSyncs attempts to gather automatic sync entries and ensure that basic
// attributes are available (name, path, synckind) to make it easier to use
// later
func collectSyncs(store blobformat.Blobs) ([]string, error) {
	var validSyncs []string

	for uuid, entry := range store.Snapshot {
		sync, _ := entry[blobformat.KeySync]
		if sync != "true" {
			continue
		}

		name := entry[blobformat.KeyName]
		if len(name) == 0 {
			errColor.Printf("%q is a sync entry but its name is broken (skipping)", uuid)
			continue
		}

		uri := entry[blobformat.KeyURL]
		if len(uri) == 0 {
			errColor.Printf("%q is a sync entry but it has no %q key (skipping)\n", name, blobformat.KeyURL)
			continue
		}

		u, err := url.Parse(uri)
		if err != nil {
			errColor.Printf("%q is a sync account but it's url is not parseable (skipping)\n", name)
			continue
		}

		switch u.Scheme {
		case syncSCP:
			validSyncs = append(validSyncs, uuid)
		default:
			errColor.Printf("entry %q is a %q sync account, but this kind is unknown (old bpass version?)\n", name, u.Scheme)
		}
	}

	return validSyncs, nil
}

// pullBlob tries to download a file from the given sync entry
func pullBlob(u *uiContext, uuid string) (ct []byte, hostentry string, err error) {
	entry := u.store.Snapshot[uuid]
	// We know this parses because we parsed it once before
	uri, _ := url.Parse(entry[blobformat.KeyURL])

	switch uri.Scheme {
	case syncSCP:
		hostentry, ct, err = sshPull(u, entry)
		if scpsync.IsNotFoundErr(err) {
			return nil, hostentry, errNotFound
		}
	case syncLocal:
		path := filepath.FromSlash(uri.Path)
		ct, err = ioutil.ReadFile(path)
		if os.IsNotExist(err) {
			return nil, "", errNotFound
		}
	}

	if err != nil {
		return nil, hostentry, err
	}

	return ct, hostentry, nil
}

// pushBlob uploads a file to a given sync entry
func pushBlob(u *uiContext, uuid string, payload []byte) (hostentry string, err error) {
	entry := u.store.Snapshot[uuid]
	uri, _ := url.Parse(entry[blobformat.KeyURL])

	switch uri.Scheme {
	case syncSCP:
		hostentry, err = sshPush(u, entry, payload)
	case syncLocal:
		path := filepath.FromSlash(uri.Path)
		err = ioutil.WriteFile(path, payload, 0600)
	}

	return hostentry, err
}

func decryptBlob(u *uiContext, name string, ct []byte) (params crypt.Params, pt []byte, err error) {
	pass := u.pass
	user := u.user
	key, salt := u.params.UserKeys()
	for {
		// Decrypt payload with our loaded key
		_, params, pt, err = crypt.Decrypt([]byte(user), []byte(pass), key, salt, ct)
		if err == nil {
			return params, pt, err
		}

		switch err {
		default:
			return params, nil, err
		case crypt.ErrNeedUser, crypt.ErrUnknownUser:
			user, err = u.prompt(promptColor.Sprintf("%s user: ", name))
			if err != nil {
				return params, nil, nil
			}
		case crypt.ErrWrongPassphrase:
			pass, err = u.promptPassword(promptColor.Sprintf("%s passphrase: ", name))
			if err != nil || len(pass) == 0 {
				return params, nil, nil
			}
		}
	}
}

var syncNoCommonAncestryWarning = `WARNING: There is no common ancestry between
the local and the remote file. What this probably means is that the wrong
file is in the sync location, and proceeding would mean that both files become
merged into one instead of remaining separate.`

func mergeLogs(u *uiContext, in []txlogs.Tx, toMerge [][]txlogs.Tx) ([]txlogs.Tx, error) {
	if len(toMerge) == 0 {
		return in, nil
	}

	var c []txlogs.Tx
	var conflicts []txlogs.Conflict
	i := 0
	for i < len(toMerge) {
		log := toMerge[i]
		c, conflicts = txlogs.Merge(in, log, conflicts)

		if len(conflicts) == 0 {
			i++
			continue
		}

		infoColor.Println(len(conflicts), "conflicts occurred during syncing!")

		for i, c := range conflicts {
			switch c.Kind {
			case txlogs.ConflictKindRoot:
				errColor.Println(syncNoCommonAncestryWarning)
				yes, err := u.getYesNo("do you want to merge these anyway?")
				if err != nil {
					return nil, err
				}

				if !yes {
					infoColor.Println("aborting merge")
					return nil, errors.New("sync target was a total fork")
				}
				conflicts[i].Force()
			case txlogs.ConflictKindDeleteSet:
				infoColor.Printf("entry %q was deleted at: %s\nbut at %s, ",
					c.Initial.UUID,
					time.Unix(0, c.Initial.Time).Format(time.RFC3339),
					time.Unix(0, c.Conflict.Time).Format(time.RFC3339),
				)

				switch c.Initial.Kind {
				case txlogs.TxSetKey:
					infoColor.Printf("a set happened:\n%s = %s\n",
						c.Conflict.Key,
						c.Conflict.Value,
					)
				case txlogs.TxDeleteKey:
					infoColor.Printf("a delete happened for key:\n%s\n",
						c.Conflict.Key,
					)
				}

				for {
					line, err := u.prompt(promptColor.Sprint("[R]estore item? [D]elete item? (r/R/d/D): "))
					if err != nil {
						return nil, err
					}

					switch line {
					case "R", "r":
						conflicts[i].DiscardInitial()
					case "D", "d":
						conflicts[i].DiscardConflict()
					default:
						continue
					}
				}
			}
		}
	}

	return c, nil
}

var disclaimer = `WARNING: There are user differences with the local copy.
Any changes accepted from a remote will immediately be applied to the local
copy and on push to will overwrite all remotes completely. Meaning the updated
local copy will completely and wholly annihilate all remotes.`

func mergeParams(u *uiContext, allParams map[string]crypt.Params) error {
	saidDisclaimer := false

LoopSources:
	for name, other := range allParams {
		diffs := u.params.Diff(other)

		if len(diffs) == 0 {
			continue
		}

		if !saidDisclaimer {
			saidDisclaimer = true
			errColor.Println(disclaimer)
		}

		for _, d := range diffs {
			switch d.Kind {
			case crypt.ParamDiffAddUser:
				infoColor.Printf("%q has an extra user: %x\n", name, d.SHA)
				yes, err := u.getYesNo("do you wish to add this user locally?")
				if err != nil {
					return err
				}

				if yes {
					if err := u.params.CopyUser(d.Index, other); err != nil {
						return err
					}
				}
			case crypt.ParamDiffDelUser:
				infoColor.Printf("%q is missing user: %x\n", name, d.SHA)
				yes, err := u.getYesNo("do you wish to remove this user locally?")
				if err != nil {
					return err
				}

				if yes {
					if err = u.params.RemoveUserHash(d.SHA); err != nil {
						return err
					}
				}
			case crypt.ParamDiffDelSelf:
				infoColor.Printf("%q has removed YOU\n", name)
				return errors.New("how did you decrypt this? bailing")
			case crypt.ParamDiffRekeyUser:
				infoColor.Printf("%q has rekeyed: %x\n", name, d.SHA)
				yes, err := u.getYesNo("do you wish to accept this rekey?")
				if err != nil {
					return err
				}

				if yes {
					// Update the salt, iv, mkey for that user
					index := -1
					for i, u := range other.Users {
						if bytes.Equal(u, d.SHA) {
							index = i
							break
						}
					}

					if index < 0 {
						return errors.New("failed to find user specified in diff")
					}

					u.params.Salts[d.Index] = other.Salts[index]
					u.params.IVs[d.Index] = other.IVs[index]
					u.params.MKeys[d.Index] = other.MKeys[index]
				}
			case crypt.ParamDiffRekeySelf:
				infoColor.Printf("%q has rekeyed YOU\n", name)
				yes, err := u.getYesNo("do you wish to accept this rekey?")
				if err != nil {
					return err
				}

				if !yes {
					continue
				}

				if !u.params.IsMultiUser() {
					u.params.Salts[0] = other.Salts[0]
					continue
				}

				// Update the salt, iv, mkey for that us
				index := -1
				for i, u := range other.Users {
					if bytes.Equal(u, d.SHA) {
						index = i
						break
					}
				}

				if index < 0 {
					return errors.New("failed to find user specified in diff")
				}

				u.params.Salts[u.params.User] = other.Salts[index]
				u.params.IVs[u.params.User] = other.IVs[index]
				u.params.MKeys[u.params.User] = other.MKeys[index]
			case crypt.ParamDiffMultiFile:
				infoColor.Printf("%q has changed into a multi-user file\n", name)
				yes, err := u.getYesNo("do you wish to accept this change?")
				if err != nil {
					return err
				}

				if yes {
					// We were able to decrypt this file, so the user both
					// knows his username and password for the file and he's
					// clearly in it. So we can safely just overwrite our
					// current params with the other ones.
					*u.params = other
				}
				// Whether or not this is added or rejected, we basically don't
				// want any changes from this source is it can only really be
				// add users.
				continue LoopSources
			case crypt.ParamDiffSingleFile:
				infoColor.Printf("%q has changed into a single-user file\n", name)
				yes, err := u.getYesNo("do you wish to accept this change?")
				if err != nil {
					return err
				}

				if yes {
					// We were able to decrypt this file so the user is the
					// last one remaining, we can simply overwrite our params
					// with the others
					*u.params = other
				}
				// Other diff chunks don't matter because this is a nuclear
				// option
				continue LoopSources
			}
		}
	}

	return nil
}

func sshPull(u *uiContext, entry txlogs.Entry) (hostentry string, ct []byte, err error) {
	address, path, config, err := sshConfig(entry)
	if err != nil {
		return "", nil, err
	}

	known := entry[blobformat.KeyKnownHosts]
	asker := &hostAsker{u: u, known: known}
	config.HostKeyCallback = asker.callback

	payload, err := scpsync.Recv(address, config, path)
	if err != nil {
		return asker.newHost, nil, err
	}

	return asker.newHost, payload, nil
}

func sshPush(u *uiContext, entry txlogs.Entry, ct []byte) (hostentry string, err error) {
	address, path, config, err := sshConfig(entry)
	if err != nil {
		return "", err
	}

	known := entry[blobformat.KeyKnownHosts]
	asker := &hostAsker{u: u, known: known}
	config.HostKeyCallback = asker.callback

	err = scpsync.Send(address, config, path, 0600, ct)
	if err != nil {
		return "", err
	}

	return asker.newHost, nil
}

func sshConfig(entry txlogs.Entry) (address, path string, config *ssh.ClientConfig, err error) {
	uri, err := url.Parse(entry[blobformat.KeyURL])
	if err != nil {
		return "", "", nil, err
	}

	host := uri.Hostname()
	port := uri.Port()
	user := uri.User.Username()
	pass, _ := uri.User.Password()
	secretKey := entry[blobformat.KeyPriv]
	path = uri.Path[1:]

	if len(user) == 0 {
		return "", "", nil, errors.New("url missing user")
	}
	if len(host) == 0 {
		return "", "", nil, errors.New("url missing host")
	}
	if len(path) == 0 {
		return "", "", nil, errors.New("url missing file path")
	}

	address = net.JoinHostPort(host, port)
	config = new(ssh.ClientConfig)
	config.User = user
	if len(pass) != 0 {
		config.Auth = append(config.Auth, ssh.Password(pass))
	}

	if len(secretKey) != 0 {
		signer, err := ssh.ParsePrivateKey([]byte(secretKey))
		if err != nil {
			return "", "", nil, err
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}

	return address, path, config, nil
}

type hostAsker struct {
	u       *uiContext
	known   string
	newHost string
}

func (h *hostAsker) callback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	// Format is `hostname address key-type key:base64`
	keyHashBytes := sha256.Sum256(key.Marshal())
	keyHash := fmt.Sprintf("%x", keyHashBytes)

	keyType := key.Type()
	addr := remote.String()
	hostLine := fmt.Sprintf(`%s %s %s %s`, hostname, addr, keyType, keyHash)

	knownLines := strings.Split(h.known, "\n")

	for _, h := range knownLines {
		vals := strings.Split(h, " ")

		if vals[0] != hostname {
			continue
		}

		// Same host, double check key is same
		if vals[2] != keyType {
			return errors.New("known host's key type has changed, could be a mitm attack")
		}
		if vals[3] != keyHash {
			return errors.New("known host's key has changed, could be a mitm attack")
		}

		// We've seen this host before and everything is OK
		return nil
	}

	var b strings.Builder
	for i := 0; i < len(keyHash)-1; i += 2 {
		if i != 0 {
			b.WriteByte(':')
		}
		b.WriteByte(keyHash[i])
		b.WriteByte(keyHash[i+1])
	}
	sha256FingerPrint := b.String()

	infoColor.Printf("(ssh) connected to: %s (%s)\nverify pubkey: %s %s\n",
		hostname, addr, keyType, sha256FingerPrint)
	line, err := h.u.prompt(promptColor.Sprint("Save this host (y/N): "))
	if err != nil {
		return fmt.Errorf("failed to get user confirmation on host: %w", err)
	}

	switch line {
	case "y", "Y":
		h.newHost = hostLine
		return nil
	default:
		return errors.New("user rejected host")
	}
}

func (u *uiContext) syncAddInterruptible(kind string) error {
	err := u.syncAdd(kind)
	switch err {
	case nil:
		return nil
	case ErrEnd:
		errColor.Println("Aborted")
		return nil
	default:
		return err
	}
}

func (u *uiContext) syncAdd(kind string) error {
	found := false
	for _, k := range []string{syncSCP} {
		if k == kind {
			found = true
			break
		}
	}

	if !found {
		errColor.Printf("%q is not a supported sync kind (old version of bpass?)\n", kind)
		return nil
	}

	return u.store.Do(func() error {
		// New entry
		uuid, err := u.store.NewSync(kind)
		if err != nil {
			return err
		}

		user, err := u.getString("user")
		if err != nil {
			return err
		}

		host, err := u.getString("host")
		if err != nil {
			return err
		}

		port := "22"
		for {
			port, err = u.prompt(promptColor.Sprint("port (22): "))
			if err != nil {
				return err
			}

			if len(port) == 0 {
				port = "22"
				break
			}

			_, err = strconv.Atoi(port)
			if err != nil {
				errColor.Printf("port must be an integer between %d and %d\n", 1, int(math.MaxUint16)-1)
				continue
			}

			break
		}

		file, err := u.getString("path")
		if err != nil {
			return err
		}

		var uri url.URL
		uri.Scheme = kind
		uri.User = url.User(user)
		uri.Host = net.JoinHostPort(host, port)
		uri.Path = file

		promptColor.Println("Key type:")
		choice, err := u.getMenuChoice(promptColor.Sprint("> "), []string{"ED25519", "RSA 4096", "Password"})
		if err != nil {
			return err
		}

		switch choice {
		case 0:
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				errColor.Println("failed to generate ed25519 ssh key")
				return nil
			}

			// Marshal private key into DER ASN.1 then to PEM
			b, err := x509.MarshalPKCS8PrivateKey(priv)
			if err != nil {
				errColor.Println("failed to marshal ed25519 private key with x509:", err)
			}
			pemBlock := pem.Block{Type: "PRIVATE KEY", Bytes: b}
			b = pem.EncodeToMemory(&pemBlock)

			public, err := ssh.NewPublicKey(pub)
			if err != nil {
				errColor.Println("failed to parse public key:", err)
			}
			publicStr := string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(public))) + " @bpass"

			u.store.Set(uuid, blobformat.KeyPriv, string(bytes.TrimSpace(b)))
			u.store.Set(uuid, blobformat.KeyPub, publicStr)

			infoColor.Printf("successfully generated new ed25519 key:\n%s\n", publicStr)

		case 1:
			priv, err := rsa.GenerateKey(rand.Reader, 4096)
			if err != nil {
				errColor.Println("failed to generate rsa-4096 ssh key")
				return nil
			}

			// Marshal private key into DER ASN.1 then to PEM
			b, err := x509.MarshalPKCS8PrivateKey(priv)
			if err != nil {
				errColor.Println("failed to marshal rsa private key with x509:", err)
				return nil
			}
			pemBlock := pem.Block{Type: "PRIVATE KEY", Bytes: b}
			b = pem.EncodeToMemory(&pemBlock)

			public, err := ssh.NewPublicKey(&priv.PublicKey)
			if err != nil {
				errColor.Println("failed to parse public key:", err)
			}
			publicStr := string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(public))) + " @bpass"

			u.store.Set(uuid, blobformat.KeyPriv, string(bytes.TrimSpace(b)))
			u.store.DB.Set(uuid, blobformat.KeyPub, publicStr)

			infoColor.Printf("successfully generated new rsa-4096 key:\n%s\n", publicStr)

		case 2:
			pass, err := u.getPassword()
			if err != nil {
				return err
			}

			uri.User = url.UserPassword(user, pass)
		default:
			panic("how did this happen?")
		}

		// Use raw-er sets to avoid timestamp spam
		u.store.DB.Set(uuid, blobformat.KeySync, "true")
		u.store.DB.Set(uuid, blobformat.KeyURL, uri.String())

		blob, err := u.store.Get(uuid)
		if err != nil {
			return err
		}

		fmt.Println()
		infoColor.Println("added new sync entry:", blob.Name())

		return nil
	})
}
