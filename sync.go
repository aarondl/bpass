package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/aarondl/bpass/blobformat"
	"github.com/aarondl/bpass/crypt"
	"github.com/aarondl/bpass/scpsync"
	"github.com/aarondl/bpass/txlogs"

	"golang.org/x/crypto/ssh"
)

type credentials struct {
	User      string
	Pass      string
	Key, Salt []byte
}

type blobParts struct {
	Name   string
	Creds  credentials
	Params crypt.Params
	Log    []txlogs.Tx
}

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
		uuid, _, err := u.store.FindByName(name)
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

	// From this point on we don't worry about keys not being present for
	// the most part since collectSyncs should only return valid things
	hosts := make(map[string]string)
	dupeCheck := make([][64]byte, 0, len(syncs))
	blobs := make([]blobParts, 0, len(syncs))
Syncs:
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

		hash := sha512.Sum512(ct)
		for _, d := range dupeCheck {
			if hash == d {
				infoColor.Printf("skipping merge (duplicate): %q\n", name)
				continue Syncs
			}
		}

		params, creds, pt, err := decryptBlob(u, name, ct)
		if err != nil {
			errColor.Printf("failed to decrypt %q: %v\n", name, err)
			syncs[i] = ""
			continue
		} else if len(pt) == 0 {
			errColor.Printf("failed to decrypt %q: %v\n", name, err)
			syncs[i] = ""
			continue
		}

		log, err := txlogs.NewLog(pt)
		if err != nil {
			errColor.Printf("failed parsing log %q: %v\n", name, err)
			syncs[i] = ""
			continue
		}

		blobs = append(blobs, blobParts{
			Name:   name,
			Creds:  creds,
			Params: params,
			Log:    log,
		})
	}

	out, err := mergeBlobs(u, blobs)
	if err != nil {
		errColor.Println("aborting sync, failed to merge logs:", err)
		return nil
	}

	u.user, u.pass = out.User, out.Pass
	u.key, u.salt = out.Key, out.Salt
	u.master, u.ivm = out.Master, out.IVM

	u.store.ResetSnapshot()
	u.store.Log = out.Log
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
	if ct, err = crypt.Encrypt(cryptVersion, u.makeParams(), pt); err != nil {
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

func decryptBlob(u *uiContext, name string, ct []byte) (params crypt.Params, creds credentials, pt []byte, err error) {
	creds.User, creds.Pass = u.user, u.pass
	creds.Key, creds.Salt = u.key, u.salt
	for {
		// Decrypt payload with our loaded key
		_, params, pt, err = crypt.Decrypt([]byte(creds.User), []byte(creds.Pass), creds.Key, creds.Salt, ct)
		if err == nil {
			return params, creds, pt, err
		}

		switch err {
		default:
			return params, creds, nil, err
		case crypt.ErrNeedUser, crypt.ErrUnknownUser:
			creds.User, err = u.prompt(promptColor.Sprintf("%s user: ", name))
			if err != nil {
				return params, creds, nil, nil
			}
		case crypt.ErrWrongPassphrase:
			creds.Pass, err = u.promptPassword(promptColor.Sprintf("%s passphrase: ", name))
			if err != nil || len(creds.Pass) == 0 {
				return params, creds, nil, nil
			}
		}
	}
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
