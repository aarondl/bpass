package main

import (
	"bytes"
	"errors"
	"time"

	"github.com/aarondl/bpass/blobformat"
	"github.com/aarondl/bpass/txlogs"
)

type mergeResult struct {
	User, Pass  string
	Key, Salt   []byte
	Master, IVM []byte
	Log         []txlogs.Tx
}

// mergeBlobs has the insane task of merging each entry into the local entry
// it uses copies of the data in order to not mess anything up if the user
// suddenly aborts
//
// merging encryption parameters is fraught with terror for various reasons
// this giant comment will attempt to outline all scenarios which we can
// encounter and how we can detect/resolve the problems.
//
// Each scenario details (local) -> (remote)
//
// single -> single
//  - upstream has different password
//  the user could have entered different credentials to open the remote
//  file. Because there's no user database entry in this mode, we check
//  which file has the latest log, if they're the same we prompt to see
//  which credentials the user would like to keep.
//
// single -> multi
//  * we can decrypt the multi-user, so we know our username/password
//    and can store these in our local state if we need to
//  * post-log merge, we know based on number of users whether we will
//    be multi-user or not
//  * must keep ivm/master state consistent after we know outcome
//    if we're multi-user: keep them
//    if we're not: discard them
//  * must keep user/key/salt state consistent after we know outcome
//    whichever side wins, we keep those credentials
//
// multi -> single
//  * same as above simply in reverse, we still merge the logs to determine
//    the outcome, and we still need to keep the credentials that were used
//    to decrypt the side that wins
//
// multi -> multi
//  * log merging solves all problems EXCEPT:
//  * if the master key has changed
//    - we can see this plainly as a difference in the params from decrypt
//    in this case it's important to determine whose master key wins
//    we can know this by looking at which mkey from the params ends up
//    in the merged log
//    it also invalidates user entries that are not in the winning side
//    because they will have been encrypted with a master key that no longer
//    is in use
func mergeBlobs(u *uiContext, remotes []blobParts) (m mergeResult, err error) {
	// Copy everything into a temp to abort at any time without damaging
	// our current stuff
	m = mergeResult{
		User: u.user, Pass: u.pass,
		Key: u.key, Salt: u.salt,
		Master: u.master, IVM: u.ivm,
		Log: make([]txlogs.Tx, len(u.store.Log)),
	}
	copy(m.Log, u.store.Log)

	for _, r := range remotes {
		takeRemoteCreds := false
		merged, err := mergeLogs(u, m.Log, r.Log)
		if err != nil {
			return m, err
		}

		if len(u.master) == 0 && len(r.Params.Master) == 0 {
			if !bytes.Equal(u.key, r.Params.Keys[r.Params.User]) {
				// Key has changed
				// Either the salt has changed or the password has changed, either
				// way we'll try to determine who has the latest updates in the log
				// to see which credential set we should keep.
				lastTimeLocal := m.Log[len(m.Log)-1].Time
				lastTimeRemote := r.Log[len(r.Log)-1].Time

				if lastTimeLocal < lastTimeRemote {
					takeRemoteCreds = true
				} else if lastTimeLocal == lastTimeRemote {
					infoColor.Println("remote %q has different credentials!")
					takeRemoteCreds, err = u.getYesNo("use remote credentials from now on?")
					if err != nil {
						return m, err
					}
				}
			}
		} else if len(u.master) != len(r.Params.Master) {
			// There's been a single->multi or multi->single change
			// We have to instantiate the merged blob and check user counts
			db := &txlogs.DB{Log: merged}
			store := blobformat.Blobs{DB: db}
			users, err := store.Users()
			if err != nil {
				return m, err
			}

			if len(users) == 0 && len(u.master) != 0 {
				// There's no users remaining in the merged DB, and the local
				// file is multi, meaning that the remote wins the merge
				// and we become a single-user file
				infoColor.Println("local file converted to single-user file")
				takeRemoteCreds = true
			} else if len(users) != 0 && len(u.master) == 0 {
				// There's users remaining in the merged DB, and the local file
				// is not multi, meaning that the remote wins the merge
				// and we become a multi-user file.
				infoColor.Println("local file converted to multi-user file")
				takeRemoteCreds = true
			}
		} else if !bytes.Equal(u.master, r.Params.Master) {
			// There's been a master change in a multi multi

			localStore := blobformat.Blobs{&txlogs.DB{Log: m.Log}}
			mergedStore := blobformat.Blobs{&txlogs.DB{Log: merged}}
			remoteStore := blobformat.Blobs{&txlogs.DB{Log: merged}}
			userUUID, localUser, err := localStore.FindUser(m.User)
			if err != nil {
				return m, err
			}

			mergedUser, err := mergedStore.Find(userUUID)
			if err != nil {
				return m, err
			}

			if localUser == nil {
				return m, errors.New("could not find current user entry in local user db")
			} else if mergedUser == nil {
				return m, errors.New("could not find current user entry in merged user db")
			}

			// Figure out if the local mkey is in the merged database
			// to see which side wins. Whichever side loses may have invalid
			// users if they were not present for the rekey, find them
			// and warn that they will not work until they're re-passworded
			localWins := localUser[blobformat.KeyMKey] == mergedUser[blobformat.KeyMKey]
			localUsers, err := localStore.Users()
			if err != nil {
				return m, err
			}
			remoteUsers, err := remoteStore.Users()
			if err != nil {
				return m, err
			}

			if localWins {
				// Find remoteUsers not in local
				for remoteUUID, user := range remoteUsers {
					found := false
					for localUUID := range localUsers {
						if remoteUUID == localUUID {
							found = true
							break
						}
					}
					if !found {
						infoColor.Printf("user %q (from remote) was not present for a local rekey\n", user)
						infoColor.Println("use the rekey command to fix them")
					}
				}
			} else {
				takeRemoteCreds = true

				for localUUID, user := range localUsers {
					found := false
					for remoteUUID := range remoteUsers {
						if remoteUUID == localUUID {
							found = true
							break
						}
					}
					if !found {
						infoColor.Printf("user %q (from local) was not present for a remote rekey\n", user)
						infoColor.Println("use the rekey command to fix them")
					}
				}
			}
		}

		if takeRemoteCreds {
			infoColor.Printf("local credentials updated from remote: %q\n", r.Name)
			m.User, m.Pass = r.Creds.User, r.Creds.Pass
			m.Key, m.Salt = r.Params.Keys[r.Params.User], r.Params.Salts[r.Params.User]
			m.Master, m.IVM = r.Params.Master, r.Params.IVM
		}

		m.Log = merged
	}

	return m, nil
}

var syncNoCommonAncestryWarning = `WARNING: There is no common ancestry between
the local and the remote file. What this probably means is that the wrong
file is in the sync location, and proceeding would mean that both files become
merged into one instead of remaining separate.`

func mergeLogs(u *uiContext, local []txlogs.Tx, remote []txlogs.Tx) ([]txlogs.Tx, error) {
	if len(remote) == 0 {
		return local, nil
	}

	var c []txlogs.Tx
	var conflicts []txlogs.Conflict
	for {
		c, conflicts = txlogs.Merge(local, remote, conflicts)

		if len(conflicts) == 0 {
			break
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
