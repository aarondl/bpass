package crypt

import (
	"regexp"
	"testing"
)

func TestParamsValidateV1(t *testing.T) {
	t.Parallel()

	config, err := getVersion(1)
	if err != nil {
		t.Fatal(err)
	}

	shouldFail := []struct {
		Err string
		P   Params
	}{
		{
			Err: `one key`,
			P:   Params{},
		},
		{
			Err: `one salt`,
			P: Params{
				Keys: [][]byte{make([]byte, config.keySize)},
			},
		},
		{
			Err: `keys\[0\]`,
			P: Params{
				Keys:  [][]byte{make([]byte, 1)},
				Salts: [][]byte{make([]byte, config.keySize)},
			},
		},
		{
			Err: `salts\[0\]`,
			P: Params{
				Keys:  [][]byte{make([]byte, config.keySize)},
				Salts: [][]byte{make([]byte, 1)},
			},
		},
		{
			Err: `each user.*a key`,
			P: Params{
				NUsers: 2,
				Keys:   [][]byte{make([]byte, config.keySize)},
				Salts:  [][]byte{make([]byte, config.saltSize)},
			},
		},
		{
			Err: `each user.*a salt`,
			P: Params{
				NUsers: 2,
				Keys:   [][]byte{make([]byte, config.keySize), make([]byte, config.keySize)},
				Salts:  [][]byte{make([]byte, config.saltSize)},
			},
		},
		{
			Err: `user should be an index`,
			P: Params{
				NUsers: 2,
				User:   -1,
				Keys:   [][]byte{make([]byte, config.keySize), make([]byte, config.keySize)},
				Salts:  [][]byte{make([]byte, config.saltSize), make([]byte, config.saltSize)},
			},
		},
		{
			Err: `users must be the same length as nusers`,
			P: Params{
				NUsers: 2,
				Keys:   [][]byte{make([]byte, config.keySize), make([]byte, config.keySize)},
				Salts:  [][]byte{make([]byte, config.saltSize), make([]byte, config.saltSize)},
			},
		},
		{
			Err: `ivs must be the same length as nusers`,
			P: Params{
				NUsers: 2,
				Users:  [][]byte{make([]byte, 32), make([]byte, 32)},
				Keys:   [][]byte{make([]byte, config.keySize), make([]byte, config.keySize)},
				Salts:  [][]byte{make([]byte, config.saltSize), make([]byte, config.saltSize)},
			},
		},
		{
			Err: `ivs\[0\] must be \d+ bytes`,
			P: Params{
				NUsers: 2,
				Users:  [][]byte{make([]byte, 32), make([]byte, 32)},
				Keys:   [][]byte{make([]byte, config.keySize), make([]byte, config.keySize)},
				Salts:  [][]byte{make([]byte, config.saltSize), make([]byte, config.saltSize)},
				IVs:    [][]byte{make([]byte, 1), make([]byte, 1)},
			},
		},
		{
			Err: `mkeys must be the same length as nusers`,
			P: Params{
				NUsers: 2,
				Users:  [][]byte{make([]byte, 32), make([]byte, 32)},
				Keys:   [][]byte{make([]byte, config.keySize), make([]byte, config.keySize)},
				Salts:  [][]byte{make([]byte, config.saltSize), make([]byte, config.saltSize)},
				IVs:    [][]byte{make([]byte, config.blockSize), make([]byte, config.blockSize)},
			},
		},
		{
			Err: `mkeys\[0\] must be \d+ bytes`,
			P: Params{
				NUsers: 2,
				Users:  [][]byte{make([]byte, 32), make([]byte, 32)},
				Keys:   [][]byte{make([]byte, config.keySize), make([]byte, config.keySize)},
				Salts:  [][]byte{make([]byte, config.saltSize), make([]byte, config.saltSize)},
				IVs:    [][]byte{make([]byte, config.blockSize), make([]byte, config.blockSize)},
				MKeys:  [][]byte{make([]byte, 1), make([]byte, 1)},
			},
		},
	}

	shouldPass := []Params{
		{
			Keys:  [][]byte{make([]byte, config.keySize)},
			Salts: [][]byte{make([]byte, config.saltSize)},
		},
		{
			NUsers: 2,
			Users:  [][]byte{make([]byte, 32), make([]byte, 32)},
			Keys:   [][]byte{make([]byte, config.keySize), make([]byte, config.keySize)},
			Salts:  [][]byte{make([]byte, config.saltSize), make([]byte, config.saltSize)},
			IVs:    [][]byte{make([]byte, config.blockSize), make([]byte, config.blockSize)},
			MKeys:  [][]byte{make([]byte, config.keySize), make([]byte, config.keySize)},
		},
	}

	for i, test := range shouldFail {
		if err := test.P.validate(config); err == nil {
			t.Errorf("%d) expected fail but succeeded:\n%#v\n", i, test)
		} else {
			ok, compileErr := regexp.MatchString(test.Err, err.Error())
			if compileErr != nil {
				t.Fatalf("%d) failed to compile regexp: %q %v", i, test.Err, compileErr)
			}

			if !ok {
				t.Errorf("%d) expected error message not matched %q: %v", i, test.Err, err)
			}
		}
	}

	for i, test := range shouldPass {
		if err := test.validate(config); err != nil {
			t.Errorf("%d) expected pass but failed: %v\n%#v\n", i, err, test)
		}
	}
}
