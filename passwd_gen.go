package main

import (
	"crypto/rand"

	"github.com/pkg/errors"
)

var (
	alphabetUppercase    = `ABCDEFGHIJKLMNOPQRSTUVWXYZ`
	alphabetLowercase    = `abcdefghijklmnopqrstuvwxyz`
	alphabetNumbers      = `0123456789`
	alphabetBasicSymbols = `!@#$%^&*`
	alphabetExtraSymbols = `()_+-=<>,.{}[]\|?/~"\'` + "`"
)

var (
	errPasswordImpossible = errors.New("password cannot be generated")
)

func genPassword(length, upper, lower, numbers, basic, extra int) (string, error) {
	needLen := 0
	for _, i := range []int{upper, lower, numbers, basic, extra} {
		if i > 0 {
			needLen += i
		}
	}

	if needLen > length {
		return "", errPasswordImpossible
	}

	randomPicks := length - needLen

	// offset is the offset in the password
	offset := 0
	// eOffset is the entropy offset
	eOffset := 0
	password := make([]byte, length)
	entropy := make([]byte, needLen+(randomPicks*2)+length)
	n, err := rand.Read(entropy)
	if err != nil {
		return "", err
	} else if n != len(entropy) {
		return "", errors.New("failed to generate enough entropy")
	}

	type pair struct {
		alphabet string
		num      int
	}

	pairs := make([]pair, 0, 5)
	if upper >= 0 {
		pairs = append(pairs, pair{alphabetUppercase, upper})
	}
	if lower >= 0 {
		pairs = append(pairs, pair{alphabetLowercase, lower})
	}
	if numbers >= 0 {
		pairs = append(pairs, pair{alphabetNumbers, numbers})
	}
	if basic >= 0 {
		pairs = append(pairs, pair{alphabetBasicSymbols, basic})
	}
	if extra >= 0 {
		pairs = append(pairs, pair{alphabetExtraSymbols, extra})
	}

	for _, p := range pairs {
		for i := p.num; i > 0; i-- {
			ln := byte(len(p.alphabet))
			password[offset] = p.alphabet[entropy[eOffset]%ln]
			offset++
			eOffset++
		}
	}

	if randomPicks > 0 && len(pairs) == 0 {
		return "", errPasswordImpossible
	}

	for i := randomPicks; i > 0; i-- {
		ln := byte(len(pairs))
		p := pairs[entropy[eOffset]%ln]
		eOffset++

		ln = byte(len(p.alphabet))
		password[offset] = p.alphabet[entropy[eOffset]%ln]
		offset++
		eOffset++
	}

	for i := 0; i < length; i++ {
		// swap i with
		swap := entropy[eOffset] % byte(length)
		password[i], password[swap] = password[swap], password[i]
		eOffset++
	}

	return string(password), nil
}
