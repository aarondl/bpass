package main

import (
	"strings"
	"testing"
	"unicode"
)

func TestGenPasswd(t *testing.T) {
	t.Parallel()

	p, err := genPassword(10, 0, 0, 0, 0, 0)
	if err != nil {
		t.Error(err)
	}
	if len(p) != 10 {
		t.Error("it should be 10 characters long")
	}

	p, err = genPassword(10, 1, 1, 1, 1, 1)
	if err != nil {
		t.Error(err)
	}
	if len(p) != 10 {
		t.Error("it should be 10 characters long")
	}
	if !strings.ContainsAny(p, alphabetUppercase) {
		t.Error("must contain uppercase:", p)
	}
	if !strings.ContainsAny(p, alphabetLowercase) {
		t.Error("must contain lowercase:", p)
	}
	if !strings.ContainsAny(p, alphabetNumbers) {
		t.Error("must contain numbers:", p)
	}
	if !strings.ContainsAny(p, alphabetBasicSymbols) {
		t.Error("must contain basic symbols:", p)
	}
	if !strings.ContainsAny(p, alphabetExtraSymbols) {
		t.Error("must contain extra symbols", p)
	}

	p, err = genPassword(10, 0, -1, -1, -1, -1)
	if err != nil {
		t.Error(err)
	}
	if len(p) != 10 {
		t.Error("it should be 10 characters long")
	}
	for _, c := range p {
		if !unicode.IsUpper(c) {
			t.Error("it should all be uppercase:", p)
		}
	}
}
