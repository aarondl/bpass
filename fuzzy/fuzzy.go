// Package fuzzy performs fuzzy searching with some special case considerations
package fuzzy

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Match performs a fuzzy match on a string s, searching for the characters
// given in search.
//
// Lowercase letters match both upper and lowercase letters, where uppercase
// matches only uppercase letters.
func Match(s string, search string) bool {
	slen := len(s)
	searchLen := len(search)

	if searchLen > slen {
		return false
	}
	if searchLen == slen && s == search {
		return true
	}

	// Use for range to get the unicode semantics
Search:
	for _, searchChar := range search {
		for i, char := range s {
			if searchChar == char || searchChar == unicode.ToLower(char) {
				s = s[utf8.RuneLen(char)+i:]
				continue Search
			}
		}
		return false
	}

	return true
}

// MatchFold does a case insensitive fuzzy match.
func MatchFold(s string, search string) bool {
	return Match(strings.ToLower(s), strings.ToLower(search))
}
