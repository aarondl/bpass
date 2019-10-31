package fuzzy

import "testing"

func TestFuzzy(t *testing.T) {
	tests := []struct {
		String string
		Search string
		Ok     bool
	}{
		// Happy cases
		{"", "", true},
		{"a", "", true},
		{"a", "a", true},
		{"abc", "abc", true},
		{"abc", "ac", true},
		{"abc", "c", true},

		// Sad cases
		{"", "a", false},
		{"a", "ab", false},
		{"a", "b", false},
		{"a", "A", false},

		// Searching for capital things when there is none should fail
		{"abc", "ABC", false},
		{"abc", "AC", false},
		{"abc", "C", false},

		// Searching for capital things when either lowercase or uppercase
		// should work
		{"ABC", "abc", true},
		{"ABC", "ac", true},
		{"ABC", "c", true},
		{"ABC", "ABC", true},
		{"ABC", "AC", true},
		{"ABC", "A", true},
	}

	for i, test := range tests {
		got := Match(test.String, test.Search)
		if got != test.Ok {
			t.Errorf("%d) (%q, %q) was not %t",
				i, test.String, test.Search, test.Ok)
		}
	}
}

func TestFuzzyFold(t *testing.T) {
	tests := []struct {
		String string
		Search string
		Ok     bool
	}{
		// Happy cases
		{"", "", true},
		{"a", "", true},
		{"a", "a", true},
		{"abc", "abc", true},
		{"abc", "ac", true},
		{"abc", "c", true},
		{"abc", "ABC", true},
		{"abc", "AC", true},
		{"abc", "C", true},
		{"ABC", "abc", true},
		{"ABC", "ac", true},
		{"ABC", "c", true},
		{"ABC", "ABC", true},
		{"ABC", "AC", true},
		{"ABC", "A", true},

		// Sad cases
		{"", "a", false},
		{"a", "b", false},
	}

	for i, test := range tests {
		got := MatchFold(test.String, test.Search)
		if got != test.Ok {
			t.Errorf("%d) (%q, %q) was not %t",
				i, test.String, test.Search, test.Ok)
		}
	}
}
