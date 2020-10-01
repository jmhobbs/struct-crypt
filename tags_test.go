package crypt

import "testing"

func Test_TagParse(t *testing.T) {
	examples := []struct {
		Tag    string
		Target string
		Clear  bool
	}{
		{
			"example",
			"example",
			true,
		},
		{
			"example,preserve",
			"example",
			false,
		},
		{
			"example,preserve,unsupported",
			"example,preserve,unsupported",
			true,
		},
	}

	for _, e := range examples {
		t.Run(e.Tag, func(t *testing.T) {
			target, clear := parseTagValue(e.Tag)
			if target != e.Target {
				t.Errorf("target not correct\nexpected: %q\n  actual: %q", e.Target, target)
			}
			if clear != e.Clear {
				t.Errorf("clear not correct\nexpected: %v\n  actual: %v", e.Clear, clear)
			}
		})
	}
}
