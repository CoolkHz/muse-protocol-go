package muse

import "testing"

func TestParseCookies(t *testing.T) {
	cases := map[string]map[string]string{
		"hatch_sess=abc; hatch_gw=x=y":                       {"hatch_sess": "abc", "hatch_gw": "x=y"},
		`{"hatch_sess":"abc","hatch_vml":"v"}`:               {"hatch_sess": "abc", "hatch_vml": "v"},
		`[{"name":"hatch_sess","value":"abc","domain":"x"}]`: {"hatch_sess": "abc"},
		"Cookie: hatch_sess=abc":                             {"hatch_sess": "abc"},
		"hatch_sess\tabc\tmuse.ai\t/\nhatch_gw\tg\tmuse.ai":  {"hatch_sess": "abc", "hatch_gw": "g"},
	}
	for in, want := range cases {
		got := ParseCookies(in)
		if len(got) != len(want) {
			t.Errorf("%q: got %v want %v", in, got, want)
			continue
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%q: %s=%q want %q", in, k, got[k], v)
			}
		}
	}
}
