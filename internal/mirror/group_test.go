package mirror

import "testing"

func TestGroupKey(t *testing.T) {
	for _, c := range []struct{ name, want string }{
		{"tricolor.ru", "tricolor.ru"},
		{"a.b.tricolor.ru", "tricolor.ru"},
		{"*.tricolor.ru", "tricolor.ru"},
		{"*.rlw.gov.ru", "rlw.gov.ru"},
		{"adminpdd.transport.gov.spb.ru", "gov.spb.ru"},
		{"gov.ru", "gov.ru"},
		{"xn--d1aqf.xn--p1ai", "xn--d1aqf.xn--p1ai"},
		{"a.xn--d1aqf.xn--p1ai", "xn--d1aqf.xn--p1ai"},
		{"ru", "ru"},
	} {
		if got := GroupKey(c.name); got != c.want {
			t.Errorf("GroupKey(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}
