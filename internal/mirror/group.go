package mirror

import "strings"

// groupSuffixes are second-level labels that many unrelated organisations sit
// under, so a name below one is grouped by its last three labels instead of
// two. Keep this in step with SUFFIXES in site/index.html: the commit message
// and the site should agree on what a registrable domain is.
var groupSuffixes = map[string]bool{
	"gov.ru": true, "edu.ru": true, "ac.ru": true, "mil.ru": true, "int.ru": true,
	"com.ru": true, "net.ru": true, "org.ru": true, "pp.ru": true,
	"msk.ru": true, "spb.ru": true, "msk.su": true, "spb.su": true, "nov.ru": true,
	"ru.net": true, "com.by": true, "com.kz": true,
	"org.xn--p1ai": true, "com.xn--p1ai": true, "net.xn--p1ai": true,
}

// GroupKey returns the registrable domain a name is grouped under: the last two
// labels, or three when the last two are one of groupSuffixes. A leading
// wildcard label is ignored, so *.example.ru groups with example.ru.
func GroupKey(name string) string {
	name = strings.TrimPrefix(name, "*.")
	labels := strings.Split(name, ".")
	if len(labels) <= 2 {
		return name
	}
	two := strings.Join(labels[len(labels)-2:], ".")
	if groupSuffixes[two] {
		return strings.Join(labels[len(labels)-3:], ".")
	}
	return two
}
