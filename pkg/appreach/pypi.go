// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"regexp"
	"strconv"
	"strings"

	pkgpurl "github.com/scanoss/reach/purl"
)

// PyPI request spelling. A Python client names a dependency by the name and
// version its lock or environment writes, which are not always the spelling
// the miner stored the release under (PyPI's): Django_Rest_Framework is
// django-rest-framework (PEP 503), 1.0.0-RC1 is 1.0.0rc1 (PEP 440). The
// request is read in the canonical spelling, so one release is one component.

// pep440 is the PEP 440 version grammar (packaging's VERSION_PATTERN),
// matched case-insensitively against a trimmed version.
var pep440 = regexp.MustCompile(`(?i)^v?` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?` +
	`(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?` +
	`(?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?` +
	`(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`)

// pep440Version is a parsed PEP 440 version in its normal form's parts.
type pep440Version struct {
	epoch   string
	release []string
	suffix  string // pre-release, post-release, dev-release and local, normalized
}

func parsePEP440(version string) (pep440Version, bool) {
	m := pep440.FindStringSubmatch(strings.TrimSpace(version))
	if m == nil {
		return pep440Version{}, false
	}
	group := func(name string) string { return m[pep440.SubexpIndex(name)] }
	number := func(s string) string {
		if s == "" {
			return "0"
		}
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return strings.TrimLeft(s, "0")
		}
		return strconv.FormatUint(n, 10)
	}
	var v pep440Version
	if e := group("epoch"); e != "" && number(e) != "0" {
		v.epoch = number(e) + "!"
	}
	for _, part := range strings.Split(group("release"), ".") {
		v.release = append(v.release, number(part))
	}
	var suffix strings.Builder
	if group("pre") != "" {
		label := strings.ToLower(group("pre_l"))
		switch label {
		case "alpha":
			label = "a"
		case "beta":
			label = "b"
		case "c", "pre", "preview":
			label = "rc"
		}
		suffix.WriteString(label + number(group("pre_n")))
	}
	if group("post") != "" {
		n := group("post_n1")
		if n == "" {
			n = group("post_n2")
		}
		suffix.WriteString(".post" + number(n))
	}
	if group("dev") != "" {
		suffix.WriteString(".dev" + number(group("dev_n")))
	}
	if local := group("local"); local != "" {
		suffix.WriteString("+" + strings.ToLower(strings.NewReplacer("-", ".", "_", ".").Replace(local)))
	}
	v.suffix = suffix.String()
	return v, true
}

// PyPIVersion is version in its PEP 440 normal form (1.0.0-RC1 -> 1.0.0rc1,
// v2.0.post -> 2.0.post0, 01.02 -> 1.2). A version PEP 440 cannot parse (a
// legacy release) is returned trimmed, as written.
func PyPIVersion(version string) string {
	v, ok := parsePEP440(version)
	if !ok {
		return strings.TrimSpace(version)
	}
	return v.epoch + strings.Join(v.release, ".") + v.suffix
}

// PyPIVersionsEqual reports whether two versions name one release under PEP
// 440's comparison, where the release's trailing zeros do not count (1.0 ==
// 1.0.0). Versions PEP 440 cannot parse are equal only as written.
func PyPIVersionsEqual(a, b string) bool {
	return pyPIVersionKey(a) == pyPIVersionKey(b)
}

func pyPIVersionKey(version string) string {
	v, ok := parsePEP440(version)
	if !ok {
		return "legacy:" + strings.TrimSpace(version)
	}
	release := v.release
	for len(release) > 1 && release[len(release)-1] == "0" {
		release = release[:len(release)-1]
	}
	return v.epoch + strings.Join(release, ".") + v.suffix
}

// canonicalPyPIName is a PyPI distribution name as the miner stores it (PEP
// 503: lower case, runs of -, _ and . as one -).
func canonicalPyPIName(name string) string {
	return pkgpurl.PyPIName(name)
}
