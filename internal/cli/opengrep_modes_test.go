// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package cli

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/scanner"
)

func envOf(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func TestResolveOpengrepMode(t *testing.T) {
	cases := []struct {
		name    string
		flagSet bool
		flag    string
		env     map[string]string
		want    scanner.OpengrepMode
		wantErr bool
	}{
		{name: "default", flag: "core", want: scanner.OpengrepModeCore},
		{name: "flag cli opts out", flagSet: true, flag: "cli", want: scanner.OpengrepModeCLI},
		{name: "flag core", flagSet: true, flag: "core", want: scanner.OpengrepModeCore},
		{name: "env cli opts out", flag: "core", env: map[string]string{opengrepModeEnv: "CLI"}, want: scanner.OpengrepModeCLI},
		{name: "env core", flag: "core", env: map[string]string{opengrepModeEnv: "CORE"}, want: scanner.OpengrepModeCore},
		{name: "flag wins over env", flagSet: true, flag: "cli", env: map[string]string{opengrepModeEnv: "core"}, want: scanner.OpengrepModeCLI},
		{name: "flag core wins over env cli", flagSet: true, flag: "core", env: map[string]string{opengrepModeEnv: "cli"}, want: scanner.OpengrepModeCore},
		{name: "blank env", flag: "core", env: map[string]string{opengrepModeEnv: " "}, want: scanner.OpengrepModeCore},
		{name: "bad flag", flagSet: true, flag: "fast", wantErr: true},
		{name: "bad env", env: map[string]string{opengrepModeEnv: "daemon"}, wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveOpengrepMode(c.flagSet, c.flag, envOf(c.env))
			if (err != nil) != c.wantErr || got != c.want {
				t.Errorf("resolveOpengrepMode = %v, %v; want %v, error %v", got, err, c.want, c.wantErr)
			}
		})
	}
}

func TestOpengrepModeExplicit(t *testing.T) {
	if opengrepModeExplicit(false, envOf(nil)) {
		t.Error("default mode reported as explicit")
	}
	if opengrepModeExplicit(false, envOf(map[string]string{opengrepModeEnv: " "})) {
		t.Error("blank env reported as explicit")
	}
	if !opengrepModeExplicit(true, envOf(nil)) {
		t.Error("flag not reported as explicit")
	}
	if !opengrepModeExplicit(false, envOf(map[string]string{opengrepModeEnv: "cli"})) {
		t.Error("env not reported as explicit")
	}
}

func TestResolveRulePrefilter(t *testing.T) {
	cases := []struct {
		name    string
		flagSet bool
		flag    string
		env     map[string]string
		want    scanner.RulePrefilter
		wantErr bool
	}{
		{name: "default", flag: "imports", want: scanner.RulePrefilterImports},
		{name: "flag off opts out", flagSet: true, flag: "off", want: scanner.RulePrefilterOff},
		{name: "flag imports", flagSet: true, flag: "imports", want: scanner.RulePrefilterImports},
		{name: "env off opts out", flag: "imports", env: map[string]string{rulePrefilterEnv: "off"}, want: scanner.RulePrefilterOff},
		{name: "env imports", flag: "imports", env: map[string]string{rulePrefilterEnv: "imports"}, want: scanner.RulePrefilterImports},
		{name: "blank env", flag: "imports", env: map[string]string{rulePrefilterEnv: " "}, want: scanner.RulePrefilterImports},
		{name: "flag wins over env", flagSet: true, flag: "off", env: map[string]string{rulePrefilterEnv: "imports"}, want: scanner.RulePrefilterOff},
		{name: "flag imports wins over env off", flagSet: true, flag: "imports", env: map[string]string{rulePrefilterEnv: "off"}, want: scanner.RulePrefilterImports},
		{name: "bad value", flagSet: true, flag: "purl", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveRulePrefilter(c.flagSet, c.flag, envOf(c.env))
			if (err != nil) != c.wantErr || got != c.want {
				t.Errorf("resolveRulePrefilter = %v, %v; want %v, error %v", got, err, c.want, c.wantErr)
			}
		})
	}
}

func TestRulePrefilterExplicit(t *testing.T) {
	if rulePrefilterExplicit(false, envOf(nil)) {
		t.Error("the default is not explicit")
	}
	if !rulePrefilterExplicit(true, envOf(nil)) {
		t.Error("the flag is explicit")
	}
	if !rulePrefilterExplicit(false, envOf(map[string]string{rulePrefilterEnv: "off"})) {
		t.Error("the variable is explicit")
	}
	if rulePrefilterExplicit(false, envOf(map[string]string{rulePrefilterEnv: " "})) {
		t.Error("a blank variable is not explicit")
	}
}

func TestResolveNoRemoteFilter(t *testing.T) {
	cases := []struct {
		name    string
		flagSet bool
		flag    bool
		env     map[string]string
		want    bool
		wantErr bool
	}{
		{name: "default"},
		{name: "flag", flagSet: true, flag: true, want: true},
		{name: "flag false wins over env", flagSet: true, flag: false, env: map[string]string{noRemoteFilterEnv: "1"}, want: false},
		{name: "env 1", env: map[string]string{noRemoteFilterEnv: "1"}, want: true},
		{name: "env true", env: map[string]string{noRemoteFilterEnv: "true"}, want: true},
		{name: "env 0", env: map[string]string{noRemoteFilterEnv: "0"}, want: false},
		{name: "blank env", env: map[string]string{noRemoteFilterEnv: " "}, want: false},
		{name: "bad env", env: map[string]string{noRemoteFilterEnv: "yes please"}, wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveNoRemoteFilter(c.flagSet, c.flag, envOf(c.env))
			if (err != nil) != c.wantErr || got != c.want {
				t.Errorf("resolveNoRemoteFilter = %v, %v; want %v, error %v", got, err, c.want, c.wantErr)
			}
		})
	}
}
