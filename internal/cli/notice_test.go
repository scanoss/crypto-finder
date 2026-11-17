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
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestNoticeShownOncePerRun(t *testing.T) {
	var out bytes.Buffer
	p := &noticePrinter{out: &out, json: func() bool { return false }}

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.show("crypto-finder 0.54 stops working on 2026-12-15")
		}()
	}
	wg.Wait()

	if got := out.String(); got != "NOTICE: crypto-finder 0.54 stops working on 2026-12-15\n" {
		t.Errorf("output = %q, want one NOTICE line", got)
	}
}

func TestNoticeBoxOnTerminal(t *testing.T) {
	var out bytes.Buffer
	p := &noticePrinter{out: &out, tty: true, json: func() bool { return false }}
	p.show("update now")

	got := out.String()
	if !strings.Contains(got, "SCANOSS") || !strings.Contains(got, "update now") {
		t.Errorf("box = %q", got)
	}
	if strings.Contains(got, "NOTICE:") {
		t.Errorf("terminal output used the plain line: %q", got)
	}
}

func TestNoticeSilentWhileStderrIsJSON(t *testing.T) {
	var out bytes.Buffer
	p := &noticePrinter{out: &out, tty: true, json: func() bool { return true }}
	p.show("update now")
	if out.Len() != 0 {
		t.Errorf("output in JSON mode = %q", out.String())
	}
}

func TestNoticeMultiLineIsOneLineOffTerminal(t *testing.T) {
	var out bytes.Buffer
	p := &noticePrinter{out: &out, json: func() bool { return false }}
	p.show("first line\nsecond line")
	if got := out.String(); got != "NOTICE: first line second line\n" {
		t.Errorf("output = %q", got)
	}
}

func TestWrapNotice(t *testing.T) {
	tests := []struct {
		text  string
		width int
		want  string
	}{
		{"short", 10, "short"},
		{"one two three four", 9, "one two\nthree\nfour"},
		{"averyveryverylongword x", 5, "averyveryverylongword\nx"},
		{"a\nb c", 10, "a\nb c"},
	}
	for _, tt := range tests {
		if got := wrapNotice(tt.text, tt.width); got != tt.want {
			t.Errorf("wrapNotice(%q, %d) = %q, want %q", tt.text, tt.width, got, tt.want)
		}
	}
}
