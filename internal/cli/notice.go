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
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/pterm/pterm"
	"github.com/rs/zerolog/log"
)

// noticeWidth is the line width a notice is wrapped to inside its box.
const noticeWidth = 72

// noticePrinter shows the first X-SCANOSS-Notice of a run, once: in a box on
// a terminal, as one "NOTICE:" line otherwise. Nothing is shown while stderr
// carries JSON (--error-format json or --progress).
type noticePrinter struct {
	out  io.Writer
	tty  bool
	json func() bool
	once sync.Once
}

func (p *noticePrinter) show(text string) {
	p.once.Do(func() {
		if p.json() {
			return
		}
		if !p.tty {
			if _, err := fmt.Fprintf(p.out, "NOTICE: %s\n", strings.Join(strings.Fields(text), " ")); err != nil {
				log.Debug().Err(err).Msg("could not write the API notice")
			}
			return
		}
		box := pterm.DefaultBox.WithTitle("SCANOSS").WithWriter(p.out)
		box.Println(wrapNotice(text, noticeWidth))
	})
}

// wrapNotice wraps each line of text at width runes, breaking between words.
// A word longer than width stays whole on its own line.
func wrapNotice(text string, width int) string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		current := ""
		for _, word := range strings.Fields(line) {
			switch {
			case current == "":
				current = word
			case len([]rune(current))+1+len([]rune(word)) <= width:
				current += " " + word
			default:
				out = append(out, current)
				current = word
			}
		}
		if current != "" {
			out = append(out, current)
		}
	}
	return strings.Join(out, "\n")
}
