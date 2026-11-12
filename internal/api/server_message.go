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

package apiclient

import (
	"bytes"
	"encoding/json"
	"mime"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Bounds of an error answer: how much of the body is read, and how much of
// its message is shown.
const (
	maxErrorBodyBytes      = 64 << 10
	maxServerMessageRunes  = 1000
	maxServerMessageLines  = 10
	serverMessageTruncated = "…"
)

// serverMessage returns the human-readable message of an error answer, or ""
// when it has none: error.message of the SCANOSS API's JSON error body
// ({"status":"error","error":{"code":…,"message":…}}, with the code appended
// in parentheses), a JSON body whose "error" or "message" is a string, or a
// text/plain body. The text is sanitized for a terminal.
func serverMessage(header http.Header, body []byte) string {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return ""
	}
	if trimmed[0] == '{' {
		return sanitizeServerMessage(jsonErrorMessage(trimmed))
	}
	mediaType, _, err := mime.ParseMediaType(header.Get("Content-Type"))
	if header.Get("Content-Type") != "" && (err != nil || mediaType != "text/plain") {
		return "" // an HTML error page or some other format says nothing readable
	}
	return sanitizeServerMessage(string(trimmed))
}

func jsonErrorMessage(body []byte) string {
	var doc struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return ""
	}
	var structured struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(doc.Error, &structured) == nil && structured.Message != "" {
		if structured.Code != "" {
			return structured.Message + " (" + structured.Code + ")"
		}
		return structured.Message
	}
	var plain string
	if json.Unmarshal(doc.Error, &plain) == nil && plain != "" {
		return plain
	}
	return doc.Message
}

// sanitizeServerMessage keeps the printable text of a server message: other
// control characters (escape sequences included) are dropped, tabs become
// spaces, lines are trimmed, at most maxServerMessageLines non-empty lines
// and maxServerMessageRunes runes are kept.
func sanitizeServerMessage(text string) string {
	if !utf8.ValidString(text) {
		text = strings.ToValidUTF8(text, "")
	}
	lines := make([]string, 0, maxServerMessageLines)
	truncated := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.Map(func(r rune) rune {
			switch {
			case r == '\t':
				return ' '
			case unicode.IsControl(r), r == ' ', r == ' ', unicode.Is(unicode.Cf, r):
				return -1
			}
			return r
		}, line))
		if line == "" {
			continue
		}
		if len(lines) == maxServerMessageLines {
			truncated = true
			break
		}
		lines = append(lines, line)
	}
	out := strings.Join(lines, "\n")
	if runes := []rune(out); len(runes) > maxServerMessageRunes {
		out, truncated = strings.TrimSpace(string(runes[:maxServerMessageRunes])), true
	}
	if truncated && out != "" {
		out += serverMessageTruncated
	}
	return out
}
