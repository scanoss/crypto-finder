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
	"net/http"
	"sync/atomic"
)

// headerNotice is the response header the SCANOSS API uses to tell the user
// something without failing the request, such as a coming end of support.
const headerNotice = "SCANOSS-Notice"

// noticeHandler receives the text of every SCANOSS-Notice header.
var noticeHandler atomic.Pointer[func(string)]

// SetNoticeHandler sets the function that receives the sanitized text of
// every SCANOSS-Notice header an API response carries, on any request of
// any Client. Nil, the default, ignores notices. The handler may be called
// many times and from several goroutines; showing the notice once is its
// job.
func SetNoticeHandler(handler func(string)) {
	if handler == nil {
		noticeHandler.Store(nil)
		return
	}
	noticeHandler.Store(&handler)
}

// noticeTransport passes SCANOSS-Notice headers to the notice handler.
type noticeTransport struct {
	base http.RoundTripper
}

func (t noticeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if resp != nil {
		reportNotice(resp.Header)
	}
	return resp, err
}

func reportNotice(header http.Header) {
	handler := noticeHandler.Load()
	if handler == nil {
		return
	}
	if text := sanitizeServerMessage(header.Get(headerNotice)); text != "" {
		(*handler)(text)
	}
}

// withNotice returns a copy of hc whose responses go through noticeTransport.
func withNotice(hc *http.Client) *http.Client {
	wrapped := *hc
	base := hc.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	wrapped.Transport = noticeTransport{base: base}
	return &wrapped
}
