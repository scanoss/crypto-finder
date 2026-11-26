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

package rules

import (
	"errors"

	"github.com/scanoss/crypto-finder/internal/parsememo"
)

// cardsMemo holds, across processes, what ReadCardsRules returned for each
// card file content parsed without error. Every scan reads the whole ruleset
// (the rule filter, the parameterCondition gate and the crypto metadata passes
// cover every language), so without it each scan parses every card file. A
// hit returns the rules the parse returned, and every pass, the validation
// included, reads them as before.
var cardsMemo = parsememo.New("cards-rules")

// SaveCardsMemo writes the card files this process parsed into the memo, for
// the scans after this one.
func SaveCardsMemo() error {
	return cardsMemo.Save()
}

func memoCardsRules(key parsememo.Key) ([]CardsRule, bool) {
	data, ok := cardsMemo.Get(key)
	if !ok {
		return nil, false
	}
	r := parsememo.NewReader(data)
	found := decodeCardsRules(r)
	return found, r.Done()
}

func storeCardsRules(key parsememo.Key, found []CardsRule) {
	var w parsememo.Writer
	if encodeCardsRules(&w, found) == nil {
		cardsMemo.Put(key, w.Bytes())
	}
}

var errCardsMemoUnsupported = errors.New("cards memo: value type not supported")

// Value tags. Nil and empty lists and maps are distinct values here, as they
// are in what the YAML decoder returns.
const (
	tagNil byte = iota
	tagString
	tagFalse
	tagTrue
	tagInt
	tagFloat
	tagList
	tagMap
	tagNilList
	tagNilMap
)

func encodeCardsRules(w *parsememo.Writer, found []CardsRule) error {
	if found == nil {
		w.Uvarint(0)
		return nil
	}
	w.Uvarint(uint64(len(found)) + 1)
	for i := range found {
		r := &found[i]
		for _, s := range []string{r.ID, r.Severity, r.Message, r.PURL, r.Pending} {
			w.String(s)
		}
		if err := encodeValue(w, r.Crypto); err != nil {
			return err
		}
		if r.Conditioned == nil {
			w.Byte(0)
			continue
		}
		w.Byte(1)
		w.Strings(r.Conditioned.Symbols)
		w.Strings(r.Conditioned.CaptureNames)
		w.Strings(r.Conditioned.CaptureBinders)
	}
	return nil
}

// encodeValue writes the values the YAML decoder returns for a document
// without tags or timestamps. Anything else leaves the card file out of the
// memo, and every process parses it.
func encodeValue(w *parsememo.Writer, v any) error {
	switch v := v.(type) {
	case nil:
		w.Byte(tagNil)
	case string:
		w.Byte(tagString)
		w.String(v)
	case bool:
		if v {
			w.Byte(tagTrue)
		} else {
			w.Byte(tagFalse)
		}
	case int:
		w.Byte(tagInt)
		w.Varint(int64(v))
	case float64:
		w.Byte(tagFloat)
		w.Float(v)
	case []any:
		if v == nil {
			w.Byte(tagNilList)
			return nil
		}
		w.Byte(tagList)
		w.Uvarint(uint64(len(v)))
		for _, item := range v {
			if err := encodeValue(w, item); err != nil {
				return err
			}
		}
	case map[string]any:
		if v == nil {
			w.Byte(tagNilMap)
			return nil
		}
		w.Byte(tagMap)
		w.Uvarint(uint64(len(v)))
		for key, item := range v {
			w.String(key)
			if err := encodeValue(w, item); err != nil {
				return err
			}
		}
	default:
		return errCardsMemoUnsupported
	}
	return nil
}

func decodeCardsRules(r *parsememo.Reader) []CardsRule {
	n := r.Uvarint()
	if n == 0 {
		return nil
	}
	out := make([]CardsRule, r.Bound(n-1))
	for i := range out {
		rule := &out[i]
		rule.ID, rule.Severity, rule.Message, rule.PURL, rule.Pending = r.String(), r.String(), r.String(), r.String(), r.String()
		crypto, ok := decodeValue(r).(map[string]any)
		if !ok {
			r.Fail()
		}
		rule.Crypto = crypto
		switch r.Byte() {
		case 0:
		case 1:
			rule.Conditioned = &CardsConditioned{Symbols: r.Strings(), CaptureNames: r.Strings(), CaptureBinders: r.Strings()}
		default:
			r.Fail()
		}
	}
	return out
}

func decodeValue(r *parsememo.Reader) any {
	switch r.Byte() {
	case tagNil:
		return nil
	case tagString:
		return r.String()
	case tagFalse:
		return false
	case tagTrue:
		return true
	case tagInt:
		return int(r.Varint())
	case tagFloat:
		return r.Float()
	case tagNilList:
		return []any(nil)
	case tagNilMap:
		return map[string]any(nil)
	case tagList:
		out := make([]any, r.Count())
		for i := range out {
			out[i] = decodeValue(r)
		}
		return out
	case tagMap:
		n := r.Count()
		out := make(map[string]any, n)
		for range n {
			key := r.String()
			out[key] = decodeValue(r)
		}
		return out
	default:
		r.Fail()
		return nil
	}
}
