package cardmatch

// The parse memo keeps, across processes, the value loadYAML built from each
// card file content. A scan loads the cards of the language it scans, and on
// a small tree their YAML parse is a large share of its CPU; a mining run
// starts one process per component against the same cards. Each hit decodes a
// new value, as each parse built one.

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"sync"

	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/parsememo"
)

// parseMemos holds one memo per cards language (cards/<language>/), so a scan
// reads and writes only the entries of the language it loads.
var parseMemos = struct {
	sync.Mutex
	byName map[string]*parsememo.Memo
}{byName: map[string]*parsememo.Memo{}}

func parseMemoFor(path string) *parsememo.Memo {
	name := "cards-match"
	if language := config.CardsLanguage(path); language != "" {
		name += "-" + language
	}
	parseMemos.Lock()
	defer parseMemos.Unlock()
	memo := parseMemos.byName[name]
	if memo == nil {
		memo = parsememo.New(name)
		parseMemos.byName[name] = memo
	}
	return memo
}

// SaveMemo writes the card files this process parsed into the memo, for the
// scans after this one.
func SaveMemo() error {
	parseMemos.Lock()
	defer parseMemos.Unlock()
	errs := make([]error, 0, len(parseMemos.byName))
	for _, memo := range parseMemos.byName {
		errs = append(errs, memo.Save())
	}
	return errors.Join(errs...)
}

// memoYAML is parseYAML through memo.
func memoYAML(memo *parsememo.Memo, data []byte) (any, error) {
	key := sha256.Sum256(data)
	if stored, ok := memo.Get(key); ok {
		r := parsememo.NewReader(stored)
		if v := decodeYAMLValue(r); r.Done() {
			return v, nil
		}
	}
	v, err := parseYAML(data)
	if err != nil {
		return nil, err
	}
	var w parsememo.Writer
	if encodeYAMLValue(&w, v) == nil {
		memo.Put(key, w.Bytes())
	}
	return v, nil
}

var errMemoUnsupported = errors.New("cardmatch: value type not supported by the parse memo")

// Value tags, one per type buildNode returns.
const (
	memoNil byte = iota
	memoString
	memoFalse
	memoTrue
	memoInt
	memoBigInt
	memoFloat
	memoList
	memoMap
)

func encodeYAMLValue(w *parsememo.Writer, v any) error {
	switch v := v.(type) {
	case nil:
		w.Byte(memoNil)
	case string:
		w.Byte(memoString)
		w.String(v)
	case bool:
		if v {
			w.Byte(memoTrue)
		} else {
			w.Byte(memoFalse)
		}
	case int64:
		w.Byte(memoInt)
		w.Varint(v)
	case *big.Int:
		if v == nil {
			return errMemoUnsupported
		}
		w.Byte(memoBigInt)
		w.String(v.String())
	case float64:
		w.Byte(memoFloat)
		w.Float(v)
	case []any:
		return encodeYAMLList(w, v)
	case *OMap:
		return encodeYAMLMap(w, v)
	default:
		return errMemoUnsupported
	}
	return nil
}

func encodeYAMLList(w *parsememo.Writer, v []any) error {
	// buildNode never returns a nil list.
	if v == nil {
		return errMemoUnsupported
	}
	w.Byte(memoList)
	w.Uvarint(uint64(len(v)))
	for _, item := range v {
		if err := encodeYAMLValue(w, item); err != nil {
			return err
		}
	}
	return nil
}

func encodeYAMLMap(w *parsememo.Writer, v *OMap) error {
	// An empty mapping has nil Keys and Vals, a non-empty one neither.
	if v == nil || len(v.Keys) != len(v.Vals) || (len(v.Keys) == 0) != (v.Keys == nil) || (v.Keys == nil) != (v.Vals == nil) {
		return errMemoUnsupported
	}
	w.Byte(memoMap)
	w.Uvarint(uint64(len(v.Keys)))
	for i := range v.Keys {
		if err := encodeYAMLValue(w, v.Keys[i]); err != nil {
			return err
		}
		if err := encodeYAMLValue(w, v.Vals[i]); err != nil {
			return err
		}
	}
	return nil
}

func decodeYAMLValue(r *parsememo.Reader) any {
	switch r.Byte() {
	case memoNil:
		return nil
	case memoString:
		return r.String()
	case memoFalse:
		return false
	case memoTrue:
		return true
	case memoInt:
		return r.Varint()
	case memoBigInt:
		n, ok := new(big.Int).SetString(r.String(), 10)
		if !ok {
			r.Fail()
		}
		return n
	case memoFloat:
		return r.Float()
	case memoList:
		out := make([]any, r.Count())
		for i := range out {
			out[i] = decodeYAMLValue(r)
		}
		return out
	case memoMap:
		m := &OMap{}
		if n := r.Count(); n > 0 {
			m.Keys, m.Vals = make([]any, n), make([]any, n)
			for i := range n {
				m.Keys[i] = decodeYAMLValue(r)
				m.Vals[i] = decodeYAMLValue(r)
			}
		}
		return m
	default:
		r.Fail()
		return nil
	}
}
