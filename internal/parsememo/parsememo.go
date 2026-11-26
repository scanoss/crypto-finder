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

// Package parsememo keeps, across processes, what this binary parsed out of a
// file, by the file's content. A scan parses the same unchanged ruleset as the
// scan before it, and on a small tree that parse is most of its CPU; a mining
// run starts one process per component. A memo is bound to the binary that
// wrote it, so a build whose parser differs never reads another's entries.
//
// The memo is off until Enable: it writes what it parses in clear, so only a
// caller whose files are already on disk in clear turns it on (a local
// ruleset, never a leased one, which stays encrypted outside a scan).
//
// The memo stores bytes. Each user encodes its values with Writer and decodes
// them with Reader, and must encode every distinction its callers can observe
// (nil against empty, the concrete type of each value), or not store the value.
package parsememo

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/scanoss/crypto-finder/internal/config"
	"github.com/scanoss/crypto-finder/internal/utils"
)

// format changes whenever the file layout does.
const format = "crypto-finder parse memo 1\n"

var enabled atomic.Bool

// Enable turns every memo of this process on.
func Enable() { enabled.Store(true) }

// Key is the sha256 of a file's content.
type Key = [sha256.Size]byte

// Memo is one memo file, ~/.scanoss/crypto-finder/cache/<name>.memo.
type Memo struct {
	name string

	once   sync.Once
	path   string
	header []byte
	stored map[Key][]byte

	mu    sync.Mutex
	used  map[Key][]byte
	added bool
}

// New returns the memo named name. It reads nothing until it is first used.
func New(name string) *Memo {
	return &Memo{name: name}
}

func (m *Memo) load() {
	m.once.Do(func() {
		m.path, m.header = location(m.name)
		if m.path == "" {
			return
		}
		data, err := os.ReadFile(m.path)
		if err != nil || !bytes.HasPrefix(data, m.header) {
			return
		}
		if stored, err := decodeEntries(data[len(m.header):]); err == nil {
			m.stored = stored
		}
	})
}

// Get returns what Put stored under key, in this process or an earlier one.
func (m *Memo) Get(key Key) ([]byte, bool) {
	if !enabled.Load() {
		return nil, false
	}
	m.load()
	value, ok := m.stored[key]
	if ok {
		m.mu.Lock()
		m.use(key, value)
		m.mu.Unlock()
	}
	return value, ok
}

// Put stores value under key for the processes after this one.
func (m *Memo) Put(key Key, value []byte) {
	if !enabled.Load() {
		return
	}
	m.load()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.use(key, value)
	m.added = true
}

func (m *Memo) use(key Key, value []byte) {
	if m.used == nil {
		m.used = make(map[Key][]byte)
	}
	m.used[key] = value
}

// maxBytes bounds the entries a Save keeps from the file. Past it, the file
// keeps only what this process used: the entries of a ruleset no scan reads
// any more go then.
var maxBytes = 32 << 20

// Save adds the entries this process stored to the file, keeping those other
// scans wrote (the cards of another language). It writes nothing when no
// entry was stored, nor when this binary cannot be identified.
func (m *Memo) Save() error {
	if !enabled.Load() {
		return nil
	}
	m.load()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.path == "" || !m.added {
		return nil
	}
	entries := m.used
	if data, err := os.ReadFile(m.path); err == nil && bytes.HasPrefix(data, m.header) && len(data) <= maxBytes {
		if stored, err := decodeEntries(data[len(m.header):]); err == nil {
			for key, value := range m.used {
				stored[key] = value
			}
			entries = stored
		}
	}
	var out Writer
	out.buf.Write(m.header)
	out.Uvarint(uint64(len(entries)))
	for key, value := range entries {
		out.buf.Write(key[:])
		out.Uvarint(uint64(len(value)))
		out.buf.Write(value)
	}
	if err := writeFileAtomic(m.path, out.Bytes()); err != nil {
		return err
	}
	m.added = false
	return nil
}

// location is the memo file and the header that binds it to this binary, or
// "" when the binary cannot be identified.
func location(name string) (path string, header []byte) {
	exe, err := os.Executable()
	if err != nil {
		return "", nil
	}
	info, err := os.Stat(exe)
	if err != nil {
		return "", nil
	}
	cacheDir, err := config.GetCacheDir()
	if err != nil {
		return "", nil
	}
	identity := format + name + " " + strconv.FormatInt(info.Size(), 10) + " " + strconv.FormatInt(info.ModTime().UnixNano(), 10)
	if build, ok := debug.ReadBuildInfo(); ok {
		identity += " " + build.Main.Version
		for _, s := range build.Settings {
			if s.Key == "vcs.revision" || s.Key == "vcs.modified" {
				identity += " " + s.Value
			}
		}
	}
	sum := sha256.Sum256([]byte(identity))
	return filepath.Join(cacheDir, name+".memo"), append([]byte(format), sum[:]...)
}

func decodeEntries(data []byte) (map[Key][]byte, error) {
	r := NewReader(data)
	count := r.Uvarint()
	stored := make(map[Key][]byte, min(count, uint64(len(data))))
	for range count {
		var key Key
		copy(key[:], r.take(sha256.Size))
		stored[key] = r.take(r.Uvarint())
		if r.err != nil {
			return nil, r.err
		}
	}
	if !r.Done() {
		return nil, ErrCorrupt
	}
	return stored, nil
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("parsememo: %w", err)
	}
	_, err = tmp.Write(data)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		utils.Discard(os.Remove(tmp.Name()))
		return fmt.Errorf("parsememo: %w", err)
	}
	return nil
}

// ErrCorrupt is a Reader's error for data no Writer wrote.
var ErrCorrupt = errors.New("parsememo: corrupt entry")

// Writer builds an entry.
type Writer struct {
	buf bytes.Buffer
}

// Bytes is what was written.
func (w *Writer) Bytes() []byte { return w.buf.Bytes() }

// Byte writes b.
func (w *Writer) Byte(b byte) { w.buf.WriteByte(b) }

// Uvarint writes v.
func (w *Writer) Uvarint(v uint64) {
	var tmp [binary.MaxVarintLen64]byte
	w.buf.Write(tmp[:binary.PutUvarint(tmp[:], v)])
}

// Varint writes v.
func (w *Writer) Varint(v int64) {
	var tmp [binary.MaxVarintLen64]byte
	w.buf.Write(tmp[:binary.PutVarint(tmp[:], v)])
}

// Float writes v's bits.
func (w *Writer) Float(v float64) {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], math.Float64bits(v))
	w.buf.Write(tmp[:])
}

// String writes s.
func (w *Writer) String(s string) {
	w.Uvarint(uint64(len(s)))
	w.buf.WriteString(s)
}

// Strings writes list, nil and empty apart.
func (w *Writer) Strings(list []string) {
	if list == nil {
		w.Uvarint(0)
		return
	}
	w.Uvarint(uint64(len(list)) + 1)
	for _, s := range list {
		w.String(s)
	}
}

// Reader reads an entry. After the first error every read returns the zero
// value and Err reports it.
type Reader struct {
	data []byte
	err  error
}

// NewReader reads data.
func NewReader(data []byte) *Reader { return &Reader{data: data} }

// Err is the first error a read met.
func (r *Reader) Err() error { return r.err }

// Done reports whether every byte was read without error.
func (r *Reader) Done() bool { return r.err == nil && len(r.data) == 0 }

// Fail records ErrCorrupt, for a value its user finds invalid.
func (r *Reader) Fail() {
	if r.err == nil {
		r.err = ErrCorrupt
	}
}

func (r *Reader) take(n uint64) []byte {
	if r.err != nil {
		return nil
	}
	if n > uint64(len(r.data)) {
		r.Fail()
		return nil
	}
	out := r.data[:n:n]
	r.data = r.data[n:]
	return out
}

// Count reads what Writer.Uvarint wrote for a number of elements, each
// encoded in one byte at least.
func (r *Reader) Count() uint64 { return r.Bound(r.Uvarint()) }

// Bound returns n, a number of elements still to read, each encoded in one
// byte at least, or fails when fewer bytes are left.
func (r *Reader) Bound(n uint64) uint64 {
	if n > uint64(len(r.data)) {
		r.Fail()
		return 0
	}
	return n
}

// Byte reads a byte.
func (r *Reader) Byte() byte {
	if b := r.take(1); b != nil {
		return b[0]
	}
	return 0
}

// Uvarint reads what Writer.Uvarint wrote.
func (r *Reader) Uvarint() uint64 {
	if r.err != nil {
		return 0
	}
	v, n := binary.Uvarint(r.data)
	if n <= 0 {
		r.Fail()
		return 0
	}
	r.data = r.data[n:]
	return v
}

// Varint reads what Writer.Varint wrote.
func (r *Reader) Varint() int64 {
	if r.err != nil {
		return 0
	}
	v, n := binary.Varint(r.data)
	if n <= 0 {
		r.Fail()
		return 0
	}
	r.data = r.data[n:]
	return v
}

// Float reads what Writer.Float wrote.
func (r *Reader) Float() float64 {
	raw := r.take(8)
	if raw == nil {
		return 0
	}
	return math.Float64frombits(binary.LittleEndian.Uint64(raw))
}

// String reads what Writer.String wrote.
func (r *Reader) String() string { return string(r.take(r.Uvarint())) }

// Strings reads what Writer.Strings wrote.
func (r *Reader) Strings() []string {
	n := r.Uvarint()
	if n == 0 || r.err != nil {
		return nil
	}
	out := make([]string, r.Bound(n-1))
	for i := range out {
		out[i] = r.String()
	}
	return out
}
