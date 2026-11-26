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

package schema

import (
	"reflect"
	"testing"
)

// Clone keeps every field of a report, also the ones the wire schema leaves
// out, and shares no memory with it. Every exported field of every type the
// report holds is set, so a field added later is covered without editing
// this test.
func TestInterimReportClone_KeepsEveryFieldAndSharesNoMemory(t *testing.T) {
	var report InterimReport
	fillExported(reflect.ValueOf(&report).Elem())
	asset := report.Findings[0].CryptographicAssets[0]
	if !asset.ConditionedValuesIncomplete || asset.Served == nil || len(report.IncompleteFiles) == 0 {
		t.Fatal("fixture: the in-process fields are not set")
	}

	clone := report.Clone()
	if !reflect.DeepEqual(clone, &report) {
		t.Fatalf("clone differs from the report:\n%+v\n%+v", clone, &report)
	}
	assertNoSharedMemory(t, "report", reflect.ValueOf(&report).Elem(), reflect.ValueOf(clone).Elem())

	if (*InterimReport)(nil).Clone() != nil {
		t.Error("nil report cloned to non-nil")
	}
}

// fillExported sets every settable field reachable from v to a non-zero value:
// slices and maps get one filled element, pointers a filled target.
func fillExported(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fillExported(v.Elem())
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fillExported(v.Index(0))
	case reflect.Map:
		key := reflect.New(v.Type().Key()).Elem()
		fillExported(key)
		value := reflect.New(v.Type().Elem()).Elem()
		fillExported(value)
		v.Set(reflect.MakeMap(v.Type()))
		v.SetMapIndex(key, value)
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				fillExported(v.Field(i))
			}
		}
	case reflect.Invalid, reflect.Uintptr, reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128,
		reflect.Array, reflect.Chan, reflect.Func, reflect.Interface, reflect.UnsafePointer:
		// The schema holds none of these kinds.
	}
}

func assertNoSharedMemory(t *testing.T, path string, a, b reflect.Value) {
	t.Helper()
	switch a.Kind() {
	case reflect.Pointer:
		if a.IsNil() {
			return
		}
		if a.Pointer() == b.Pointer() {
			t.Errorf("%s: pointer shared", path)
		}
		assertNoSharedMemory(t, path, a.Elem(), b.Elem())
	case reflect.Slice:
		if a.Len() == 0 {
			return
		}
		if a.Pointer() == b.Pointer() {
			t.Errorf("%s: slice shared", path)
		}
		for i := range a.Len() {
			assertNoSharedMemory(t, path+"[]", a.Index(i), b.Index(i))
		}
	case reflect.Map:
		if a.Len() == 0 {
			return
		}
		if a.Pointer() == b.Pointer() {
			t.Errorf("%s: map shared", path)
		}
		for _, key := range a.MapKeys() {
			assertNoSharedMemory(t, path+"[key]", a.MapIndex(key), b.MapIndex(key))
		}
	case reflect.Struct:
		for i := range a.NumField() {
			if a.Type().Field(i).IsExported() {
				assertNoSharedMemory(t, path+"."+a.Type().Field(i).Name, a.Field(i), b.Field(i))
			}
		}
	case reflect.Invalid, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.Array, reflect.Chan,
		reflect.Func, reflect.Interface, reflect.String, reflect.UnsafePointer:
		// Scalars hold no memory to share.
	}
}
