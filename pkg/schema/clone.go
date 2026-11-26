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
	"maps"
	"slices"

	"github.com/scanoss/reach/paramcondition"
)

// Clone returns a deep copy of the report that shares no memory with it. It
// keeps every field, also the in-process state the wire schema leaves out
// (IncompleteFiles, ConditionedValuesIncomplete, Served), which a JSON round
// trip would drop.
func (r *InterimReport) Clone() *InterimReport {
	if r == nil {
		return nil
	}
	c := *r
	c.Rules.Lease = clonePointer(r.Rules.Lease)
	c.IncompleteFiles = slices.Clone(r.IncompleteFiles)
	if r.Findings != nil {
		c.Findings = make([]Finding, len(r.Findings))
		for i := range r.Findings {
			c.Findings[i] = r.Findings[i].clone()
		}
	}
	return &c
}

func (f *Finding) clone() Finding {
	c := *f
	if f.CryptographicAssets != nil {
		c.CryptographicAssets = make([]CryptographicAsset, len(f.CryptographicAssets))
		for i := range f.CryptographicAssets {
			c.CryptographicAssets[i] = f.CryptographicAssets[i].clone()
		}
	}
	return c
}

func (c *CryptographicAsset) clone() CryptographicAsset {
	a := *c
	a.Rules = slices.Clone(c.Rules)
	a.Metadata = maps.Clone(c.Metadata)
	if c.ParameterConditions != nil {
		a.ParameterConditions = make([]paramcondition.Condition, len(c.ParameterConditions))
		for i, condition := range c.ParameterConditions {
			condition.Selector.Index = clonePointer(condition.Selector.Index)
			condition.Selector.Name = clonePointer(condition.Selector.Name)
			a.ParameterConditions[i] = condition
		}
	}
	a.DependencyInfo = clonePointer(c.DependencyInfo)
	if a.DependencyInfo != nil {
		a.DependencyInfo.Markers = slices.Clone(c.DependencyInfo.Markers)
		a.DependencyInfo.Extras = slices.Clone(c.DependencyInfo.Extras)
	}
	if c.PQC != nil {
		pqc := *c.PQC
		pqc.Deadlines = slices.Clone(c.PQC.Deadlines)
		a.PQC = &pqc
	}
	if c.Served != nil {
		served := *c.Served
		served.CallChains = slices.Clone(c.Served.CallChains)
		served.Analysis = slices.Clone(c.Served.Analysis)
		a.Served = &served
	}
	return a
}

func clonePointer[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
