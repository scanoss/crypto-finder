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

package sbomcbom

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Format names the SBOM format a document was read as.
type Format string

// The formats ParseSBOM reads.
const (
	FormatCycloneDX    Format = "CycloneDX"
	FormatSPDX         Format = "SPDX"
	FormatSPDXTagValue Format = "SPDX tag-value"
)

// ErrUnknownFormat reports a document that is neither CycloneDX JSON nor SPDX
// (JSON or tag-value).
var ErrUnknownFormat = errors.New("sbomcbom: not a CycloneDX or SPDX document")

// Component is one package an SBOM lists by package URL.
type Component struct {
	PURL    string
	Name    string
	Version string
}

// Document is what an SBOM says about the software it describes.
type Document struct {
	Format Format
	// Name and Version describe the software the SBOM is for, when it says.
	Name    string
	Version string
	// Components lists every package with a package URL, in document order.
	Components []Component
	// WithoutPURL counts the packages that name no package URL. They cannot
	// be looked up.
	WithoutPURL int
}

// ParseSBOM reads a CycloneDX JSON, SPDX JSON or SPDX tag-value document.
func ParseSBOM(data []byte) (*Document, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var probe struct {
			BOMFormat   string `json:"bomFormat"`
			SPDXVersion string `json:"spdxVersion"`
		}
		if err := json.Unmarshal(trimmed, &probe); err != nil {
			return nil, fmt.Errorf("sbomcbom: parse JSON: %w", err)
		}
		switch {
		case strings.EqualFold(probe.BOMFormat, "CycloneDX"):
			return parseCycloneDX(trimmed)
		case probe.SPDXVersion != "":
			return parseSPDXJSON(trimmed)
		}
		return nil, ErrUnknownFormat
	}
	if bytes.HasPrefix(trimmed, []byte("SPDXVersion:")) {
		return parseSPDXTagValue(trimmed)
	}
	return nil, ErrUnknownFormat
}

type cdxComponent struct {
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	PURL       string         `json:"purl"`
	Components []cdxComponent `json:"components"`
}

func parseCycloneDX(data []byte) (*Document, error) {
	var bom struct {
		Metadata struct {
			Component *cdxComponent `json:"component"`
		} `json:"metadata"`
		Components []cdxComponent `json:"components"`
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("sbomcbom: parse CycloneDX: %w", err)
	}
	doc := &Document{Format: FormatCycloneDX}
	if root := bom.Metadata.Component; root != nil {
		doc.Name, doc.Version = root.Name, root.Version
	}
	var walk func([]cdxComponent)
	walk = func(components []cdxComponent) {
		for _, c := range components {
			doc.add(c.PURL, c.Name, c.Version)
			walk(c.Components)
		}
	}
	walk(bom.Components)
	return doc, nil
}

func parseSPDXJSON(data []byte) (*Document, error) {
	var spdx struct {
		Name     string `json:"name"`
		Packages []struct {
			Name         string `json:"name"`
			VersionInfo  string `json:"versionInfo"`
			ExternalRefs []struct {
				ReferenceType    string `json:"referenceType"`
				ReferenceLocator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &spdx); err != nil {
		return nil, fmt.Errorf("sbomcbom: parse SPDX: %w", err)
	}
	doc := &Document{Format: FormatSPDX, Name: spdx.Name}
	for _, p := range spdx.Packages {
		purl := ""
		for _, ref := range p.ExternalRefs {
			if strings.EqualFold(ref.ReferenceType, "purl") {
				purl = ref.ReferenceLocator
				break
			}
		}
		doc.add(purl, p.Name, p.VersionInfo)
	}
	return doc, nil
}

func parseSPDXTagValue(data []byte) (*Document, error) {
	doc := &Document{Format: FormatSPDXTagValue}
	var name, version, purl string
	inPackage := false
	flush := func() {
		if inPackage {
			doc.add(purl, name, version)
		}
		name, version, purl = "", "", ""
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		tag, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(tag) {
		case "DocumentName":
			doc.Name = value
		case "PackageName":
			flush()
			inPackage, name = true, value
		case "PackageVersion":
			version = value
		case "ExternalRef":
			// ExternalRef: PACKAGE-MANAGER purl pkg:npm/left-pad@1.3.0
			fields := strings.Fields(value)
			if len(fields) == 3 && strings.EqualFold(fields[1], "purl") && purl == "" {
				purl = fields[2]
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("sbomcbom: read SPDX tag-value: %w", err)
	}
	flush()
	return doc, nil
}

func (d *Document) add(purl, name, version string) {
	purl = strings.TrimSpace(purl)
	if !strings.HasPrefix(purl, "pkg:") {
		d.WithoutPURL++
		return
	}
	d.Components = append(d.Components, Component{PURL: purl, Name: name, Version: version})
}
