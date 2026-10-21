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

// Package sbomcbom builds a CycloneDX CBOM for an SBOM from the findings
// SCANOSS published when it mined each component with crypto-finder. It is the
// same conversion `crypto-finder convert` applies to a scan, so a CBOM built
// from an SBOM and one built from a scan of the same component agree.
package sbomcbom

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	cdx "github.com/CycloneDX/cyclonedx-go"

	apiclient "github.com/scanoss/crypto-finder/internal/api"
	"github.com/scanoss/crypto-finder/internal/converter"
	"github.com/scanoss/crypto-finder/internal/enricher"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/purl"
)

// DefaultAPIURL is the SCANOSS API the findings come from.
const DefaultAPIURL = "https://api.scanoss.com"

const (
	componentReady       = "READY"
	defaultConcurrency   = 8
	defaultMaxComponents = 500
)

var (
	// ErrTooManyComponents reports an SBOM with more distinct components than
	// Options.MaxComponents allows.
	ErrTooManyComponents = errors.New("sbomcbom: too many components")
	// ErrAccessDenied reports that the API refused the key.
	ErrAccessDenied = errors.New("sbomcbom: the SCANOSS API refused the API key")
)

// Status is what the lookup learned about one component.
type Status string

const (
	// StatusCrypto means SCANOSS mined the component and it uses cryptography.
	StatusCrypto Status = "crypto"
	// StatusNoCrypto means SCANOSS mined the component and found no cryptography.
	StatusNoCrypto Status = "no-crypto"
	// StatusNotMined means SCANOSS has not mined this component or version.
	StatusNotMined Status = "not-mined"
	// StatusUnsupported means the entry has no usable package URL or version.
	StatusUnsupported Status = "unsupported"
	// StatusFailed means the lookup failed, so the component is missing from
	// the CBOM.
	StatusFailed Status = "failed"
)

// ComponentResult is one SBOM component's outcome.
type ComponentResult struct {
	// PURL is the package URL as the SBOM wrote it.
	PURL   string
	Status Status
	// InfoCode is the API's verdict (READY, COMPONENT_NOT_FOUND...), when it
	// answered.
	InfoCode string
	// Ref is the bom-ref of the component's library in the CBOM, when it uses
	// cryptography: the canonical package URL at the version served.
	Ref string
	// ServedVersion is the version the findings were mined from. It can be a
	// later patch than the SBOM asked for.
	ServedVersion string
	// Problem says why a failed lookup failed.
	Problem string
}

// Options configures Generate.
type Options struct {
	APIKey string `json:"-"`
	// APIURL defaults to DefaultAPIURL.
	APIURL string
	// HTTPClient defaults to the API client's own.
	HTTPClient *http.Client
	// Concurrency bounds the lookups in flight. Default 8.
	Concurrency int
	// MaxComponents bounds the distinct components looked up. Default 500.
	MaxComponents int
	// ToolVersion is stamped on the CBOM's tool entry.
	ToolVersion string
}

// Result is the CBOM and how each SBOM component fared.
type Result struct {
	BOM *cdx.BOM
	// Components follows the order of the SBOM, one entry per component.
	Components []ComponentResult
	// RulesVersion is the detection ruleset the findings were mined with.
	RulesVersion string
}

type lookup struct {
	base, version string
	name          string
	answer        *apiclient.ComponentFindings
	err           error
	// ref is the bom-ref of the component's library in the CBOM, set when
	// the findings went into it.
	ref string
}

// Generate looks up every component of doc and converts the findings
// SCANOSS published for them into one CycloneDX 1.7 CBOM. Each component
// that uses cryptography appears as a library whose dependencies are its
// crypto assets.
func Generate(ctx context.Context, doc *Document, opts Options) (*Result, error) {
	if doc == nil {
		return nil, fmt.Errorf("sbomcbom: nil document")
	}
	opts = withDefaults(opts)

	perEntry, distinct := planLookups(doc.Components)
	if len(distinct) > opts.MaxComponents {
		return nil, fmt.Errorf("%w: %d distinct components, the limit is %d", ErrTooManyComponents, len(distinct), opts.MaxComponents)
	}
	if err := lookUp(ctx, newClient(opts), distinct, opts.Concurrency); err != nil {
		return nil, err
	}

	report, rulesVersion := buildReport(distinct, opts.ToolVersion)
	bom, err := convert(report)
	if err != nil {
		// One component's findings can carry a value strict CycloneDX
		// validation refuses. Leave that component out, marked failed,
		// rather than lose the CBOM of every other component.
		if !excludeUnconvertible(distinct, opts.ToolVersion) {
			return nil, err
		}
		report, rulesVersion = buildReport(distinct, opts.ToolVersion)
		if bom, err = convert(report); err != nil {
			return nil, err
		}
	}
	if doc.Name != "" {
		bom.Metadata.Component = &cdx.Component{Type: cdx.ComponentTypeApplication, BOMRef: "sbom-subject", Name: doc.Name, Version: doc.Version}
	}

	results := make([]ComponentResult, len(doc.Components))
	for i, c := range doc.Components {
		results[i] = componentResult(c.PURL, perEntry[i])
	}
	return &Result{BOM: bom, Components: results, RulesVersion: rulesVersion}, nil
}

// planLookups gives each SBOM entry its lookup, nil when the entry has no
// usable package URL or version. Entries naming the same package at the same
// version share one lookup; distinct lists each lookup once, in SBOM order.
func planLookups(components []Component) (perEntry, distinct []*lookup) {
	perEntry = make([]*lookup, len(components))
	byKey := map[string]*lookup{}
	for i, c := range components {
		base, version, ok := purl.Split(c.PURL)
		if !ok || version == "" {
			continue
		}
		key := base + "@" + version
		l, seen := byKey[key]
		if !seen {
			l = &lookup{base: base, version: version, name: c.Name}
			byKey[key] = l
			distinct = append(distinct, l)
		}
		perEntry[i] = l
	}
	return perEntry, distinct
}

// buildReport gathers the served findings into one interim report, each
// asset attributed to its component, and returns the ruleset they were
// mined with.
func buildReport(lookups []*lookup, toolVersion string) (*entities.InterimReport, string) {
	report := &entities.InterimReport{Version: "1.0", Tool: entities.ToolInfo{Name: "crypto-finder", Version: toolVersion}}
	rulesVersion := ""
	for _, l := range lookups {
		l.ref = ""
		if l.err != nil || l.answer == nil || l.answer.InfoCode != componentReady || len(l.answer.Findings) == 0 {
			continue
		}
		if rulesVersion == "" {
			rulesVersion = l.answer.RulesVersion
		}
		dep := &entities.DependencyInfo{Module: moduleName(l), Version: l.answer.Version, PURL: purl.WithVersion(l.base, l.answer.Version)}
		l.ref = dep.PURL
		report.Findings = append(report.Findings, attribute(l.answer.Findings, dep)...)
	}
	report.Rules = entities.RulesInfo{Source: "scanoss-api", Version: rulesVersion}
	return report, rulesVersion
}

func withDefaults(opts Options) Options {
	if opts.APIURL == "" {
		opts.APIURL = DefaultAPIURL
	}
	opts.APIURL = strings.TrimRight(opts.APIURL, "/")
	if opts.Concurrency <= 0 {
		opts.Concurrency = defaultConcurrency
	}
	if opts.MaxComponents <= 0 {
		opts.MaxComponents = defaultMaxComponents
	}
	return opts
}

func newClient(opts Options) *apiclient.Client {
	if opts.HTTPClient != nil {
		return apiclient.NewClientWithHTTPClient(opts.APIURL, opts.APIKey, opts.HTTPClient)
	}
	return apiclient.NewClient(opts.APIURL, opts.APIKey)
}

// lookUp asks the API about every lookup, Concurrency at a time. A refused
// key stops the whole run, since no other lookup can succeed; any other
// failure is kept on its lookup.
func lookUp(parent context.Context, client *apiclient.Client, lookups []*lookup, concurrency int) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	var (
		mu     sync.Mutex
		denied error
		wg     sync.WaitGroup
	)
	work := make(chan *lookup)
	for range min(concurrency, len(lookups)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for l := range work {
				ask(ctx, client, l)
				if refused(l.err) {
					mu.Lock()
					if denied == nil {
						denied = l.err
					}
					mu.Unlock()
					cancel()
				}
			}
		}()
	}
	for _, l := range lookups {
		if ctx.Err() != nil {
			break
		}
		work <- l
	}
	close(work)
	wg.Wait()

	if denied != nil {
		return fmt.Errorf("%w: %w", ErrAccessDenied, denied)
	}
	if err := parent.Err(); err != nil {
		return fmt.Errorf("sbomcbom: lookups stopped: %w", err)
	}
	return nil
}

// excludeUnconvertible converts each component's findings on their own and
// marks failed the ones that cannot become a valid CBOM. It reports whether
// it found any.
func excludeUnconvertible(lookups []*lookup, toolVersion string) bool {
	found := false
	for _, l := range lookups {
		if l.ref == "" {
			continue
		}
		report, _ := buildReport([]*lookup{l}, toolVersion)
		if _, err := convert(report); err != nil {
			l.err = fmt.Errorf("sbomcbom: findings of %s: %w", l.ref, err)
			found = true
		}
	}
	return found
}

// ask looks l up, once more after a transient failure.
func ask(ctx context.Context, client *apiclient.Client, l *lookup) {
	l.answer, l.err = client.LookupComponent(ctx, l.base, l.version)
	if transient(ctx, l.err) {
		l.answer, l.err = client.LookupComponent(ctx, l.base, l.version)
	}
}

func refused(err error) bool {
	return errors.Is(err, apiclient.ErrUnauthorized) || errors.Is(err, apiclient.ErrForbidden)
}

// transient reports a failure one more attempt may not repeat: anything but a
// refusal, a missing endpoint or the run being stopped.
func transient(ctx context.Context, err error) bool {
	return err != nil && ctx.Err() == nil && !refused(err) && !errors.Is(err, apiclient.ErrNotFound)
}

func componentResult(raw string, l *lookup) ComponentResult {
	r := ComponentResult{PURL: raw, Status: StatusUnsupported}
	switch {
	case l == nil:
		return r
	case l.err != nil:
		r.Status, r.Problem = StatusFailed, l.err.Error()
		return r
	}
	r.InfoCode = l.answer.InfoCode
	r.ServedVersion = l.answer.Version
	r.Ref = l.ref
	switch l.answer.InfoCode {
	case componentReady:
		r.Status = StatusNoCrypto
		if l.ref != "" {
			r.Status = StatusCrypto
		}
	case "INVALID_PURL", "INVALID_SEMVER":
	default:
		r.Status = StatusNotMined
	}
	return r
}

// attribute copies findings and marks every asset as found in dep, which is
// what lets the converter link the library to its assets.
func attribute(findings []entities.Finding, dep *entities.DependencyInfo) []entities.Finding {
	out := make([]entities.Finding, len(findings))
	for i := range findings {
		out[i] = findings[i]
		out[i].CryptographicAssets = make([]entities.CryptographicAsset, len(findings[i].CryptographicAssets))
		for j := range findings[i].CryptographicAssets {
			asset := findings[i].CryptographicAssets[j]
			asset.Source = "dependency"
			asset.DependencyInfo = dep
			out[i].CryptographicAssets[j] = asset
		}
	}
	return out
}

func moduleName(l *lookup) string {
	if l.name != "" {
		return l.name
	}
	return l.base
}

func convert(report *entities.InterimReport) (*cdx.BOM, error) {
	prepared, err := enricher.NewOIDEnricher().PrepareReport(report)
	if err != nil {
		return nil, fmt.Errorf("sbomcbom: prepare report: %w", err)
	}
	if prepared == nil {
		return nil, fmt.Errorf("sbomcbom: prepare report: nil report")
	}
	bom, err := converter.NewConverter().Convert(prepared.ReportClone())
	if err != nil {
		return nil, fmt.Errorf("sbomcbom: convert: %w", err)
	}
	return bom, nil
}
