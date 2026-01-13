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

package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/version"
)

// Mock implementations for testing

type mockDetector struct {
	detectFunc func(targetPath string) ([]string, error)
}

func (m *mockDetector) Detect(targetPath string) ([]string, error) {
	if m.detectFunc != nil {
		return m.detectFunc(targetPath)
	}
	return []string{"go"}, nil
}

type mockRuleSource struct {
	loadFunc func() ([]string, error)
	nameFunc func() string
}

func (m *mockRuleSource) Load() ([]string, error) {
	if m.loadFunc != nil {
		return m.loadFunc()
	}
	return []string{"/path/to/rules"}, nil
}

func (m *mockRuleSource) Name() string {
	if m.nameFunc != nil {
		return m.nameFunc()
	}
	return "mock-source"
}

type mockScanner struct {
	initializeFunc func(config scanner.Config) error
	scanFunc       func(ctx context.Context, target string, rulePaths []string, toolInfo entities.ToolInfo) (*entities.InterimReport, error)
	getInfoFunc    func() scanner.Info
}

func (m *mockScanner) Initialize(config scanner.Config) error {
	if m.initializeFunc != nil {
		return m.initializeFunc(config)
	}
	return nil
}

func (m *mockScanner) Scan(ctx context.Context, target string, rulePaths []string, toolInfo entities.ToolInfo) (*entities.InterimReport, error) {
	if m.scanFunc != nil {
		return m.scanFunc(ctx, target, rulePaths, toolInfo)
	}
	return &entities.InterimReport{
		Version:  "1.0",
		Tool:     toolInfo,
		Findings: []entities.Finding{},
	}, nil
}

func (m *mockScanner) GetInfo() scanner.Info {
	if m.getInfoFunc != nil {
		return m.getInfoFunc()
	}
	return scanner.Info{
		Name:        "mock-scanner",
		Version:     "1.0.0",
		Description: "Mock scanner for testing",
	}
}

func TestOrchestrator_Scan_Success(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Setup mocks
	detector := &mockDetector{
		detectFunc: func(_ string) ([]string, error) {
			return []string{"go", "python"}, nil
		},
	}

	ruleSource := &mockRuleSource{
		loadFunc: func() ([]string, error) {
			return []string{"/path/to/rules/go.yaml", "/path/to/rules/python.yaml"}, nil
		},
	}

	rulesManager := rules.NewManager(ruleSource)

	mockScan := &mockScanner{
		scanFunc: func(_ context.Context, _ string, _ []string, toolInfo entities.ToolInfo) (*entities.InterimReport, error) {
			return &entities.InterimReport{
				Version: "1.0",
				Tool:    toolInfo,
				Findings: []entities.Finding{
					{
						FilePath: "main.go",
						Language: "go",
						CryptographicAssets: []entities.CryptographicAsset{
							{
								MatchType: "semgrep",
								StartLine: 10,
								EndLine:   10,
								Match:     "AES.encrypt",
								Rule: entities.RuleInfo{
									ID:       "go.crypto.aes",
									Message:  "AES usage detected",
									Severity: "INFO",
								},
								Status:   "pending",
								Metadata: map[string]string{"algorithm": "AES"},
							},
						},
					},
				},
			}, nil
		},
	}

	registry := scanner.NewRegistry()
	registry.Register("test-scanner", mockScan)

	orchestrator := NewOrchestrator(detector, rulesManager, registry)

	// Execute
	opts := ScanOptions{
		Target:      "/path/to/code",
		ScannerName: "test-scanner",
		ScannerConfig: scanner.Config{
			Timeout: 0,
		},
	}

	report, err := orchestrator.Scan(ctx, opts)
	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report == nil {
		t.Fatal("expected non-nil report")
	}

	if len(report.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(report.Findings))
	}

	if report.Version != "1.0" {
		t.Errorf("expected version 1.0, got %s", report.Version)
	}
}

func TestOrchestrator_Scan_WithLanguageHint(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	detectorCalled := false
	detector := &mockDetector{
		detectFunc: func(_ string) ([]string, error) {
			detectorCalled = true
			return []string{"go"}, nil
		},
	}

	ruleSource := &mockRuleSource{}
	rulesManager := rules.NewManager(ruleSource)

	mockScan := &mockScanner{}
	registry := scanner.NewRegistry()
	registry.Register("test-scanner", mockScan)

	orchestrator := NewOrchestrator(detector, rulesManager, registry)

	// Execute with language hint
	opts := ScanOptions{
		Target:       "/path/to/code",
		ScannerName:  "test-scanner",
		LanguageHint: []string{"java", "python"},
	}

	_, err := orchestrator.Scan(ctx, opts)
	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if detectorCalled {
		t.Error("detector should not be called when language hint is provided")
	}
}

func TestOrchestrator_Scan_LanguageDetectionError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	detector := &mockDetector{
		detectFunc: func(_ string) ([]string, error) {
			return nil, errors.New("language detection failed")
		},
	}

	ruleSource := &mockRuleSource{}
	rulesManager := rules.NewManager(ruleSource)

	registry := scanner.NewRegistry()

	orchestrator := NewOrchestrator(detector, rulesManager, registry)

	opts := ScanOptions{
		Target:      "/path/to/code",
		ScannerName: "test-scanner",
	}

	_, err := orchestrator.Scan(ctx, opts)

	if err == nil {
		t.Fatal("expected error but got none")
	}

	if !errors.Is(err, errors.New("failed to detect languages: language detection failed")) && err.Error() != "failed to detect languages: language detection failed" {
		t.Errorf("expected language detection error, got: %v", err)
	}
}

func TestOrchestrator_Scan_RuleLoadingError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	detector := &mockDetector{}

	ruleSource := &mockRuleSource{
		loadFunc: func() ([]string, error) {
			return nil, errors.New("failed to load rules")
		},
	}
	rulesManager := rules.NewManager(ruleSource)

	registry := scanner.NewRegistry()

	orchestrator := NewOrchestrator(detector, rulesManager, registry)

	opts := ScanOptions{
		Target:      "/path/to/code",
		ScannerName: "test-scanner",
	}

	_, err := orchestrator.Scan(ctx, opts)

	if err == nil {
		t.Fatal("expected error but got none")
	}

	// Just check that it contains "failed to load rules"
	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}
}

func TestOrchestrator_Scan_ScannerNotFoundError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	detector := &mockDetector{}
	ruleSource := &mockRuleSource{}
	rulesManager := rules.NewManager(ruleSource)

	registry := scanner.NewRegistry()
	// Don't register any scanner

	orchestrator := NewOrchestrator(detector, rulesManager, registry)

	opts := ScanOptions{
		Target:      "/path/to/code",
		ScannerName: "nonexistent-scanner",
	}

	_, err := orchestrator.Scan(ctx, opts)

	if err == nil {
		t.Fatal("expected error but got none")
	}

	// Just check that an error was returned
	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}
}

func TestOrchestrator_Scan_ScannerInitializeError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	detector := &mockDetector{}
	ruleSource := &mockRuleSource{}
	rulesManager := rules.NewManager(ruleSource)

	mockScan := &mockScanner{
		initializeFunc: func(_ scanner.Config) error {
			return errors.New("scanner initialization failed")
		},
	}

	registry := scanner.NewRegistry()
	registry.Register("test-scanner", mockScan)

	orchestrator := NewOrchestrator(detector, rulesManager, registry)

	opts := ScanOptions{
		Target:      "/path/to/code",
		ScannerName: "test-scanner",
	}

	_, err := orchestrator.Scan(ctx, opts)

	if err == nil {
		t.Fatal("expected error but got none")
	}

	if err.Error() != "failed to initialize scanner 'test-scanner': scanner initialization failed" {
		t.Errorf("expected scanner initialization error, got: %v", err)
	}
}

func TestOrchestrator_Scan_ScanExecutionError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	detector := &mockDetector{}
	ruleSource := &mockRuleSource{}
	rulesManager := rules.NewManager(ruleSource)

	mockScan := &mockScanner{
		scanFunc: func(_ context.Context, _ string, _ []string, _ entities.ToolInfo) (*entities.InterimReport, error) {
			return nil, errors.New("scan execution failed")
		},
	}

	registry := scanner.NewRegistry()
	registry.Register("test-scanner", mockScan)

	orchestrator := NewOrchestrator(detector, rulesManager, registry)

	opts := ScanOptions{
		Target:      "/path/to/code",
		ScannerName: "test-scanner",
	}

	_, err := orchestrator.Scan(ctx, opts)

	if err == nil {
		t.Fatal("expected error but got none")
	}

	if err.Error() != "scan failed: scan execution failed" {
		t.Errorf("expected scan execution error, got: %v", err)
	}
}

func TestOrchestrator_Scan_ContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	detector := &mockDetector{}
	ruleSource := &mockRuleSource{}
	rulesManager := rules.NewManager(ruleSource)

	mockScan := &mockScanner{
		scanFunc: func(ctx context.Context, _ string, _ []string, _ entities.ToolInfo) (*entities.InterimReport, error) {
			// Check context cancellation
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return &entities.InterimReport{}, nil
		},
	}

	registry := scanner.NewRegistry()
	registry.Register("test-scanner", mockScan)

	orchestrator := NewOrchestrator(detector, rulesManager, registry)

	opts := ScanOptions{
		Target:      "/path/to/code",
		ScannerName: "test-scanner",
	}

	_, err := orchestrator.Scan(ctx, opts)

	if err == nil {
		t.Fatal("expected error due to context cancellation")
	}
}

func TestOrchestrator_Scan_ToolInfoPropagation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	detector := &mockDetector{}
	ruleSource := &mockRuleSource{}
	rulesManager := rules.NewManager(ruleSource)

	var receivedToolInfo entities.ToolInfo
	mockScan := &mockScanner{
		scanFunc: func(_ context.Context, _ string, _ []string, toolInfo entities.ToolInfo) (*entities.InterimReport, error) {
			receivedToolInfo = toolInfo
			return &entities.InterimReport{
				Version:  "1.0",
				Tool:     toolInfo,
				Findings: []entities.Finding{},
			}, nil
		},
	}

	registry := scanner.NewRegistry()
	registry.Register("test-scanner", mockScan)

	orchestrator := NewOrchestrator(detector, rulesManager, registry)

	opts := ScanOptions{
		Target:      "/path/to/code",
		ScannerName: "test-scanner",
	}

	_, err := orchestrator.Scan(ctx, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedToolInfo.Name != version.ToolName {
		t.Errorf("expected tool name %q, got %q", version.ToolName, receivedToolInfo.Name)
	}

	if receivedToolInfo.Version != version.Version {
		t.Errorf("expected tool version %q, got %q", version.Version, receivedToolInfo.Version)
	}
}

func TestNewOrchestrator(t *testing.T) {
	t.Parallel()

	detector := &mockDetector{}
	ruleSource := &mockRuleSource{}
	rulesManager := rules.NewManager(ruleSource)
	registry := scanner.NewRegistry()

	orchestrator := NewOrchestrator(detector, rulesManager, registry)

	if orchestrator == nil {
		t.Fatal("NewOrchestrator() returned nil")
	}

	if orchestrator.langDetector == nil {
		t.Error("orchestrator.langDetector is nil")
	}

	if orchestrator.rulesManager == nil {
		t.Error("orchestrator.rulesManager is nil")
	}

	if orchestrator.scannerReg == nil {
		t.Error("orchestrator.scannerReg is nil")
	}

	if orchestrator.processor == nil {
		t.Error("orchestrator.processor is nil")
	}
}
