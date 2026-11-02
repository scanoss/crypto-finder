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

package main

import (
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The tests below pin the boundaries of .github/workflows/post-merge-qa.yml
// and its prompt, the agent run that drives this map after a merge.
const (
	qaWorkflowPath = "../../.github/workflows/post-merge-qa.yml"
	qaPromptPath   = "../../.github/post-merge-qa.md"
)

type ghStep struct {
	Name string            `yaml:"name"`
	ID   string            `yaml:"id"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
	With map[string]any    `yaml:"with"`
	// TimeoutMinutes is a step's own timeout, inside the job's.
	TimeoutMinutes int `yaml:"timeout-minutes"`
}

type ghJob struct {
	Permissions    map[string]string `yaml:"permissions"`
	Needs          any               `yaml:"needs"`
	If             string            `yaml:"if"`
	TimeoutMinutes int               `yaml:"timeout-minutes"`
	Steps          []ghStep          `yaml:"steps"`
}

type ghWorkflow struct {
	On          map[string]any    `yaml:"on"`
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]ghJob  `yaml:"jobs"`
}

func loadQAWorkflow(t *testing.T) (ghWorkflow, string) {
	t.Helper()
	raw, err := os.ReadFile(qaWorkflowPath)
	if err != nil {
		t.Fatal(err)
	}
	var w ghWorkflow
	if err := yaml.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	return w, string(raw)
}

func (j ghJob) step(t *testing.T, name string) (int, ghStep) {
	t.Helper()
	for i, s := range j.Steps {
		if s.Name == name {
			return i, s
		}
	}
	t.Fatalf("no step %q", name)
	return 0, ghStep{}
}

func TestQAWorkflowRunsOnlyOnMergedCode(t *testing.T) {
	w, _ := loadQAWorkflow(t)
	var events []string
	for e := range w.On {
		events = append(events, e)
	}
	slices.Sort(events)
	if !slices.Equal(events, []string{"push", "workflow_dispatch"}) {
		t.Errorf("events = %q, want push and workflow_dispatch only (never pull_request)", events)
	}
	push, _ := w.On["push"].(map[string]any)
	if branches, _ := push["branches"].([]any); len(branches) != 1 || branches[0] != "main" {
		t.Errorf("push branches = %v, want [main]", push["branches"])
	}
	// A run by hand checks out the PR's merge commit, found before the checkout.
	qa := w.Jobs["qa"]
	find, _ := qa.step(t, "Find the change")
	checkout := -1
	for i, s := range qa.Steps {
		if strings.HasPrefix(s.Uses, "actions/checkout@") {
			checkout = i
			if s.With["ref"] != "${{ steps.change.outputs.sha }}" {
				t.Errorf("checkout ref = %v, want the change's sha", s.With["ref"])
			}
		}
	}
	if checkout < find {
		t.Errorf("checkout (step %d) must follow Find the change (step %d)", checkout, find)
	}
}

func TestQAWorkflowStopsWithoutFeatures(t *testing.T) {
	w, _ := loadQAWorkflow(t)
	qa := w.Jobs["qa"]
	pick, s := qa.step(t, "Pick the features")
	if !strings.Contains(s.Run, "go run ./scripts/featuremap select") || !strings.Contains(s.Env["MAX"], "vars.QA_MAX_FEATURES || 5") {
		t.Errorf("Pick the features must run featuremap select capped by QA_MAX_FEATURES (default 5):\n%s", s.Run)
	}
	for _, later := range qa.Steps[pick+1:] {
		if !strings.Contains(later.If, "steps.features.outputs.ids != ''") {
			t.Errorf("step %q runs without features (if: %q)", later.Name+later.Uses, later.If)
		}
	}
	if !strings.Contains(w.Jobs["report"].If, "needs.qa.outputs.ids != ''") {
		t.Errorf("report job runs without features (if: %q)", w.Jobs["report"].If)
	}
}

func TestQAWorkflowUsesOnlyTheSeatToken(t *testing.T) {
	w, raw := loadQAWorkflow(t)
	for _, banned := range []string{"OPENROUTER", "ANTHROPIC_BASE_URL", "secrets.ANTHROPIC_API_KEY"} {
		if strings.Contains(raw, banned) {
			t.Errorf("workflow mentions %s; the agent runs on CLAUDE_CODE_OAUTH_TOKEN only", banned)
		}
	}
	// claude-code-action pulls oven-sh/setup-bun, which the organization's
	// Actions policy refuses; the pinned CLI is installed with npm instead.
	for _, job := range w.Jobs {
		for _, s := range job.Steps {
			if strings.Contains(s.Uses, "claude-code-action") {
				t.Errorf("step %q uses %s", s.Name, s.Uses)
			}
		}
	}
	for _, m := range regexp.MustCompile(`secrets\.([A-Z_]+)`).FindAllStringSubmatch(raw, -1) {
		if m[1] != "CLAUDE_CODE_OAUTH_TOKEN" {
			t.Errorf("workflow reads secret %s; only CLAUDE_CODE_OAUTH_TOKEN is allowed", m[1])
		}
	}
	qa := w.Jobs["qa"]
	var users []string
	for _, s := range qa.Steps {
		for _, v := range s.Env {
			if strings.Contains(v, "secrets.CLAUDE_CODE_OAUTH_TOKEN") {
				users = append(users, s.Name)
			}
		}
	}
	if !slices.Equal(users, []string{"Pick the features", "Drive the features", "Check the evidence holds no secret"}) {
		t.Errorf("steps reading the token = %q", users)
	}
	if _, s := qa.step(t, "Pick the features"); s.Env["QA_KEY"] != "${{ secrets.CLAUDE_CODE_OAUTH_TOKEN != '' }}" || !strings.Contains(s.Run, "::notice::CLAUDE_CODE_OAUTH_TOKEN is not set") {
		t.Errorf("QA must stay off with a notice when the secret is absent")
	}
	_, drive := qa.step(t, "Drive the features")
	if v, ok := drive.Env["ANTHROPIC_API_KEY"]; !ok || v != "" {
		t.Errorf(`ANTHROPIC_API_KEY = %q, want "" so no API key is billed`, v)
	}
	if drive.Env["CLAUDE_CONFIG_DIR"] != "${{ runner.temp }}/claude" {
		t.Errorf("CLAUDE_CONFIG_DIR = %q, want a job-owned directory", drive.Env["CLAUDE_CONFIG_DIR"])
	}
	if drive.Env["QA_MODEL"] != "${{ vars.QA_MODEL || 'haiku' }}" || !strings.Contains(drive.Run, `--model "${QA_MODEL:-haiku}"`) {
		t.Errorf("the model must come from vars.QA_MODEL, default haiku")
	}
	if _, install := qa.step(t, "Install Claude Code"); !regexp.MustCompile(`^npm install -g @anthropic-ai/claude-code@\d+\.\d+\.\d+$`).MatchString(strings.TrimSpace(install.Run)) {
		t.Errorf("Claude Code must be installed with npm at a pinned version: %q", install.Run)
	}
}

func TestQAWorkflowAgentJobOnlyReads(t *testing.T) {
	w, _ := loadQAWorkflow(t)
	if want := map[string]string{"contents": "read"}; !maps.Equal(w.Permissions, want) {
		t.Errorf("workflow permissions = %v, want %v", w.Permissions, want)
	}
	if want := map[string]string{"contents": "read", "pull-requests": "read"}; !maps.Equal(w.Jobs["qa"].Permissions, want) {
		t.Errorf("qa permissions = %v, want %v", w.Jobs["qa"].Permissions, want)
	}
	if want := map[string]string{"issues": "write", "pull-requests": "write"}; !maps.Equal(w.Jobs["report"].Permissions, want) {
		t.Errorf("report permissions = %v, want %v", w.Jobs["report"].Permissions, want)
	}
	for _, s := range w.Jobs["report"].Steps {
		if strings.Contains(s.Run, "claude") || strings.Contains(s.Uses, "claude") {
			t.Errorf("the report job, the only writer, must run no agent: step %q", s.Name)
		}
	}
	if len(w.Jobs) != 2 {
		t.Errorf("jobs = %d, want qa and report", len(w.Jobs))
	}
}

// allowedTools splits the --allowedTools list of the agent's command line.
func allowedTools(t *testing.T, run string) []string {
	t.Helper()
	m := regexp.MustCompile(`--allowedTools "([^"]+)"`).FindStringSubmatch(run)
	if m == nil {
		t.Fatal("no --allowedTools list")
	}
	return strings.Split(m[1], ",")
}

func TestQAWorkflowLimitsTheAgent(t *testing.T) {
	w, _ := loadQAWorkflow(t)
	_, drive := w.Jobs["qa"].step(t, "Drive the features")
	tools := allowedTools(t, drive.Run)
	var edits []string
	for _, tool := range tools {
		switch {
		case tool == "Bash", tool == "Edit", tool == "Write", tool == "MultiEdit", tool == "NotebookEdit":
			t.Errorf("bare %s grants every path or command", tool)
		case strings.HasPrefix(tool, "Write("):
			t.Errorf("%s matches nothing: file paths are Edit(...) rules", tool)
		case strings.HasPrefix(tool, "Edit("):
			edits = append(edits, tool)
		case strings.HasPrefix(tool, "Bash("):
			if !slices.Contains(qaBashAllowed, tool) {
				t.Errorf("%s is not one of the commands the drive needs", tool)
			}
		case !slices.Contains([]string{"Read", "Glob", "Grep"}, tool):
			t.Errorf("unexpected tool %s", tool)
		}
	}
	if want := []string{"Edit(/${{ github.workspace }}/bin/verify/evidence/**)", "Edit(//tmp/**)"}; !slices.Equal(edits, want) {
		t.Errorf("Edit rules = %q, want %q", edits, want)
	}
	for _, flag := range []string{"--disallowedTools Agent", `--max-turns "$MAX_TURNS"`, "--json-schema '", "--output-format json"} {
		if !strings.Contains(drive.Run, flag) {
			t.Errorf("the agent's command line lacks %s", flag)
		}
	}
	if drive.Env["MAX_TURNS"] != "${{ vars.QA_MAX_TURNS || 80 }}" {
		t.Errorf("MAX_TURNS = %q", drive.Env["MAX_TURNS"])
	}
	// A failing claude still reaches the verdict parser under bash -e.
	if !strings.Contains(drive.Run, "&& status=0 || status=$?") {
		t.Error("the drive step must keep claude's exit status without ending early")
	}
	if drive.TimeoutMinutes == 0 || drive.TimeoutMinutes >= w.Jobs["qa"].TimeoutMinutes {
		t.Errorf("drive timeout %d must sit inside the job's %d", drive.TimeoutMinutes, w.Jobs["qa"].TimeoutMinutes)
	}
	_, result := w.Jobs["qa"].step(t, "Read the verdicts")
	if !strings.HasPrefix(result.If, "always()") || !strings.Contains(result.Run, "featuremap qa-result") {
		t.Errorf("Read the verdicts must run always() through featuremap qa-result")
	}
}

// qaBashAllowed is every shell command the agent may run: the verify scripts
// and read-only basics, nothing that writes or reaches the network.
var qaBashAllowed = []string{
	"Bash(bash .claude/skills/verify/scripts/*)",
	"Bash(jq:*)", "Bash(ls:*)", "Bash(cat:*)", "Bash(head:*)", "Bash(tail:*)", "Bash(wc:*)",
}

func TestQAWorkflowGuardsEvidenceBeforeUpload(t *testing.T) {
	w, _ := loadQAWorkflow(t)
	qa := w.Jobs["qa"]
	guardAt, guard := qa.step(t, "Check the evidence holds no secret")
	uploadAt, upload := qa.step(t, "Upload the evidence")
	if guard.ID != "guard" || uploadAt < guardAt {
		t.Errorf("the guard (id %q, step %d) must run before the upload (step %d)", guard.ID, guardAt, uploadAt)
	}
	if !strings.Contains(upload.If, "steps.guard.outcome == 'success'") {
		t.Errorf("upload if = %q, want it gated on the guard", upload.If)
	}
	if !strings.Contains(guard.Run, `grep -rqaF -- "$QA_KEY"`) || !strings.Contains(guard.Run, `rm -rf "$evidence"`) {
		t.Errorf("the guard must delete the evidence when the token appears:\n%s", guard.Run)
	}
	if upload.With["path"] != "${{ github.workspace }}/bin/verify/evidence/" {
		t.Errorf("upload path = %v, want the guarded evidence directory", upload.With["path"])
	}
}

func TestQAPromptPlaceholdersMatchTheWorkflow(t *testing.T) {
	w, _ := loadQAWorkflow(t)
	_, write := w.Jobs["qa"].step(t, "Write the prompt")
	prompt, err := os.ReadFile(qaPromptPath)
	if err != nil {
		t.Fatal(err)
	}
	placeholder := regexp.MustCompile(`\{\{(\w+)\}\}`)
	keys := func(s string) []string {
		var out []string
		for _, m := range placeholder.FindAllStringSubmatch(s, -1) {
			if !slices.Contains(out, m[1]) {
				out = append(out, m[1])
			}
		}
		slices.Sort(out)
		return out
	}
	if filled, used := keys(write.Run), keys(string(prompt)); !slices.Equal(filled, used) || len(used) == 0 {
		t.Errorf("the workflow fills %q, the prompt uses %q", filled, used)
	}
	if !strings.Contains(write.Run, ".github/post-merge-qa.md") {
		t.Error("Write the prompt must read .github/post-merge-qa.md")
	}
	// The prompt names the command form the Bash rule allows.
	if !strings.Contains(string(prompt), "`bash .claude/skills/verify/scripts/run.sh <id> [lang]`") {
		t.Error("the prompt must tell the agent to drive run.sh with the bash prefix the permission rule allows")
	}
}

func TestQAReportFailsWithoutVerdict(t *testing.T) {
	w, _ := loadQAWorkflow(t)
	report := w.Jobs["report"]
	if len(report.Steps) != 1 {
		t.Fatalf("report steps = %d, want 1", len(report.Steps))
	}
	script, _ := report.Steps[0].With["script"].(string)
	for _, want := range []string{
		"core.setFailed(`no verdict from the QA agent",
		"core.setFailed(`no verdict for",
		"<!-- post-merge-qa -->",
		"updateComment",
		"github.rest.issues.create(",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("report script lacks %q", want)
		}
	}
}
