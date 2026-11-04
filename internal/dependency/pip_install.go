package dependency

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/failure"
)

const requirementsFile = "requirements.txt"

// pythonManifest is what a provisioned environment is built from: a
// requirements file when the project has one, otherwise the project directory
// itself, whose build backend reads its pyproject.toml, setup.py or setup.cfg.
type pythonManifest struct {
	requirements string
	files        []string
}

func findPythonManifest(projectDir string) (pythonManifest, bool) {
	if req := filepath.Join(projectDir, requirementsFile); isFile(req) {
		return pythonManifest{requirements: req}, true
	}
	var files []string
	for _, name := range pythonBuildFiles {
		if path := filepath.Join(projectDir, name); isFile(path) {
			files = append(files, path)
		}
	}
	return pythonManifest{files: files}, len(files) > 0
}

// pythonEnv is the environment Resolve lists: the interpreter that runs the
// introspection scripts, and the argv prefix that runs pip against it.
type pythonEnv struct {
	python string
	pip    []string
}

func ownPipEnv(python string) pythonEnv {
	return pythonEnv{python: python, pip: []string{python, "-m", "pip"}}
}

// pythonFor returns the environment whose packages Resolve lists, and false
// when there is none to list. An environment the user set up always wins: they
// installed it. In install mode the ambient interpreter's packages are never
// listed, because they are the tool's environment, not the project's.
func (r *PipResolver) pythonFor(ctx context.Context, projectDir string) (pythonEnv, bool, error) {
	if python := userVenvPython(projectDir); python != "" {
		return ownPipEnv(python), true, nil
	}
	ambient, err := r.ambientPython()
	if err != nil {
		return pythonEnv{}, false, fmt.Errorf("failed to locate Python interpreter: %w", err)
	}
	if !r.install {
		return ownPipEnv(ambient), true, nil
	}
	manifest, ok := findPythonManifest(projectDir)
	if !ok {
		return pythonEnv{}, false, nil
	}
	env, err := r.provisionVenv(ctx, projectDir, ambient, manifest)
	return env, err == nil, err
}

// provisionVenv builds the environment outside the scan tree, so it is never
// scanned as first-party source, under a key of the manifest and interpreter.
// The venv is created without pip and the ambient pip installs into it, so it
// holds the project's dependencies and nothing of the tool's own.
// It is built in a temporary sibling and renamed into place only when every
// requirement installed: a directory at the final path is always complete, and
// one missing a package after a transient failure is never reused.
func (r *PipResolver) provisionVenv(ctx context.Context, projectDir, ambient string, manifest pythonManifest) (pythonEnv, error) {
	if err := r.checkAmbientPip(ctx, projectDir, ambient); err != nil {
		return pythonEnv{}, err
	}
	key, err := r.venvKey(ctx, projectDir, ambient, manifest)
	if err != nil {
		return pythonEnv{}, provisionFailure(err, projectDir, "could not read the Python manifest or interpreter version")
	}
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		return pythonEnv{}, provisionFailure(err, projectDir, "could not locate the user cache directory")
	}
	parent := filepath.Join(cacheRoot, "crypto-finder", "python-envs")
	final := filepath.Join(parent, key)
	if python := venvPythonCandidate(final); python != "" {
		log.Info().Str("root", projectDir).Str("venv", final).Msg("Reusing provisioned Python environment")
		return ambientPipEnv(ambient, python), nil
	}
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return pythonEnv{}, provisionFailure(err, projectDir, "could not create "+parent)
	}
	staging, err := os.MkdirTemp(parent, key+".tmp-")
	if err != nil {
		return pythonEnv{}, provisionFailure(err, projectDir, "could not create a staging directory in "+parent)
	}

	log.Info().Str("root", projectDir).Str("venv", final).Msg("Provisioning Python environment")
	start := time.Now()
	if _, stderr, err := r.run(ctx, projectDir, ambient, "-m", "venv", "--without-pip", staging); err != nil {
		discardStaging(staging)
		return pythonEnv{}, provisionFailure(err, projectDir, "python -m venv failed: "+stderr)
	}
	python := venvPythonCandidate(staging)
	if python == "" {
		discardStaging(staging)
		return pythonEnv{}, provisionFailure(fmt.Errorf("no interpreter in %s", staging), projectDir, "python -m venv created no interpreter")
	}
	env := ambientPipEnv(ambient, python)
	failed, err := r.pipInstall(ctx, projectDir, env, manifest)
	if err != nil {
		discardStaging(staging)
		return pythonEnv{}, err
	}
	r.uninstallFirstParty(ctx, projectDir, env)
	duration := time.Since(start)
	if len(failed) > 0 {
		log.Warn().Str("root", projectDir).Strs("failed", failed).Str("venv", staging).Dur("duration", duration).
			Msg("Provisioned Python environment without some requirements; it is used for this scan only")
		return env, nil
	}
	if err := os.Rename(staging, final); err != nil {
		// A concurrent scan of the same manifest finished first.
		discardStaging(staging)
		if python := venvPythonCandidate(final); python != "" {
			return ambientPipEnv(ambient, python), nil
		}
		return pythonEnv{}, provisionFailure(err, projectDir, "could not move the Python environment into "+final)
	}
	log.Info().Str("root", projectDir).Str("venv", final).Dur("duration", duration).Msg("Provisioned Python environment")
	return ambientPipEnv(ambient, venvPythonCandidate(final)), nil
}

func ambientPipEnv(ambient, venvPython string) pythonEnv {
	return pythonEnv{python: venvPython, pip: []string{ambient, "-m", "pip", "--python", venvPython}}
}

// checkAmbientPip fails unless the ambient pip can install into another
// interpreter, which `pip --python` needs pip 22.3 or later for.
func (r *PipResolver) checkAmbientPip(ctx context.Context, projectDir, ambient string) error {
	stdout, stderr, err := r.run(ctx, projectDir, ambient, "-m", "pip", "--version")
	if err != nil {
		return provisionFailure(err, projectDir,
			"--install-dependencies needs pip for "+ambient+", and `"+ambient+" -m pip --version` failed: "+stderr)
	}
	var major, minor int
	if _, err := fmt.Sscanf(string(stdout), "pip %d.%d", &major, &minor); err != nil || major < 22 || (major == 22 && minor < 3) {
		return provisionFailure(fmt.Errorf("unsupported pip: %s", strings.TrimSpace(string(stdout))), projectDir,
			"--install-dependencies needs pip 22.3 or later for "+ambient)
	}
	return nil
}

// venvKey changes whenever what the environment would contain can change: the
// contents of every file the install reads, and the interpreter it is built
// with. The executable is part of it because a venv links to its base
// interpreter by path. A file the install would read but that does not exist is
// hashed as absent, so creating it changes the key too.
func (r *PipResolver) venvKey(ctx context.Context, projectDir, ambient string, manifest pythonManifest) (string, error) {
	files := manifest.files
	if manifest.requirements != "" {
		files = requirementsInputs(projectDir, manifest.requirements)
	}
	hash := sha256.New()
	for _, file := range files {
		name, err := filepath.Rel(projectDir, file)
		if err != nil {
			name = file
		}
		content, err := os.ReadFile(file)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			hash.Write([]byte(name + "\x00absent\x00"))
		case err != nil:
			return "", err
		default:
			hash.Write([]byte(name + "\x00" + strconv.Itoa(len(content)) + "\x00"))
			hash.Write(content)
		}
	}
	version, stderr, err := r.run(ctx, projectDir, ambient, "-c", "import sys; print(sys.version); print(sys.executable)")
	if err != nil {
		return "", fmt.Errorf("%s: %w: %s", ambient, err, stderr)
	}
	hash.Write(version)
	return hex.EncodeToString(hash.Sum(nil)[:16]), nil
}

// requirementsInputs lists every file pip reads to install a requirements
// file: the file itself, the files it includes with -r and -c (relative to the
// including file, recursively), and the build files of each local project it
// installs with -e or as a path (relative to projectDir, where pip runs).
// Remote includes and requirements are left out: their contents are not local.
func requirementsInputs(projectDir, requirements string) []string {
	w := requirementsWalk{projectDir: projectDir, visited: map[string]bool{}}
	w.walk(requirements)
	return w.inputs
}

type requirementsWalk struct {
	projectDir string
	visited    map[string]bool
	inputs     []string
}

func (w *requirementsWalk) walk(file string) {
	file = filepath.Clean(file)
	if w.visited[file] {
		return
	}
	w.visited[file] = true
	w.inputs = append(w.inputs, file)
	content, err := os.ReadFile(file)
	if err != nil {
		return
	}
	for _, line := range requirementLines(string(content)) {
		w.line(filepath.Dir(file), line)
	}
}

func (w *requirementsWalk) line(dir, line string) {
	option, value := splitRequirementOption(line)
	switch option {
	case "-r", "--requirement", "-c", "--constraint":
		if value != "" && !strings.Contains(value, "://") {
			w.walk(resolvePath(dir, value))
		}
	case "-e", "--editable", "":
		if project, ok := localProjectPath(value); ok {
			for _, name := range pythonBuildFiles {
				w.inputs = append(w.inputs, filepath.Join(resolvePath(w.projectDir, project), name))
			}
		}
	}
}

var pythonBuildFiles = []string{"pyproject.toml", "setup.py", "setup.cfg"}

func resolvePath(base, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

// localProjectPath returns the directory of a requirement that names a local
// project: ".", a path, or a file: URL, without extras, markers or options.
func localProjectPath(requirement string) (string, bool) {
	fields := strings.Fields(requirement)
	if len(fields) == 0 {
		return "", false
	}
	path, _, _ := strings.Cut(fields[0], ";")
	path, _, _ = strings.Cut(path, "[")
	path, _, _ = strings.Cut(path, "#")
	if rest, ok := strings.CutPrefix(path, "file:"); ok {
		return strings.TrimPrefix(rest, "//"), true
	}
	if path == "." || path == ".." || strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") || filepath.IsAbs(path) {
		return path, true
	}
	return "", false
}

// pipInstall installs the manifest and returns the requirements that failed. A
// requirements file that fails as a whole is retried one requirement at a time,
// so one package that cannot build costs that package, not every dependency.
// Nothing installed at all is an error.
func (r *PipResolver) pipInstall(ctx context.Context, projectDir string, env pythonEnv, manifest pythonManifest) ([]string, error) {
	pip := env.pip[0]
	base := slices.Concat(env.pip[1:], []string{"install", "--disable-pip-version-check", "--no-input"})
	if manifest.requirements == "" {
		if _, stderr, err := r.run(ctx, projectDir, pip, append(base, projectDir)...); err != nil {
			return nil, provisionFailure(err, projectDir, "pip install of the project failed: "+stderr)
		}
		return nil, nil
	}
	_, stderr, err := r.run(ctx, projectDir, pip, append(base, "-r", manifest.requirements)...)
	if err == nil {
		return nil, nil
	}
	log.Warn().Str("root", projectDir).Str("stderr", stderr).
		Msg("Installing requirements.txt failed as a whole, retrying one requirement at a time")
	content, readErr := os.ReadFile(manifest.requirements)
	if readErr != nil {
		return nil, provisionFailure(readErr, projectDir, "could not read "+requirementsFile)
	}
	header, units := parseRequirementUnits(string(content))
	var failed []string
	for _, unit := range units {
		if _, unitStderr, unitErr := r.run(ctx, projectDir, pip, slices.Concat(base, header, unit)...); unitErr != nil {
			name := strings.Join(unit, " ")
			failed = append(failed, name)
			log.Warn().Str("requirement", name).Str("stderr", unitStderr).Msg("Python requirement failed to install")
		}
	}
	if len(failed) == len(units) {
		return nil, provisionFailure(err, projectDir, "pip install -r "+requirementsFile+" failed: "+stderr)
	}
	return failed, nil
}

// firstPartyDistributionsScript names every distribution pip installed from a
// local path (PEP 610 direct_url.json with a file: URL). In an environment
// built from one project, that is the project itself, or a sibling path the
// user wrote: first-party source that must not be reported as a dependency.
const firstPartyDistributionsScript = `import json, importlib.metadata as m
for d in m.distributions():
    u = d.read_text("direct_url.json")
    if u and json.loads(u).get("url", "").startswith("file:"):
        print(d.metadata["Name"])`

func (r *PipResolver) uninstallFirstParty(ctx context.Context, projectDir string, env pythonEnv) {
	stdout, stderr, err := r.run(ctx, projectDir, env.python, "-c", firstPartyDistributionsScript)
	if err != nil {
		log.Warn().Str("stderr", stderr).Msg("Could not list locally installed Python distributions")
		return
	}
	names := strings.Fields(string(stdout))
	if len(names) == 0 {
		return
	}
	args := slices.Concat(env.pip[1:], []string{"uninstall", "--disable-pip-version-check", "-y"}, names)
	if _, stderr, err := r.run(ctx, projectDir, env.pip[0], args...); err != nil {
		log.Warn().Strs("distributions", names).Str("stderr", stderr).Msg("Could not remove first-party distributions from the environment")
	}
}

// requirementHeaderOptions apply to every requirement of the file, so the
// per-requirement retry passes them along with each one.
var requirementHeaderOptions = []string{
	"--index-url", "-i", "--extra-index-url", "--find-links", "-f", "--trusted-host",
	"--pre", "--prefer-binary", "--only-binary", "--no-binary",
}

// parseRequirementUnits splits a requirements file into the options that apply
// to all of it and the units pip can install on their own: one requirement, or
// one -r/-c/-e line.
func parseRequirementUnits(content string) (header []string, units [][]string) {
	for _, line := range requirementLines(content) {
		if !strings.HasPrefix(line, "-") {
			// Per-requirement options such as --hash have no command-line form.
			if i := strings.Index(line, " --"); i >= 0 {
				line = strings.TrimSpace(line[:i])
			}
			units = append(units, []string{line})
			continue
		}
		fields := strings.Fields(line)
		option, _, _ := strings.Cut(fields[0], "=")
		if slices.Contains(requirementHeaderOptions, option) {
			header = append(header, fields...)
			continue
		}
		units = append(units, fields)
	}
	return header, units
}

// requirementLines returns the logical lines of a requirements file, with
// continuations joined and comments and blank lines dropped.
func requirementLines(content string) []string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\\\n", " ")
	var lines []string
	for _, line := range strings.Split(content, "\n") {
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}

// splitRequirementOption splits a requirements line into its option and that
// option's value, accepting "-r file", "-rfile" and "--requirement=file". A
// line that is a requirement has no option and is returned whole as the value.
func splitRequirementOption(line string) (option, value string) {
	if !strings.HasPrefix(line, "-") {
		return "", line
	}
	fields := strings.Fields(line)
	option, rest := fields[0], strings.Join(fields[1:], " ")
	if long, attached, ok := strings.Cut(option, "="); ok && strings.HasPrefix(option, "--") {
		return long, attached
	}
	if !strings.HasPrefix(option, "--") && len(option) > 2 {
		return option[:2], option[2:]
	}
	return option, rest
}

// run executes name in dir and returns its stdout and the tail of its stderr.
func (r *PipResolver) run(ctx context.Context, dir, name string, args ...string) ([]byte, string, error) {
	cmd := r.execCommand(ctx, name, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), tailForFailure(strings.TrimSpace(stderr.String()), failureOutputLimit), err
}

func discardStaging(dir string) {
	if err := os.RemoveAll(dir); err != nil {
		log.Warn().Err(err).Str("dir", dir).Msg("Could not remove a Python environment staging directory")
	}
}

func provisionFailure(err error, projectDir, message string) error {
	return failure.Wrap(err, failure.CodeDependencyResolutionFailed, failure.StageDependency,
		"provisioning Python dependencies of "+projectDir+": "+message,
		failure.WithDetail("target_dir", projectDir),
	)
}
