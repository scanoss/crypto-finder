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

package callgraph

import (
	"path/filepath"
	"strings"
)

// Scripts: a JavaScript or TypeScript file a person or a build runs directly,
// with no import leading to it. Two signals say so: a shebang naming a
// JavaScript runtime, and a package.json "scripts" value that runs the file
// with one. Either makes the module's top level a program entry.

// nodeScriptRunners are the commands that execute a JavaScript or TypeScript
// file given as an argument.
var nodeScriptRunners = map[string]bool{
	"node": true, "nodejs": true, "tsx": true, "ts-node": true, "bun": true, "deno": true,
}

// nodeScriptExtensions are the extensions a script entry may have, written in
// a shebang file name or in a package.json script.
var nodeScriptExtensions = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".mts": true, ".cts": true,
}

// nodeRunnerValueFlags are runner flags that consume the next argument, which
// is then not the script.
var nodeRunnerValueFlags = map[string]bool{
	"-r": true, "--require": true, "--import": true, "--loader": true, "--experimental-loader": true,
	"-e": true, "--eval": true, "-p": true, "--print": true, "--env-file": true, "--conditions": true, "-C": true,
	"--tsconfig": true, "--config": true, "-c": true,
}

// nodeRunnerWrappers are commands that run the rest of the line, as
// `cross-env NODE_ENV=x node build.js` or `npx tsx build.ts`.
var nodeRunnerWrappers = map[string]bool{"cross-env": true, "npx": true, "dotenv": true, "env": true}

// nodeHasScriptShebang reports whether src starts with a shebang naming a
// JavaScript or TypeScript runtime, as `#!/usr/bin/env node`, `#!/usr/bin/env
// -S deno run`, or `#!/usr/bin/bun`, in a file with a script extension.
func nodeHasScriptShebang(filePath string, src []byte) bool {
	if !nodeScriptExtensions[strings.ToLower(filepath.Ext(filePath))] {
		return false
	}
	line, _, _ := strings.Cut(string(src), "\n")
	line, ok := strings.CutPrefix(strings.TrimSpace(line), "#!")
	if !ok {
		return false
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	command := filepath.Base(fields[0])
	if command == "env" {
		command = ""
		for _, field := range fields[1:] {
			if strings.HasPrefix(field, "-") || strings.Contains(field, "=") {
				continue
			}
			command = filepath.Base(field)
			break
		}
	}
	return nodeScriptRunners[command]
}

// nodeScriptTargets returns the files a package.json script value runs with a
// JavaScript or TypeScript runtime, as written: `tsx scripts/seed.ts` yields
// scripts/seed.ts. Commands chained with &&, ||, ; or | are read one by one.
// A runner given no file, or a script name (`bun run build`), yields nothing.
func nodeScriptTargets(script string) []string {
	var targets []string
	chained := strings.NewReplacer("&&", ";", "||", ";", "|", ";").Replace(script)
	for _, command := range strings.Split(chained, ";") {
		if target := nodeCommandTarget(strings.Fields(command)); target != "" {
			targets = append(targets, target)
		}
	}
	return targets
}

// nodeCommandTarget returns the script file one command runs, or "".
func nodeCommandTarget(words []string) string {
	i := 0
	for i < len(words) && (strings.Contains(words[i], "=") || nodeRunnerWrappers[words[i]]) {
		i++
	}
	if i >= len(words) || !nodeScriptRunners[filepath.Base(words[i])] {
		return ""
	}
	for i++; i < len(words); i++ {
		word := strings.Trim(words[i], `"'`)
		switch {
		case word == "run":
			continue
		case nodeRunnerValueFlags[word]:
			i++
		case strings.HasPrefix(word, "-"):
		case nodeScriptExtensions[strings.ToLower(filepath.Ext(word))] && !strings.ContainsAny(word, "$*"):
			return word
		default:
			return ""
		}
	}
	return ""
}
