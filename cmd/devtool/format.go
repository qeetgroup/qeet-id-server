package main

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// One formatter per language, each pinned like the other tools:
//   - Go: gofmt and goimports, through golangci-lint (the formatters in .golangci.yml)
//   - JavaScript, JSON, YAML and Markdown: Prettier (api/openapi/src/package.json, .prettierrc.json)
//   - shell: shfmt (its settings come from .editorconfig)
func shfmtVersion() string { return envOr("SHFMT_VERSION", "v3.14.1") }

// formatAll rewrites every file its formatter would change.
func formatAll() error {
	if err := golangci("fmt"); err != nil {
		return err
	}
	if err := prettier("--log-level", "warn", "--write", "."); err != nil {
		return err
	}
	if err := shfmt("-w"); err != nil {
		return err
	}
	fmt.Println("fmt: every file formatted")
	return nil
}

// formatCheck fails, showing what make fmt would change, if any file isn't formatted.
func formatCheck() error {
	if err := golangci("fmt", "--diff"); err != nil {
		return fmt.Errorf("go files need formatting (run make fmt): %w", err)
	}
	if err := prettier("--log-level", "warn", "--check", "."); err != nil {
		return fmt.Errorf("files need formatting (run make fmt): %w", err)
	}
	if err := shfmt("-d"); err != nil {
		return fmt.Errorf("shell scripts need formatting (run make fmt): %w", err)
	}
	fmt.Println("fmt-check: every file is formatted")
	return nil
}

// golangci runs the pinned golangci-lint with args.
func golangci(args ...string) error {
	return run("go", append([]string{"run", "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@" + golangciVersion()}, args...)...)
}

// prettier runs the pinned Prettier from the repository root, so it reads .prettierrc.json,
// .editorconfig and .gitignore there.
func prettier(args ...string) error {
	if err := jsInstall(); err != nil {
		return err
	}
	cli := filepath.FromSlash(openapiSrc + "/node_modules/prettier/bin/prettier.cjs")
	return run("bun", append([]string{"--bun", cli}, args...)...)
}

// shfmt runs the pinned shfmt with args over every shell script in the repository.
func shfmt(args ...string) error {
	var scripts []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != "." && (strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules" || d.Name() == "bin") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(path, ".sh") {
			scripts = append(scripts, path)
		}
		return nil
	})
	if err != nil || len(scripts) == 0 {
		return err
	}
	return run("go", append(append([]string{"run", "mvdan.cc/sh/v3/cmd/shfmt@" + shfmtVersion()}, args...), scripts...)...)
}
