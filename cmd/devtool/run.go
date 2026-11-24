package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
)

// run runs name with args in the current directory, its output to ours.
func run(name string, args ...string) error {
	return runIn("", nil, os.Stdout, name, args...)
}

// runIn runs name with args in dir ("": here), with env added to ours, writing to out (stderr too).
// Ctrl+C reaches the child, which decides how to stop; devtool waits for it.
func runIn(dir string, env []string, out io.Writer, name string, args ...string) error {
	cmd := exec.Command(name, args...) // #nosec G204 -- devtool runs the developer's own tools by design
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, out, out
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)
	return cmd.Run()
}

// output runs name with args and returns its trimmed standard output.
func output(name string, args ...string) (string, error) {
	var buf bytes.Buffer
	cmd := exec.Command(name, args...) // #nosec G204 -- devtool runs the developer's own tools by design
	cmd.Stdout, cmd.Stderr = &buf, os.Stderr
	err := cmd.Run()
	return strings.TrimSpace(buf.String()), err
}

// exe is path with the platform's executable suffix.
func exe(path string) string {
	if runtime.GOOS == "windows" && !strings.HasSuffix(path, ".exe") {
		return path + ".exe"
	}
	return filepath.FromSlash(path)
}

// repoDir is the repository root as an absolute path, for Docker volume mounts.
func repoDir() (string, error) {
	return filepath.Abs(".")
}

// envOr is the environment's value for key (set in the shell or in .env, which devtool loads), or
// def when it is unset or empty. Every setting devtool uses goes through it, so nothing is fixed.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
