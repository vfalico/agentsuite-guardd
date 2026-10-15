// agentsuite-guardd-runc is a transparent OCI runtime adapter.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func classify(args []string) string {
	for _, a := range args {
		if a == "create" || a == "start" || a == "exec" || a == "kill" || a == "delete" || a == "state" {
			return a
		}
	}
	return ""
}
func underlying() string {
	if p := os.Getenv("AGENTSUITE_GUARDD_UNDERLYING_RUNTIME"); p != "" {
		return p
	}
	return "/usr/bin/runc"
}
func run(args []string) error {
	op := classify(args)
	if op == "create" {
		manifest := os.Getenv("AGENTSUITE_GUARDD_MANIFEST")
		if manifest == "" {
			return fmt.Errorf("guarded create requires AGENTSUITE_GUARDD_MANIFEST")
		}
		if !filepath.IsAbs(manifest) {
			return fmt.Errorf("manifest path must be absolute")
		}
		if _, e := os.Stat(manifest); e != nil {
			return fmt.Errorf("read guarded create manifest: %w", e)
		}
	}
	c := exec.Command(underlying(), args...)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Env = os.Environ()
	return c.Run()
}
func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		if x, ok := e.(*exec.ExitError); ok {
			os.Exit(x.ExitCode())
		}
		os.Exit(125)
	}
}
