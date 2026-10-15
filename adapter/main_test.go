package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassify(t *testing.T) {
	if classify([]string{"--root", "/x", "delete", "id"}) != "delete" {
		t.Fatal("wrong classification")
	}
}
func TestNonCreateDoesNotReadManifest(t *testing.T) {
	d := t.TempDir()
	runtime := filepath.Join(d, "runtime")
	os.WriteFile(runtime, []byte("#!/bin/sh\nexit 0\n"), 0700)
	t.Setenv("AGENTSUITE_GUARDD_UNDERLYING_RUNTIME", runtime)
	t.Setenv("AGENTSUITE_GUARDD_MANIFEST", filepath.Join(d, "absent"))
	if e := run([]string{"delete", "id"}); e != nil {
		t.Fatal(e)
	}
}
func TestCreateFailsBeforeRuntime(t *testing.T) {
	t.Setenv("AGENTSUITE_GUARDD_UNDERLYING_RUNTIME", "/bin/true")
	t.Setenv("AGENTSUITE_GUARDD_MANIFEST", "")
	if e := run([]string{"create", "id"}); e == nil {
		t.Fatal("accepted unguarded create")
	}
}
