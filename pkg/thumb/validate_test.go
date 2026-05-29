package thumb

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateExecutable_EmptyPath(t *testing.T) {
	_, err := ValidateExecutable("")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestValidateExecutable_NonexistentFile(t *testing.T) {
	_, err := ValidateExecutable("/nonexistent/binary/that/does/not/exist")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestValidateExecutable_Directory(t *testing.T) {
	dir := t.TempDir()
	_, err := ValidateExecutable(dir)
	if err == nil {
		t.Error("expected error for directory")
	}
}

func TestValidateExecutable_NoExecPermission(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "noexec")
	if err := os.WriteFile(f, []byte("#!/bin/sh\necho hi"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := ValidateExecutable(f)
	if err == nil {
		t.Error("expected error for non-executable file")
	}
}

func TestValidateExecutable_ValidAbsolute(t *testing.T) {
	// 绝对路径现在应被拒绝 — 仅接受裸可执行文件名
	dir := t.TempDir()
	f := filepath.Join(dir, "mybin")
	if err := os.WriteFile(f, []byte("#!/bin/sh\necho hi"), 0755); err != nil {
		t.Fatal(err)
	}
	_, err := ValidateExecutable(f)
	if err == nil {
		t.Error("expected error for absolute path (bare names only)")
	}
}

func TestValidateExecutable_RelativePath(t *testing.T) {
	// 相对路径（含分隔符）应被拒绝
	_, err := ValidateExecutable("./something")
	if err == nil {
		t.Error("expected error for relative path")
	}
}

func TestValidateExecutable_ValidBasename(t *testing.T) {
	// "go" should be in PATH on any dev machine
	resolved, err := ValidateExecutable("go")
	if err != nil {
		t.Fatalf("unexpected error for 'go' in PATH: %v", err)
	}
	if !filepath.IsAbs(resolved) {
		t.Errorf("expected absolute path, got %s", resolved)
	}
}

func TestValidateExecutable_BareNotFound(t *testing.T) {
	_, err := ValidateExecutable("definitely_not_a_real_binary_name_12345")
	if err == nil {
		t.Error("expected error for nonexistent bare name")
	}
}
