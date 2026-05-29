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

func TestValidateExecutable_NullByte(t *testing.T) {
	_, err := ValidateExecutable("vips\x00hidden")
	if err == nil {
		t.Error("expected error for path containing null byte")
	}
}

func TestValidateExecutable_NonexistentFile(t *testing.T) {
	_, err := ValidateExecutable("/nonexistent/binary/that/does/not/exist")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}
// 绝对路径应被接受并直接验证
func TestValidateExecutable_ValidAbsolute(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "mybin")
	if err := os.WriteFile(f, []byte("#!/bin/sh\necho hi"), 0755); err != nil {
		t.Fatal(err)
	}
	resolved, err := ValidateExecutable(f)
	if err != nil {
		t.Fatalf("unexpected error for valid absolute path: %v", err)
	}
	if resolved != f {
		t.Errorf("expected %s, got %s", f, resolved)
	}
}

func TestValidateExecutable_AbsoluteNotRegular(t *testing.T) {
	// 绝对路径指向目录 → 应失败
	dir := t.TempDir()
	_, err := ValidateExecutable(dir)
	if err == nil {
		t.Error("expected error for absolute path pointing to directory")
	}
}

func TestValidateExecutable_AbsoluteNoExec(t *testing.T) {
	// 绝对路径指向无执行权限的文件 → 应失败
	dir := t.TempDir()
	f := filepath.Join(dir, "noexec")
	if err := os.WriteFile(f, []byte("#!/bin/sh\necho hi"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := ValidateExecutable(f)
	if err == nil {
		t.Error("expected error for absolute path without exec permission")
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
