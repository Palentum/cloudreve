package thumb

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// ValidateExecutable checks that the given path points to a real, executable regular file.
// It accepts both absolute paths and bare command names (resolved via PATH).
func ValidateExecutable(executable string) (string, error) {
	cleaned := filepath.Clean(executable)

	// Reject paths with null bytes
	if len(cleaned) == 0 {
		return "", fmt.Errorf("executable path is empty")
	}
	for _, c := range cleaned {
		if c == 0 {
			return "", fmt.Errorf("executable path contains null byte")
		}
	}

	// Bare name (e.g. "vips") — resolve through PATH
	if !filepath.IsAbs(cleaned) {
		resolved, err := exec.LookPath(cleaned)
		if err != nil {
			return "", fmt.Errorf("executable not found in PATH: %w", err)
		}
		// LookPath may return a relative path; make it absolute
		if !filepath.IsAbs(resolved) {
			abs, err := filepath.Abs(resolved)
			if err != nil {
				return "", fmt.Errorf("failed to resolve absolute path: %w", err)
			}
			resolved = abs
		}
		cleaned = resolved
	}

	info, err := os.Stat(cleaned)
	if err != nil {
		return "", fmt.Errorf("executable not found: %w", err)
	}

	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("executable is not a regular file: %s", cleaned)
	}

	if info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("executable has no execute permission: %s", cleaned)
	}

	return cleaned, nil
}
