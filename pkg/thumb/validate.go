package thumb

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ValidateExecutable 验证给定的名称指向 PATH 中的一个真实、可执行的普通文件。
// 仅接受裸可执行文件名（不含路径分隔符），拒绝绝对路径和相对路径，
// 以降低管理员配置可执行路径时的权限提升风险。
func ValidateExecutable(executable string) (string, error) {
	cleaned := filepath.Clean(executable)

	// 拒绝空路径
	if len(cleaned) == 0 {
		return "", fmt.Errorf("executable path is empty")
	}

	// 拒绝含路径分隔符或绝对路径，仅允许裸可执行文件名
	if strings.Contains(cleaned, string(filepath.Separator)) || filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("executable must be a bare name, not a path")
	}

	// 拒绝含 null 字节
	for _, c := range cleaned {
		if c == 0 {
			return "", fmt.Errorf("executable path contains null byte")
		}
	}

	// 通过 PATH 解析
	resolved, err := exec.LookPath(cleaned)
	if err != nil {
		return "", fmt.Errorf("executable not found in PATH: %w", err)
	}

	// 确保为绝对路径
	if !filepath.IsAbs(resolved) {
		abs, err := filepath.Abs(resolved)
		if err != nil {
			return "", fmt.Errorf("failed to resolve absolute path: %w", err)
		}
		resolved = abs
	}

	// 验证文件属性
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("executable not found: %w", err)
	}

	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("executable is not a regular file: %s", cleaned)
	}

	if info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("executable has no execute permission: %s", cleaned)
	}

	return resolved, nil
}
