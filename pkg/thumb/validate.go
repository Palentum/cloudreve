package thumb

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ValidateExecutable 验证并解析可执行文件路径。
// 接受绝对路径（直接验证文件）或裸可执行文件名（通过 PATH 解析）。
// 拒绝相对路径，以降低管理员配置可执行路径时的权限提升风险。
func ValidateExecutable(executable string) (string, error) {
	cleaned := filepath.Clean(executable)

	// 拒绝空路径
	if len(cleaned) == 0 {
		return "", fmt.Errorf("executable path is empty")
	}

	// 拒绝含 null 字节
	for _, c := range cleaned {
		if c == 0 {
			return "", fmt.Errorf("executable path contains null byte")
		}
	}

	if filepath.IsAbs(cleaned) {
		// 绝对路径：直接验证文件属性
		return validateFileExecutable(cleaned, cleaned)
	}

	if strings.Contains(cleaned, string(filepath.Separator)) {
		// 相对路径（含分隔符）：拒绝
		return "", fmt.Errorf("executable must be a bare name or absolute path, not a relative path")
	}

	// 裸可执行文件名：通过 PATH 解析
	resolved, err := exec.LookPath(cleaned)
	if err != nil {
		return "", fmt.Errorf("executable not found in PATH: %w", err)
	}

	// 确保为绝对路径（PATH 可能含相对目录）
	if !filepath.IsAbs(resolved) {
		abs, err := filepath.Abs(resolved)
		if err != nil {
			return "", fmt.Errorf("failed to resolve absolute path: %w", err)
		}
		resolved = abs
	}

	return validateFileExecutable(resolved, cleaned)
}

// validateFileExecutable 验证文件存在、为普通文件且具有执行权限。
func validateFileExecutable(path, display string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("executable not found: %w", err)
	}

	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("executable is not a regular file: %s", display)
	}

	if info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("executable has no execute permission: %s", display)
	}

	return path, nil
}
