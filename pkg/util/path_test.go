package util

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDotPathToStandardPath(t *testing.T) {
	asserts := assert.New(t)

	asserts.Equal("/", DotPathToStandardPath(""))
	asserts.Equal("/目录", DotPathToStandardPath("目录"))
	asserts.Equal("/目录/目录2", DotPathToStandardPath("目录,目录2"))
}

func TestFillSlash(t *testing.T) {
	asserts := assert.New(t)
	asserts.Equal("/", FillSlash("/"))
	asserts.Equal("/", FillSlash(""))
	asserts.Equal("/123/", FillSlash("/123"))
}

func TestRemoveSlash(t *testing.T) {
	asserts := assert.New(t)
	asserts.Equal("/", RemoveSlash("/"))
	asserts.Equal("/123/1236", RemoveSlash("/123/1236"))
	asserts.Equal("/123/1236", RemoveSlash("/123/1236/"))
}

func TestSplitPath(t *testing.T) {
	asserts := assert.New(t)
	asserts.Equal([]string{}, SplitPath(""))
	asserts.Equal([]string{}, SplitPath("1"))
	asserts.Equal([]string{"/"}, SplitPath("/"))
	asserts.Equal([]string{"/", "123", "321"}, SplitPath("/123/321"))
}

func TestIsPathUnderRoot(t *testing.T) {
	asserts := assert.New(t)

	// 路径在根目录内
	asserts.True(IsPathUnderRoot("/data/uploads/file.txt", "/data/uploads"))
	asserts.True(IsPathUnderRoot("/data/uploads", "/data/uploads"))
	asserts.True(IsPathUnderRoot("/data/uploads/sub/dir/file.txt", "/data/uploads"))

	// 路径穿越：../逃逸
	asserts.False(IsPathUnderRoot("/data/uploads/../../etc/passwd", "/data/uploads"))
	asserts.False(IsPathUnderRoot("/data/other", "/data/uploads"))

	// 路径穿越：前缀匹配但不是子目录
	asserts.False(IsPathUnderRoot("/data/uploads_evil/file.txt", "/data/uploads"))
	asserts.False(IsPathUnderRoot("/data/uploads_backup", "/data/uploads"))

	// 绝对路径逃逸
	asserts.False(IsPathUnderRoot("/etc/passwd", "/data/uploads"))

	// Clean 后的路径穿越
	asserts.False(IsPathUnderRoot("/data/uploads/../secret", "/data/uploads"))
}
