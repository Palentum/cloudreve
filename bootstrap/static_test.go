package bootstrap

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudreve/Cloudreve/v3/pkg/conf"
	"github.com/cloudreve/Cloudreve/v3/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitStaticFallsBackToEmbeddedAssetsWhenDiskStaticsStale(t *testing.T) {
	oldStaticFS := StaticFS
	oldRequiredStaticVersion := conf.RequiredStaticVersion
	oldIsPro := conf.IsPro
	t.Cleanup(func() {
		StaticFS = oldStaticFS
		conf.RequiredStaticVersion = oldRequiredStaticVersion
		conf.IsPro = oldIsPro
	})
	conf.RequiredStaticVersion = "fresh"
	conf.IsPro = "false"

	staticsDir := util.RelativePath(StaticFolder)
	require.NoError(t, os.RemoveAll(staticsDir))
	t.Cleanup(func() {
		_ = os.RemoveAll(staticsDir)
	})
	require.NoError(t, os.MkdirAll(staticsDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(staticsDir, "version.json"), []byte(`{"name":"cloudreve-frontend","version":"stale"}`), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(staticsDir, "index.html"), []byte("disk"), 0600))

	InitStatic(NewFS(makeStaticZip(t, "fresh", "embedded")))

	assert.Equal(t, "embedded", readStaticFile(t, "/index.html"))
}

func makeStaticZip(t *testing.T, version, index string) string {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	addZipDir(t, zw, "assets/")
	addZipDir(t, zw, "assets/build/")
	addZipFile(t, zw, "assets/build/version.json", `{"name":"cloudreve-frontend","version":"`+version+`"}`)
	addZipFile(t, zw, "assets/build/index.html", index)
	require.NoError(t, zw.Close())
	return buf.String()
}

func addZipDir(t *testing.T, zw *zip.Writer, name string) {
	t.Helper()
	_, err := zw.Create(name)
	require.NoError(t, err)
}

func addZipFile(t *testing.T, zw *zip.Writer, name, content string) {
	t.Helper()
	w, err := zw.Create(name)
	require.NoError(t, err)
	_, err = w.Write([]byte(content))
	require.NoError(t, err)
}

func readStaticFile(t *testing.T, name string) string {
	t.Helper()
	f, err := StaticFS.Open(name)
	require.NoError(t, err)
	defer f.Close()
	b, err := io.ReadAll(f)
	require.NoError(t, err)
	return string(b)
}
