package middleware

import (
	"errors"
	"github.com/cloudreve/Cloudreve/v3/bootstrap"
	"github.com/cloudreve/Cloudreve/v3/pkg/cache"
	"github.com/cloudreve/Cloudreve/v3/pkg/conf"
	"github.com/cloudreve/Cloudreve/v3/pkg/util"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	testMock "github.com/stretchr/testify/mock"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type StaticMock struct {
	testMock.Mock
}

func (m StaticMock) Open(name string) (http.File, error) {
	args := m.Called(name)
	return args.Get(0).(http.File), args.Error(1)
}

func (m StaticMock) Exists(prefix string, filepath string) bool {
	args := m.Called(prefix, filepath)
	return args.Bool(0)
}

func TestFrontendFileHandler(t *testing.T) {
	asserts := assert.New(t)
	rec := httptest.NewRecorder()

	// 静态资源未加载
	{
		TestFunc := FrontendFileHandler()

		c, _ := gin.CreateTestContext(rec)
		c.Params = []gin.Param{}
		c.Request, _ = http.NewRequest("GET", "/", nil)
		TestFunc(c)
		asserts.False(c.IsAborted())
	}

	// index.html 不存在
	{
		testStatic := &StaticMock{}
		bootstrap.StaticFS = testStatic
		testStatic.On("Open", "/index.html").
			Return(&os.File{}, errors.New("error"))
		TestFunc := FrontendFileHandler()

		c, _ := gin.CreateTestContext(rec)
		c.Params = []gin.Param{}
		c.Request, _ = http.NewRequest("GET", "/", nil)
		TestFunc(c)
		asserts.False(c.IsAborted())
	}

	// index.html 读取失败
	{
		file, _ := util.CreatNestedFile("tests/index.html")
		file.Close()
		testStatic := &StaticMock{}
		bootstrap.StaticFS = testStatic
		testStatic.On("Open", "/index.html").
			Return(file, nil)
		TestFunc := FrontendFileHandler()

		c, _ := gin.CreateTestContext(rec)
		c.Params = []gin.Param{}
		c.Request, _ = http.NewRequest("GET", "/", nil)
		TestFunc(c)
		asserts.False(c.IsAborted())
	}

	// 成功且命中
	{
		file, _ := util.CreatNestedFile("tests/index.html")
		defer file.Close()
		testStatic := &StaticMock{}
		bootstrap.StaticFS = testStatic
		testStatic.On("Open", "/index.html").
			Return(file, nil)
		TestFunc := FrontendFileHandler()

		c, _ := gin.CreateTestContext(rec)
		c.Params = []gin.Param{}
		c.Request, _ = http.NewRequest("GET", "/", nil)

		cache.Set("setting_siteName", "cloudreve", 0)
		cache.Set("setting_siteKeywords", "cloudreve", 0)
		cache.Set("setting_siteScript", "cloudreve", 0)
		cache.Set("setting_pwa_small_icon", "cloudreve", 0)

		TestFunc(c)
		asserts.True(c.IsAborted())
	}
	// XSS 防护 — siteName/siteDes/pwa_small_icon 应被转义，siteScript 保留原始内容
	{
		file, _ := util.CreatNestedFile("tests/index_xss.html")
		htmlContent := "<title>{siteName}</title><meta content=\"{siteDes}\"><link href=\"{pwa_small_icon}\">{siteScript}"
		file.WriteString(htmlContent)
		file.Seek(0, 0)
		defer file.Close()
		testStatic := &StaticMock{}
		bootstrap.StaticFS = testStatic
		testStatic.On("Open", "/index.html").
			Return(file, nil)
		TestFunc := FrontendFileHandler()
		c, _ := gin.CreateTestContext(rec)
		c.Params = []gin.Param{}
		c.Request, _ = http.NewRequest("GET", "/", nil)
		cache.Set("setting_siteName", "<script>alert(1)</script>", 0)
		cache.Set("setting_siteDes", "\" onload=\"alert(1)", 0)
		cache.Set("setting_siteScript", "<script>safe</script>", 0)
		cache.Set("setting_pwa_small_icon", "\" onerror=\"alert(1)", 0)
		TestFunc(c)
		body := rec.Body.String()
		asserts.NotContains(body, "<script>alert(1)</script>",
			"siteName 中的 script 标签应被转义")
		asserts.NotContains(body, "\" onload=\"alert(1)",
			"siteDes 中的属性注入应被转义")
		asserts.NotContains(body, "\" onerror=\"alert(1)",
			"pwa_small_icon 中的属性注入应被转义")
		asserts.Contains(body, "<script>safe</script>",
			"siteScript 应保留原始 HTML")
	}

	// 成功且命中静态文件
	{
		file, _ := util.CreatNestedFile("tests/index.html")
		defer file.Close()
		testStatic := &StaticMock{}
		bootstrap.StaticFS = testStatic
		testStatic.On("Open", "/index.html").
			Return(file, nil)
		testStatic.On("Exists", "/", "/2").
			Return(true)
		testStatic.On("Open", "/2").
			Return(file, nil)
		TestFunc := FrontendFileHandler()

		c, _ := gin.CreateTestContext(rec)
		c.Params = []gin.Param{}
		c.Request, _ = http.NewRequest("GET", "/2", nil)

		TestFunc(c)
		asserts.True(c.IsAborted())
		testStatic.AssertExpectations(t)
	}

	// API 相关跳过
	{
		for _, reqPath := range []string{"/api/user", "/manifest.json", "/dav/path"} {
			file, _ := util.CreatNestedFile("tests/index.html")
			defer file.Close()
			testStatic := &StaticMock{}
			bootstrap.StaticFS = testStatic
			testStatic.On("Open", "/index.html").
				Return(file, nil)
			TestFunc := FrontendFileHandler()

			c, _ := gin.CreateTestContext(rec)
			c.Params = []gin.Param{}
			c.Request, _ = http.NewRequest("GET", reqPath, nil)

			TestFunc(c)
			asserts.False(c.IsAborted())
		}
	}

}

func TestInjectSWCleanup(t *testing.T) {
	asserts := assert.New(t)

	oldVersion := conf.BackendVersion
	conf.BackendVersion = "3.8.6'\\</script><script>alert(1)</script>"
	t.Cleanup(func() {
		conf.BackendVersion = oldVersion
	})

	withBody := injectSWCleanup("<html><body><main></main></body></html>")
	asserts.Contains(withBody, "sw_cleanup_ver")
	asserts.Contains(withBody, `v='3.8.6\'\\\u003C/script\u003E\u003Cscript\u003Ealert(1)\u003C/script\u003E'`)
	asserts.Contains(withBody, "navigator.serviceWorker.getRegistrations()")
	asserts.NotContains(withBody, "</script><script>alert(1)")
	asserts.True(
		strings.Index(withBody, "sw_cleanup_ver") < strings.Index(withBody, "</body>"),
		"cleanup script should be injected before closing body",
	)

	withoutBody := injectSWCleanup("<html></html>")
	asserts.True(strings.HasSuffix(withoutBody, "</script>"))
}
