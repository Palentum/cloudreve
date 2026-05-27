package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudreve/Cloudreve/v3/pkg/conf"
	"github.com/cloudreve/Cloudreve/v3/pkg/util"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestSession(t *testing.T) {
	asserts := assert.New(t)

	{
		handler := Session("2333")
		asserts.NotNil(handler)
		asserts.NotNil(Store)
		asserts.IsType(emptyFunc(), handler)
	}
}

func emptyFunc() gin.HandlerFunc {
	return func(c *gin.Context) {}
}

func TestCSRFInit(t *testing.T) {
	asserts := assert.New(t)
	rec := httptest.NewRecorder()
	sessionFunc := Session("233")
	{
		c, _ := gin.CreateTestContext(rec)
		c.Request, _ = http.NewRequest("GET", "/test", nil)
		sessionFunc(c)
		CSRFInit()(c)
		asserts.True(util.GetSession(c, "CSRF").(bool))
	}
}

func TestCSRFCheck(t *testing.T) {
	asserts := assert.New(t)
	rec := httptest.NewRecorder()
	sessionFunc := Session("233")

	// 通过检查
	{
		c, _ := gin.CreateTestContext(rec)
		c.Request, _ = http.NewRequest("GET", "/test", nil)
		sessionFunc(c)
		CSRFInit()(c)
		CSRFCheck()(c)
		asserts.False(c.IsAborted())
	}

	// 未通过检查
	{
		c, _ := gin.CreateTestContext(rec)
		c.Request, _ = http.NewRequest("GET", "/test", nil)
		sessionFunc(c)
		CSRFCheck()(c)
		asserts.True(c.IsAborted())
	}
}

func TestCSRFProtection(t *testing.T) {
	asserts := assert.New(t)

	// GET 请求直接放行
	{
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request, _ = http.NewRequest("GET", "/test", nil)
		CSRFProtection()(c)
		asserts.False(c.IsAborted())
	}

	// 无 Origin 无 Referer 放行
	{
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request, _ = http.NewRequest("POST", "/test", nil)
		CSRFProtection()(c)
		asserts.False(c.IsAborted())
	}

	// 同源 Origin 通过
	{
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request, _ = http.NewRequest("POST", "/test", nil)
		c.Request.Host = "example.com"
		c.Request.Header.Set("Origin", "https://example.com")
		CSRFProtection()(c)
		asserts.False(c.IsAborted())
	}

	// 跨域 Origin 无 CORS 配置时拒绝
	{
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request, _ = http.NewRequest("POST", "/test", nil)
		c.Request.Host = "example.com"
		c.Request.Header.Set("Origin", "https://evil.com")
		CSRFProtection()(c)
		asserts.True(c.IsAborted())
	}

	// Referer 同源通过
	{
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request, _ = http.NewRequest("POST", "/test", nil)
		c.Request.Host = "example.com"
		c.Request.Header.Set("Referer", "https://example.com/page")
		CSRFProtection()(c)
		asserts.False(c.IsAborted())
	}

	// Referer 跨域拒绝
	{
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request, _ = http.NewRequest("PUT", "/test", nil)
		c.Request.Host = "example.com"
		c.Request.Header.Set("Referer", "https://evil.com/attack")
		CSRFProtection()(c)
		asserts.True(c.IsAborted())
	}

	// HEAD 请求放行
	{
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request, _ = http.NewRequest("HEAD", "/test", nil)
		c.Request.Header.Set("Origin", "https://evil.com")
		CSRFProtection()(c)
		asserts.False(c.IsAborted())
	}

	// OPTIONS 请求放行
	{
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request, _ = http.NewRequest("OPTIONS", "/test", nil)
		c.Request.Header.Set("Origin", "https://evil.com")
		CSRFProtection()(c)
		asserts.False(c.IsAborted())
	}
}

func TestCSRFProtectionCORSAllowed(t *testing.T) {
	asserts := assert.New(t)

	// 临时修改 CORS 白名单
	origins := conf.CORSConfig.AllowOrigins
	conf.CORSConfig.AllowOrigins = []string{"https://trusted.com", "https://other.com"}
	defer func() { conf.CORSConfig.AllowOrigins = origins }()

	// CORS 白名单中的 origin 通过
	{
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request, _ = http.NewRequest("POST", "/test", nil)
		c.Request.Host = "example.com"
		c.Request.Header.Set("Origin", "https://trusted.com")
		CSRFProtection()(c)
		asserts.False(c.IsAborted())
	}

	// 不在白名单中的 origin 拒绝
	{
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request, _ = http.NewRequest("POST", "/test", nil)
		c.Request.Host = "example.com"
		c.Request.Header.Set("Origin", "https://evil.com")
		CSRFProtection()(c)
		asserts.True(c.IsAborted())
	}

	// 仅有 Referer 且在白名单中（修复前的 bug：Referer-only 场景白名单比对失效）
	{
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request, _ = http.NewRequest("POST", "/test", nil)
		c.Request.Host = "example.com"
		c.Request.Header.Set("Referer", "https://trusted.com/page")
		CSRFProtection()(c)
		asserts.False(c.IsAborted())
	}

	// 仅有 Referer 且不在白名单中（应拒绝）
	{
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request, _ = http.NewRequest("POST", "/test", nil)
		c.Request.Host = "example.com"
		c.Request.Header.Set("Referer", "https://evil.com/attack")
		CSRFProtection()(c)
		asserts.True(c.IsAborted())
	}
}
