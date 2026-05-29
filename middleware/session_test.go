package middleware

import (
	"github.com/cloudreve/Cloudreve/v3/pkg/conf"
	"github.com/cloudreve/Cloudreve/v3/pkg/util"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
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

// TestSessionSameSiteDefault 验证当配置 SameSite 值无效时，cookie 默认使用 Lax
func TestSessionSameSiteDefault(t *testing.T) {
	asserts := assert.New(t)

	// 保存原始配置
	originalSameSite := conf.SessionConfig.SameSite
	defer func() { conf.SessionConfig.SameSite = originalSameSite }()
	conf.SessionConfig.SameSite = "invalid"

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(Session("test-secret-samesite"))
	r.GET("/test", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set("key", "value")
		session.Save()
		c.String(200, "ok")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(rec, req)

	// 验证 Set-Cookie 头包含 SameSite=Lax
	setCookie := rec.Header().Get("Set-Cookie")
	asserts.Contains(setCookie, "SameSite=Lax",
		"当配置 SameSite 无效时应默认使用 Lax")
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

func TestCSRFProtectionCORSWildcardDoesNotTrustAllOrigins(t *testing.T) {
	asserts := assert.New(t)

	origins := conf.CORSConfig.AllowOrigins
	conf.CORSConfig.AllowOrigins = []string{"*"}
	defer func() { conf.CORSConfig.AllowOrigins = origins }()

	// CORS 的 * 不应让 CSRF 放行任意跨站 Origin
	{
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request, _ = http.NewRequest("POST", "/test", nil)
		c.Request.Host = "example.com"
		c.Request.Header.Set("Origin", "https://evil.com")
		CSRFProtection()(c)
		asserts.True(c.IsAborted())
	}

	// CORS 的 * 不应让 CSRF 放行任意跨站 Referer
	{
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request, _ = http.NewRequest("POST", "/test", nil)
		c.Request.Host = "example.com"
		c.Request.Header.Set("Referer", "https://evil.com/attack")
		CSRFProtection()(c)
		asserts.True(c.IsAborted())
	}

	// 同源请求仍然通过
	{
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request, _ = http.NewRequest("POST", "/test", nil)
		c.Request.Host = "example.com"
		c.Request.Header.Set("Origin", "https://example.com")
		CSRFProtection()(c)
		asserts.False(c.IsAborted())
	}
}
