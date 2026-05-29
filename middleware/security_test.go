package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudreve/Cloudreve/v3/pkg/conf"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestSecurityHeaders(t *testing.T) {
	a := assert.New(t)

	// 不启用 HSTS（SSL 未配置）
	conf.SSLConfig.CertPath = ""
	conf.SSLConfig.KeyPath = ""

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request, _ = http.NewRequest("GET", "/", nil)

	SecurityHeaders()(c)

	a.Equal("nosniff", c.Writer.Header().Get("X-Content-Type-Options"))
	a.Equal("SAMEORIGIN", c.Writer.Header().Get("X-Frame-Options"))
	a.Equal("strict-origin-when-cross-origin", c.Writer.Header().Get("Referrer-Policy"))
 	a.Equal("0", c.Writer.Header().Get("X-XSS-Protection"))
	a.Contains(c.Writer.Header().Get("Content-Security-Policy"), "default-src 'self'")
 	a.Empty(c.Writer.Header().Get("Strict-Transport-Security"))
}

func TestSecurityHeadersWithHSTS(t *testing.T) {
	a := assert.New(t)

	// 启用 HSTS（SSL 已配置）
	conf.SSLConfig.CertPath = "/path/to/cert"
	conf.SSLConfig.KeyPath = "/path/to/key"
	defer func() {
		conf.SSLConfig.CertPath = ""
		conf.SSLConfig.KeyPath = ""
	}()

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request, _ = http.NewRequest("GET", "/", nil)

	SecurityHeaders()(c)

	a.Equal("nosniff", c.Writer.Header().Get("X-Content-Type-Options"))
	a.Equal("SAMEORIGIN", c.Writer.Header().Get("X-Frame-Options"))
	a.Equal("max-age=63072000; includeSubDomains", c.Writer.Header().Get("Strict-Transport-Security"))
}
