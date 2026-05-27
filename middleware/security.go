package middleware

import (
	"github.com/cloudreve/Cloudreve/v3/pkg/conf"
	"github.com/gin-gonic/gin"
)

// SecurityHeaders 添加全局安全响应头
func SecurityHeaders() gin.HandlerFunc {
	hstsEnabled := conf.SSLConfig.CertPath != "" && conf.SSLConfig.KeyPath != ""

	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "SAMEORIGIN")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("X-XSS-Protection", "0")

		if hstsEnabled {
			c.Header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
	}
}
