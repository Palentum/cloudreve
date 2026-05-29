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
		c.Header("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://recaptcha.net https://www.recaptcha.net https://ssl.captcha.qq.com; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data: blob: https:; "+
				"font-src 'self' data:; "+
				"connect-src 'self' https://www.google.com https://recaptcha.net https://www.recaptcha.net https://ssl.captcha.qq.com https://captcha.tencentcloudapi.com; "+
				"frame-src 'self' https://www.google.com https://recaptcha.net https://www.recaptcha.net")

		if hstsEnabled {
			c.Header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
	}
}