package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/cloudreve/Cloudreve/v3/pkg/cache"
	"github.com/cloudreve/Cloudreve/v3/pkg/conf"
	"github.com/cloudreve/Cloudreve/v3/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v3/pkg/sessionstore"
	"github.com/cloudreve/Cloudreve/v3/pkg/util"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// Store session存储
var Store sessions.Store

// Session 初始化session
func Session(secret string) gin.HandlerFunc {
	// Redis设置不为空，且非测试模式时使用Redis
	Store = sessionstore.NewStore(cache.Store, []byte(secret))

	sameSiteMode := http.SameSiteLaxMode
	switch strings.ToLower(conf.CORSConfig.SameSite) {
	case "default":
		sameSiteMode = http.SameSiteDefaultMode
	case "none":
		sameSiteMode = http.SameSiteNoneMode
	case "strict":
		sameSiteMode = http.SameSiteStrictMode
	case "lax":
		sameSiteMode = http.SameSiteLaxMode
	}

	// Also set Secure: true if using SSL, you should though
	Store.Options(sessions.Options{
		HttpOnly: true,
		MaxAge:   60 * 86400,
		Path:     "/",
		SameSite: sameSiteMode,
		Secure:   conf.CORSConfig.Secure,
	})

	return sessions.Sessions("cloudreve-session", Store)
}

// CSRFInit 初始化CSRF标记
func CSRFInit() gin.HandlerFunc {
	return func(c *gin.Context) {
		util.SetSession(c, map[string]interface{}{"CSRF": true})
		c.Next()
	}
}

// CSRFCheck 检查CSRF标记
func CSRFCheck() gin.HandlerFunc {
	return func(c *gin.Context) {
		if check, ok := util.GetSession(c, "CSRF").(bool); ok && check {
			c.Next()
			return
		}

		c.JSON(200, serializer.Err(serializer.CodeNoPermissionErr, "Invalid origin", nil))
		c.Abort()
	}
}

// CSRFProtection 通过校验 Origin/Referer 头防御 CSRF 攻击。
// 仅校验非安全方法（POST/PUT/PATCH/DELETE），GET/HEAD/OPTIONS 直接放行。
// 允许无 Origin 的请求（非浏览器客户端、部分隐私模式浏览器），依赖 SameSite cookie 兜底。
func CSRFProtection() gin.HandlerFunc {
	// 从 CORS 白名单 URL 中提取 host，用于后续比对。
	// CORS 的 "*" 不代表 CSRF 可信来源，不能用于放行跨站写请求。
	allowedHosts := make(map[string]bool)
	for _, o := range conf.CORSConfig.AllowOrigins {
		if o == "*" {
			continue
		}
		u, err := url.Parse(o)
		if err == nil && u.Host != "" {
			allowedHosts[strings.ToLower(u.Host)] = true
		}
	}

	return func(c *gin.Context) {
		method := c.Request.Method
		if method == "GET" || method == "HEAD" || method == "OPTIONS" {
			c.Next()
			return
		}

		origin := c.GetHeader("Origin")
		referer := c.GetHeader("Referer")

		if origin == "" && referer == "" {
			c.Next()
			return
		}

		var host string
		if origin != "" {
			u, err := url.Parse(origin)
			if err != nil {
				c.JSON(200, serializer.Err(serializer.CodeNoPermissionErr, "Invalid origin", nil))
				c.Abort()
				return
			}
			host = u.Host
		} else {
			u, err := url.Parse(referer)
			if err != nil {
				c.JSON(200, serializer.Err(serializer.CodeNoPermissionErr, "Invalid origin", nil))
				c.Abort()
				return
			}
			host = u.Host
		}

		host = strings.ToLower(host)
		reqHost := strings.ToLower(c.Request.Host)
		if host == reqHost {
			c.Next()
			return
		}

		if allowedHosts[host] {
			c.Next()
			return
		}

		util.Log().Warning("CSRF: rejected cross-origin %s %s (host=%s, reqHost=%s)",
			method, c.Request.URL.Path, host, c.Request.Host)
		c.JSON(200, serializer.Err(serializer.CodeNoPermissionErr, "Cross-origin request rejected", nil))
		c.Abort()
	}
}
