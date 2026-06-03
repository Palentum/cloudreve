package middleware

import (
	"fmt"
	"github.com/cloudreve/Cloudreve/v3/bootstrap"
	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/cloudreve/Cloudreve/v3/pkg/conf"
	"github.com/cloudreve/Cloudreve/v3/pkg/util"
	"github.com/gin-gonic/gin"
	"html"
	"html/template"
	"io/ioutil"
	"net/http"
	"strings"
)

// FrontendFileHandler 前端静态文件处理
func FrontendFileHandler() gin.HandlerFunc {
	ignoreFunc := func(c *gin.Context) {
		c.Next()
	}

	if bootstrap.StaticFS == nil {
		return ignoreFunc
	}

	// 读取index.html
	file, err := bootstrap.StaticFS.Open("/index.html")
	if err != nil {
		util.Log().Warning("Static file \"index.html\" does not exist, it might affect the display of the homepage.")
		return ignoreFunc
	}

	fileContentBytes, err := ioutil.ReadAll(file)
	if err != nil {
		util.Log().Warning("Cannot read static file \"index.html\", it might affect the display of the homepage.")
		return ignoreFunc
	}
	fileContent := string(fileContentBytes)

	fileServer := http.FileServer(bootstrap.StaticFS)
	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// API 跳过
		if strings.HasPrefix(path, "/api") ||
			strings.HasPrefix(path, "/custom") ||
			strings.HasPrefix(path, "/dav") ||
			strings.HasPrefix(path, "/f") ||
			path == "/manifest.json" {
			c.Next()
			return
		}

		// 不存在的路径和index.html均返回index.html
		if (path == "/index.html") || (path == "/") || !bootstrap.StaticFS.Exists("/", path) {
			// 读取、替换站点设置
			options := model.GetSettingByNames("siteName", "siteKeywords", "siteScript",
				"pwa_small_icon")
			finalHTML := util.Replace(map[string]string{
				"{siteName}":       html.EscapeString(options["siteName"]),
				"{siteDes}":        html.EscapeString(options["siteDes"]),
				"{siteScript}":     options["siteScript"],
				"{pwa_small_icon}": html.EscapeString(options["pwa_small_icon"]),
			}, fileContent)

			// 注入 Service Worker 自愈脚本：版本变更时自动注销旧 SW
			finalHTML = injectSWCleanup(finalHTML)

			c.Header("Content-Type", "text/html")
			c.String(200, finalHTML)
			c.Abort()
			return
		}

		if path == "/service-worker.js" {
			c.Header("Cache-Control", "private, no-cache, no-store, must-revalidate")
		}

		// 存在的静态文件
		fileServer.ServeHTTP(c.Writer, c.Request)
		c.Abort()
	}
}

// injectSWCleanup 在 index.html 中注入 Service Worker 自愈脚本。
// 当检测到后端版本变更时，自动注销所有旧 SW 并刷新页面，
// 解决升级后因旧 SW 缓存导致的白屏问题。
func injectSWCleanup(html string) string {
	// 作为 JS 字符串字面量注入到 script 标签内，必须同时转义引号和 </script>。
	ver := template.JSEscapeString(conf.BackendVersion)

	script := fmt.Sprintf(`<script>!function(){try{var k='sw_cleanup_ver',v='%s';if(localStorage.getItem(k)!==v){if('serviceWorker' in navigator){navigator.serviceWorker.getRegistrations().then(function(r){return Promise.all(r.map(function(i){return i.unregister()}))}).finally(function(){localStorage.setItem(k,v);window.location.reload()})}else{localStorage.setItem(k,v)}}}catch(e){}}</script>`, ver)

	// 注入到 </body> 之前；若无 </body> 则追加到末尾
	if idx := strings.LastIndex(html, "</body>"); idx != -1 {
		return html[:idx] + script + html[idx:]
	}
	return html + script
}
