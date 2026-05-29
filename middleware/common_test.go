package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudreve/Cloudreve/v3/pkg/cache"
	"github.com/cloudreve/Cloudreve/v3/pkg/hashid"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHashID(t *testing.T) {
	asserts := assert.New(t)
	rec := httptest.NewRecorder()
	TestFunc := HashID(hashid.FolderID)

	// 未给定ID对象，跳过
	{
		c, _ := gin.CreateTestContext(rec)
		c.Params = []gin.Param{}
		c.Request, _ = http.NewRequest("POST", "/api/v3/file/dellete/1", nil)
		TestFunc(c)
		asserts.NoError(mock.ExpectationsWereMet())
		asserts.False(c.IsAborted())
	}

	// 给定ID，解析失败
	{
		c, _ := gin.CreateTestContext(rec)
		c.Params = []gin.Param{
			{"id", "2333"},
		}
		c.Request, _ = http.NewRequest("POST", "/api/v3/file/dellete/1", nil)
		TestFunc(c)
		asserts.NoError(mock.ExpectationsWereMet())
		asserts.True(c.IsAborted())
	}

	// 给定ID，解析成功
	{
		c, _ := gin.CreateTestContext(rec)
		c.Params = []gin.Param{
			{"id", hashid.HashID(1, hashid.FolderID)},
		}
		c.Request, _ = http.NewRequest("POST", "/api/v3/file/dellete/1", nil)
		TestFunc(c)
		asserts.NoError(mock.ExpectationsWereMet())
		asserts.False(c.IsAborted())
	}
}

func TestIsFunctionEnabled(t *testing.T) {
	asserts := assert.New(t)
	rec := httptest.NewRecorder()
	TestFunc := IsFunctionEnabled("TestIsFunctionEnabled")

	// 未开启
	{
		cache.Set("setting_TestIsFunctionEnabled", "0", 0)
		c, _ := gin.CreateTestContext(rec)
		c.Params = []gin.Param{}
		c.Request, _ = http.NewRequest("POST", "/api/v3/file/dellete/1", nil)
		TestFunc(c)
		asserts.True(c.IsAborted())
	}
	// 开启
	{
		cache.Set("setting_TestIsFunctionEnabled", "1", 0)
		c, _ := gin.CreateTestContext(rec)
		c.Params = []gin.Param{}
		c.Request, _ = http.NewRequest("POST", "/api/v3/file/dellete/1", nil)
		TestFunc(c)
		asserts.False(c.IsAborted())
	}

}

func TestCacheControl(t *testing.T) {
	a := assert.New(t)
	TestFunc := CacheControl()
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	TestFunc(c)
	a.Contains(c.Writer.Header().Get("Cache-Control"), "no-cache")
}

func TestSandbox(t *testing.T) {
	a := assert.New(t)
	TestFunc := Sandbox()
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	TestFunc(c)
	a.Contains(c.Writer.Header().Get("Content-Security-Policy"), "sandbox")
}

func TestStaticResourceCache(t *testing.T) {
	a := assert.New(t)
	TestFunc := StaticResourceCache()
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	TestFunc(c)
	a.Contains(c.Writer.Header().Get("Cache-Control"), "public, max-age")
}

func TestHTTPStatusForCode(t *testing.T) {
	asserts := assert.New(t)

	// 三位错误码直接复用 HTTP 语义
	asserts.Equal(401, httpStatusForCode(401))
	asserts.Equal(403, httpStatusForCode(403))
	asserts.Equal(404, httpStatusForCode(404))
	asserts.Equal(409, httpStatusForCode(409))

	// 成功码 200
	asserts.Equal(200, httpStatusForCode(200))

	// 4xxxx 统一映射为 400
	asserts.Equal(400, httpStatusForCode(40001))
	asserts.Equal(400, httpStatusForCode(40044))
	asserts.Equal(400, httpStatusForCode(40020))

	// 5xxxx 统一映射为 500
	asserts.Equal(500, httpStatusForCode(50001))
	asserts.Equal(500, httpStatusForCode(50002))

	// CodeNotSet (-1) 映射为 500
	asserts.Equal(500, httpStatusForCode(-1))

	// 其他未知码映射为 500
	// 成功码 0 映射为 200
	asserts.Equal(200, httpStatusForCode(0))

	// 其他未知码映射为 500
	asserts.Equal(500, httpStatusForCode(199))
}
