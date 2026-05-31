package conf

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudreve/Cloudreve/v3/pkg/util"
	"github.com/stretchr/testify/assert"
)

// 测试Init日志路径错误
func TestInitPanic(t *testing.T) {
	asserts := assert.New(t)

	// 日志路径不存在时
	asserts.NotPanics(func() {
		Init("not/exist/path/conf.ini")
	})

	asserts.True(util.Exists("not/exist/path/conf.ini"))

}

// TestInitDelimiterNotFound 日志路径存在但 Key 格式错误时
func TestInitDelimiterNotFound(t *testing.T) {
	asserts := assert.New(t)
	testCase := `[Database]
Type = mysql
User = root
Password233root
Host = 127.0.0.1:3306
Name = v3
TablePrefix = v3_`
	err := ioutil.WriteFile("testConf.ini", []byte(testCase), 0644)
	defer func() { err = os.Remove("testConf.ini") }()
	if err != nil {
		panic(err)
	}
	asserts.Panics(func() {
		Init("testConf.ini")
	})
}

// TestInitNoPanic 日志路径存在且合法时
func TestInitNoPanic(t *testing.T) {
	asserts := assert.New(t)
	testCase := `
[System]
Listen = 3000
HashIDSalt = 1

[Database]
Type = mysql
User = root
Password = root
Host = 127.0.0.1:3306
Name = v3
TablePrefix = v3_

[OptionOverwrite]
key=value
`
	err := ioutil.WriteFile("testConf.ini", []byte(testCase), 0644)
	defer func() { err = os.Remove("testConf.ini") }()
	if err != nil {
		panic(err)
	}
	asserts.NotPanics(func() {
		Init("testConf.ini")
	})
	asserts.Equal(OptionOverwrite["key"], "value")
}

func TestInitAccessLogConfig(t *testing.T) {
	asserts := assert.New(t)
	originalAccessLog := SystemConfig.AccessLog
	defer func() {
		SystemConfig.AccessLog = originalAccessLog
	}()
	SystemConfig.AccessLog = true

	testCase := `
[System]
Listen = 3000
HashIDSalt = 1
AccessLog = false
`
	err := ioutil.WriteFile("testConfAccessLog.ini", []byte(testCase), 0644)
	defer func() { _ = os.Remove("testConfAccessLog.ini") }()
	if err != nil {
		panic(err)
	}
	asserts.NotPanics(func() {
		Init("testConfAccessLog.ini")
	})
	asserts.False(SystemConfig.AccessLog)
}

func TestInitAccessLogDefault(t *testing.T) {
	asserts := assert.New(t)
	originalAccessLog := SystemConfig.AccessLog
	defer func() {
		SystemConfig.AccessLog = originalAccessLog
	}()
	SystemConfig.AccessLog = true

	testCase := `
[System]
Listen = 3000
HashIDSalt = 1
`
	err := ioutil.WriteFile("testConfAccessLogDefault.ini", []byte(testCase), 0644)
	defer func() { _ = os.Remove("testConfAccessLogDefault.ini") }()
	if err != nil {
		panic(err)
	}
	asserts.NotPanics(func() {
		Init("testConfAccessLogDefault.ini")
	})
	asserts.True(SystemConfig.AccessLog)
}

func TestMapSection(t *testing.T) {
	asserts := assert.New(t)

	//正常情况
	testCase := `
[System]
Listen = 3000
HashIDSalt = 1

[Database]
Type = mysql
User = root
Password:root
Host = 127.0.0.1:3306
Name = v3
TablePrefix = v3_`
	err := ioutil.WriteFile("testConf.ini", []byte(testCase), 0644)
	defer func() { err = os.Remove("testConf.ini") }()
	if err != nil {
		panic(err)
	}
	Init("testConf.ini")
	err = mapSection("Database", DatabaseConfig)
	asserts.NoError(err)

}

// 重置会话与SSL相关配置到默认值，避免包级变量在测试间泄漏
func resetSessionAndSSLDefaults() {
	SessionConfig.SameSite = "Lax"
	SessionConfig.Secure = false
	SSLConfig.CertPath = ""
	SSLConfig.KeyPath = ""
	SSLConfig.Listen = ":443"
}

// TestSessionSecureTLSDetection TLS 证书已配置时自动启用 Session Secure
func TestSessionSecureTLSDetection(t *testing.T) {
	asserts := assert.New(t)
	resetSessionAndSSLDefaults()
	defer resetSessionAndSSLDefaults()

	testCase := `
[System]
Listen = :5212
HashIDSalt = s1

[SSL]
CertPath = /path/to/cert.pem
KeyPath = /path/to/key.pem
Listen = :443
`
	err := ioutil.WriteFile("testConfTLS.ini", []byte(testCase), 0644)
	defer func() { _ = os.Remove("testConfTLS.ini") }()
	if err != nil {
		panic(err)
	}
	asserts.NotPanics(func() {
		Init("testConfTLS.ini")
	})
	asserts.True(SessionConfig.Secure,
		"TLS 证书配置后 Secure 应自动启用")
}

// TestSessionSecureExplicitOverride 用户显式设置后不被自动检测覆盖
func TestSessionSecureExplicitOverride(t *testing.T) {
	asserts := assert.New(t)
	resetSessionAndSSLDefaults()
	defer resetSessionAndSSLDefaults()

	testCase := `
[System]
Listen = :5212
HashIDSalt = s1

[SSL]
CertPath = /path/to/cert.pem
KeyPath = /path/to/key.pem
Listen = :443

[Session]
Secure = false
`
	err := ioutil.WriteFile("testConfOverride.ini", []byte(testCase), 0644)
	defer func() { _ = os.Remove("testConfOverride.ini") }()
	if err != nil {
		panic(err)
	}
	asserts.NotPanics(func() {
		Init("testConfOverride.ini")
	})
	asserts.False(SessionConfig.Secure,
		"用户显式设置 Secure=false 后不应被自动检测覆盖")
}

// TestSessionBackwardCompat CORS 段配置自动迁移到 Session 段
func TestSessionBackwardCompat(t *testing.T) {
	asserts := assert.New(t)
	resetSessionAndSSLDefaults()
	defer resetSessionAndSSLDefaults()

	testCase := `
[System]
Listen = :5212
HashIDSalt = s1

[CORS]
AllowOrigins = *
SameSite = strict
Secure = true
`
	err := ioutil.WriteFile("testConfCompat.ini", []byte(testCase), 0644)
	defer func() { _ = os.Remove("testConfCompat.ini") }()
	if err != nil {
		panic(err)
	}
	asserts.NotPanics(func() {
		Init("testConfCompat.ini")
	})
	asserts.Equal("strict", SessionConfig.SameSite,
		"旧 [CORS] SameSite 配置应迁移到 SessionConfig")
	asserts.True(SessionConfig.Secure,
		"旧 [CORS] Secure 配置应迁移到 SessionConfig")
}

// TestSessionNoTLSNoAutoEnable 无 TLS 时 Secure 保持默认 false
func TestSessionNoTLSNoAutoEnable(t *testing.T) {
	asserts := assert.New(t)
	resetSessionAndSSLDefaults()
	defer resetSessionAndSSLDefaults()

	testCase := `
[System]
Listen = :5212
HashIDSalt = s1
`
	err := ioutil.WriteFile("testConfNoTLS.ini", []byte(testCase), 0644)
	defer func() { _ = os.Remove("testConfNoTLS.ini") }()
	if err != nil {
		panic(err)
	}
	asserts.NotPanics(func() {
		Init("testConfNoTLS.ini")
	})
	asserts.False(SessionConfig.Secure,
		"无 TLS 配置时 Secure 应保持 false")
}

// TestSessionCorSSecureFalseWithTLS 用户通过 [CORS] 显式关闭 Secure 后，
// TLS 自动检测不应覆盖该决策（即使配置了 TLS 证书）。
func TestSessionCorSSecureFalseWithTLS(t *testing.T) {
	asserts := assert.New(t)
	resetSessionAndSSLDefaults()
	defer resetSessionAndSSLDefaults()

	testCase := `
[System]
Listen = :5212
HashIDSalt = s1

[SSL]
CertPath = /path/to/cert.pem
KeyPath = /path/to/key.pem
Listen = :443

[CORS]
AllowOrigins = *
Secure = false
`
	err := ioutil.WriteFile("testConfCORSFalseTLS.ini", []byte(testCase), 0644)
	defer func() { _ = os.Remove("testConfCORSFalseTLS.ini") }()
	if err != nil {
		panic(err)
	}
	asserts.NotPanics(func() {
		Init("testConfCORSFalseTLS.ini")
	})
	asserts.False(SessionConfig.Secure,
		"用户通过 [CORS] Secure=false 显式关闭后，TLS 自动检测不应覆盖")
}
