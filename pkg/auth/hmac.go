package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"strconv"
	"strings"
	"time"
)

// HMACAuth HMAC算法鉴权
type HMACAuth struct {
	SecretKey []byte
}

// Sign 对给定Body生成expires后失效的签名，expires为过期时间戳，
// 填写为0表示不限制有效期
func (auth HMACAuth) Sign(body string, expires int64) string {
	sum, expireTimeStamp := auth.signatureSum(body, expires)
	return encodeSign(sum, expireTimeStamp, base64.URLEncoding)
}

func (auth HMACAuth) signatureSum(body string, expires int64) ([]byte, string) {
	h := hmac.New(sha256.New, auth.SecretKey)
	expireTimeStamp := strconv.FormatInt(expires, 10)
	_, err := io.WriteString(h, body+":"+expireTimeStamp)
	if err != nil {
		return nil, ""
	}

	return h.Sum(nil), expireTimeStamp
}

func encodeSign(sum []byte, expireTimeStamp string, encoding *base64.Encoding) string {
	if sum == nil {
		return ""
	}

	return encoding.EncodeToString(sum) + ":" + expireTimeStamp
}

// Check 对给定Body和Sign进行鉴权，包括对expires的检查
func (auth HMACAuth) Check(body string, sign string) error {
	signSlice := strings.Split(sign, ":")
	// 如果未携带expires字段
	if signSlice[len(signSlice)-1] == "" {
		return ErrExpiresMissing
	}

	// 验证是否过期
	expires, err := strconv.ParseInt(signSlice[len(signSlice)-1], 10, 64)
	if err != nil {
		return ErrAuthFailed.WithError(err)
	}
	// 如果签名过期
	if expires < time.Now().Unix() && expires != 0 {
		return ErrExpired
	}

	// 验证签名
	signSum, expireTimeStamp := auth.signatureSum(body, expires)
	paddedSign := encodeSign(signSum, expireTimeStamp, base64.URLEncoding)
	rawSign := encodeSign(signSum, expireTimeStamp, base64.RawURLEncoding)
	if subtle.ConstantTimeCompare([]byte(paddedSign), []byte(sign)) != 1 &&
		subtle.ConstantTimeCompare([]byte(rawSign), []byte(sign)) != 1 {
		return ErrAuthFailed
	}
	return nil
}
