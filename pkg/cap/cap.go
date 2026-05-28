package cap

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/cloudreve/Cloudreve/v3/pkg/cache"
)

const (
	// HeaderName is the request header used by protected Cloudreve endpoints.
	HeaderName = "X-Cap-Token"

	challengeCachePrefix = "cap_challenge_"
	tokenCachePrefix     = "cap_token_"

	defaultChallengeCount      = 50
	defaultChallengeSize       = 32
	defaultChallengeDifficulty = 4
)

// challengeIPPrefix 用于按 IP 限制挑战创建频率。
const challengeIPPrefix = "cap_ip_"

const maxChallengePerIP = 20

var (
	defaultChallengeTTL = 10 * time.Minute
	defaultTokenTTL     = 20 * time.Minute
)

type challengeConfig struct {
	count      int
	size       int
	difficulty int
	ip         string // 客户端 IP，仅用于频率统计
	ttl        time.Duration
}

type challengeState struct {
	Count      int
	Size       int
	Difficulty int
	Expires    int64
}

// Challenge contains Cap proof-of-work parameters.
type Challenge struct {
	C int `json:"c"`
	S int `json:"s"`
	D int `json:"d"`
}

// ChallengeResponse is the wire format consumed by cap-widget.
type ChallengeResponse struct {
	Challenge Challenge `json:"challenge"`
	Token     string    `json:"token"`
	Expires   int64     `json:"expires"`
}

// RedeemRequest is submitted by cap-widget after solving the challenge.
type RedeemRequest struct {
	Token     string   `json:"token"`
	Solutions []uint64 `json:"solutions"`
}

// RedeemResponse is the wire format consumed by cap-widget.
type RedeemResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token,omitempty"`
	Expires int64  `json:"expires,omitempty"`
	Error   string `json:"error,omitempty"`
}

func init() {
	gob.Register(challengeState{})
}

// CreateChallengeForIP 创建挑战，按 IP 限制频率。
func CreateChallengeForIP(ip string) (ChallengeResponse, error) {
	key := challengeIPPrefix + ip
	if count, ok := cache.Get(key); ok {
		if n, ok := count.(int); ok && n >= maxChallengePerIP {
			return ChallengeResponse{}, errors.New("rate limited")
		}
	}
	return createChallenge(challengeConfig{ip: ip})
}

// CreateChallenge creates a default Cap challenge (no rate limiting).
func CreateChallenge() (ChallengeResponse, error) {
	return createChallenge(challengeConfig{})
}

func createChallenge(config challengeConfig) (ChallengeResponse, error) {
	config = normalizeConfig(config)
	if err := validateConfig(config); err != nil {
		return ChallengeResponse{}, err
	}

	token, err := randomHex(32)
	if err != nil {
		return ChallengeResponse{}, err
	}

	expires := time.Now().Add(config.ttl).UnixMilli()
	state := challengeState{
		Count:      config.count,
		Size:       config.size,
		Difficulty: config.difficulty,
		Expires:    expires,
	}

	// 按 IP 计数，限制频率
	if config.ip != "" {
		key := challengeIPPrefix + config.ip
		n := 0
		if c, ok := cache.Get(key); ok {
			if v, ok := c.(int); ok {
				n = v
			}
		}
		_ = cache.Set(key, n+1, int(config.ttl.Seconds()))
	}

	if err := cache.Set(challengeCachePrefix+token, state, int(config.ttl.Seconds())); err != nil {
		return ChallengeResponse{}, err
	}

	return ChallengeResponse{
		Challenge: Challenge{C: config.count, S: config.size, D: config.difficulty},
		Token:     token,
		Expires:   expires,
	}, nil
}

// RedeemChallenge verifies a solved challenge and issues a short-lived token.
func RedeemChallenge(req RedeemRequest) RedeemResponse {
	if req.Token == "" || len(req.Solutions) == 0 {
		return redeemFailure("Invalid body")
	}

	rawState, ok := cache.Get(challengeCachePrefix + req.Token)
	if !ok {
		return redeemFailure("Challenge expired")
	}

	state, ok := rawState.(challengeState)
	if !ok || state.Expires < time.Now().UnixMilli() {
		return redeemFailure("Challenge expired")
	}

	if len(req.Solutions) != state.Count {
		return redeemFailure("Invalid solution")
	}

	if !validateSolutions(req.Token, req.Solutions, state) {
		return redeemFailure("Invalid solution")
	}

	// 先删除 challenge 防止并发重放
	_ = cache.Deletes([]string{req.Token}, challengeCachePrefix)

	// 签发验证 token；失败时回滚 challenge，允许客户端重试
	verificationToken, tokenKey, err := newVerificationToken()
	if err != nil {
		_ = cache.Set(challengeCachePrefix+req.Token, state, int(time.Until(time.UnixMilli(state.Expires)).Seconds()))
		return redeemFailure("Failed to issue token")
	}

	expires := time.Now().Add(defaultTokenTTL).UnixMilli()
	if err := cache.Set(tokenCachePrefix+tokenKey, true, int(defaultTokenTTL.Seconds())); err != nil {
		_ = cache.Set(challengeCachePrefix+req.Token, state, int(time.Until(time.UnixMilli(state.Expires)).Seconds()))
		return redeemFailure("Failed to issue token")
	}

	return RedeemResponse{Success: true, Token: verificationToken, Expires: expires}
}

// ValidateToken checks a token issued by RedeemChallenge.
// 当 keepToken 为 true 时，token 在有效期内可复用，以支持批量下载场景。
// 分享下载有独立的下载次数限制，不会因为 token 复用而绕过。
func ValidateToken(token string, keepToken bool) bool {
	tokenKey, ok := verificationTokenKey(token)
	if !ok {
		return false
	}

	if _, ok = cache.Get(tokenCachePrefix + tokenKey); !ok {
		return false
	}

	if !keepToken {
		_ = cache.Deletes([]string{tokenKey}, tokenCachePrefix)
	}

	return true
}

func normalizeConfig(config challengeConfig) challengeConfig {
	if config.count == 0 {
		config.count = defaultChallengeCount
	}
	if config.size == 0 {
		config.size = defaultChallengeSize
	}
	if config.difficulty == 0 {
		config.difficulty = defaultChallengeDifficulty
	}
	if config.ttl == 0 {
		config.ttl = defaultChallengeTTL
	}
	return config
}

func validateConfig(config challengeConfig) error {
	if config.count < 1 || config.count > 1000 {
		return errors.New("invalid challenge count")
	}
	if config.size < 1 || config.size > 256 {
		return errors.New("invalid challenge size")
	}
	if config.difficulty < 1 || config.difficulty > 16 {
		return errors.New("invalid challenge difficulty")
	}
	if config.ttl <= 0 {
		return errors.New("invalid challenge ttl")
	}
	return nil
}

func redeemFailure(message string) RedeemResponse {
	return RedeemResponse{Success: false, Error: message}
}

func randomHex(bytesCount int) (string, error) {
	buf := make([]byte, bytesCount)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func newVerificationToken() (string, string, error) {
	id, err := randomHex(8)
	if err != nil {
		return "", "", err
	}
	secret, err := randomHex(15)
	if err != nil {
		return "", "", err
	}

	token := id + ":" + secret
	tokenKey, _ := verificationTokenKey(token)
	return token, tokenKey, nil
}

func verificationTokenKey(token string) (string, bool) {
	id, secret, ok := strings.Cut(token, ":")
	if !ok || id == "" || secret == "" || strings.Contains(secret, ":") {
		return "", false
	}

	sum := sha256.Sum256([]byte(secret))
	return id + ":" + hex.EncodeToString(sum[:]), true
}
