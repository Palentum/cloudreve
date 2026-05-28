package cap

import (
	"strconv"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v3/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChallengeVectorMatchesCapWidget(t *testing.T) {
	token := "0123456789abcdef"
	tokenSeed := fnv1a(token)
	saltSeed := fnv1aResume(tokenSeed, "1")
	targetSeed := fnv1aResume(saltSeed, "d")

	assert.Equal(t, uint32(2277258045), tokenSeed)
	assert.Equal(t, "75209df8b56a7857b67c4987d6da7201", prngFromHash(saltSeed, 32))
	assert.Equal(t, "5e47", prngFromHash(targetSeed, 4))
	assert.True(t, solutionMatchesTarget("75209df8b56a7857b67c4987d6da7201", 44101, "5e47"))
	assert.False(t, solutionMatchesTarget("75209df8b56a7857b67c4987d6da7201", 44100, "5e47"))
}

func TestCreateRedeemAndValidateToken(t *testing.T) {
	cache.Store = cache.NewMemoStore()

	challenge, err := createChallenge(challengeConfig{
		count:      2,
		size:       8,
		difficulty: 2,
		ttl:        time.Minute,
	})
	require.NoError(t, err)

	redeem := RedeemChallenge(RedeemRequest{
		Token:     challenge.Token,
		Solutions: solveChallenge(challenge),
	})
	require.True(t, redeem.Success, redeem.Error)
	require.NotEmpty(t, redeem.Token)
	require.Greater(t, redeem.Expires, time.Now().UnixMilli())

	_, challengeExists := cache.Get(challengeCachePrefix + challenge.Token)
	assert.False(t, challengeExists)
	assert.True(t, ValidateToken(redeem.Token, true))
	assert.True(t, ValidateToken(redeem.Token, false))
	assert.False(t, ValidateToken(redeem.Token, false))
}

func TestRedeemChallengeReplayProtection(t *testing.T) {
	cache.Store = cache.NewMemoStore()

	challenge, err := createChallenge(challengeConfig{
		count:      1,
		size:       8,
		difficulty: 2,
		ttl:        time.Minute,
	})
	require.NoError(t, err)
	solutions := solveChallenge(challenge)

	// 首次兑换成功
	redeem := RedeemChallenge(RedeemRequest{Token: challenge.Token, Solutions: solutions})
	require.True(t, redeem.Success, redeem.Error)

	// 第二次兑换应失败（challenge 已被删除）
	redeem2 := RedeemChallenge(RedeemRequest{Token: challenge.Token, Solutions: solutions})
	assert.False(t, redeem2.Success)
}

func TestRedeemChallengeRejectsInvalidSolution(t *testing.T) {
	cache.Store = cache.NewMemoStore()

	challenge, err := createChallenge(challengeConfig{
		count:      1,
		size:       8,
		difficulty: 2,
		ttl:        time.Minute,
	})
	require.NoError(t, err)

	redeem := RedeemChallenge(RedeemRequest{Token: challenge.Token, Solutions: []uint64{0, 1}})
	assert.False(t, redeem.Success)
	assert.Empty(t, redeem.Token)
}

func TestRateLimitPerIP(t *testing.T) {
	cache.Store = cache.NewMemoStore()

	// 前 maxChallengePerIP 次应成功
	for i := 0; i < maxChallengePerIP; i++ {
		_, err := CreateChallengeForIP("192.0.2.1")
		require.NoError(t, err, "challenge %d should succeed", i)
	}

	// 第 maxChallengePerIP+1 次应被限流
	_, err := CreateChallengeForIP("192.0.2.1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rate limited")

	// 不同 IP 不受影响
	_, err = CreateChallengeForIP("192.0.2.2")
	require.NoError(t, err)
}

func solveChallenge(challenge ChallengeResponse) []uint64 {
	state := challengeState{
		Count:      challenge.Challenge.C,
		Size:       challenge.Challenge.S,
		Difficulty: challenge.Challenge.D,
	}
	solutions := make([]uint64, state.Count)
	tokenSeed := fnv1a(challenge.Token)
	for i := range solutions {
		saltSeed := fnv1aResume(tokenSeed, strconv.Itoa(i+1))
		targetSeed := fnv1aResume(saltSeed, "d")
		salt := prngFromHash(saltSeed, state.Size)
		target := prngFromHash(targetSeed, state.Difficulty)
		for nonce := uint64(0); ; nonce++ {
			if solutionMatchesTarget(salt, nonce, target) {
				solutions[i] = nonce
				break
			}
		}
	}
	return solutions
}
