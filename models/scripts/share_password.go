package scripts

import (
	"context"

	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/cloudreve/Cloudreve/v3/pkg/util"
	"golang.org/x/crypto/bcrypt"
)

type ClearSharePasswords int

type UpgradeSharePasswords int

type passwordUpgradeStats struct {
	upgraded int
	skipped  int
	failed   int
}

const passwordUpgradeBatchSize = 100

// Run upgrades plaintext share passwords to bcrypt hashes.
// The script name is kept for compatibility with existing manual operations.
func (script ClearSharePasswords) Run(ctx context.Context) {
	UpgradeSharePasswords(0).Run(ctx)
}

// Run 将所有明文分享密码升级为 bcrypt 哈希。
func (script UpgradeSharePasswords) Run(ctx context.Context) {
	count, err := countSharePasswords()
	if err != nil {
		util.Log().Error("查询分享密码数量失败: %s", err)
		return
	}

	if count == 0 {
		util.Log().Info("无分享密码需要升级")
		return
	}

	util.Log().Info("开始升级 %d 条分享密码...", count)
	stats := upgradeSharePasswordBatches()
	util.Log().Info("分享密码升级完成: %d 条已哈希, %d 条已跳过, %d 条失败",
		stats.upgraded, stats.skipped, stats.failed)
	if stats.failed > 0 {
		util.Log().Warning("有 %d 条分享密码升级失败，建议重新运行脚本", stats.failed)
	}
}

func countSharePasswords() (int, error) {
	var count int
	err := model.DB.Model(&model.Share{}).Where("password != ?", "").Count(&count).Error
	return count, err
}

func upgradeSharePasswordBatches() passwordUpgradeStats {
	stats := passwordUpgradeStats{}
	lastID := uint(0)
	for {
		shares, err := listSharePasswordBatch(lastID, passwordUpgradeBatchSize)
		if err != nil {
			util.Log().Error("查询分享密码批次 (last_id=%d) 失败: %s", lastID, err)
			return stats
		}
		if len(shares) == 0 {
			return stats
		}
		for i := range shares {
			lastID = shares[i].ID
			upgradeSharePassword(&shares[i], &stats)
		}
	}
}

func listSharePasswordBatch(lastID uint, batchSize int) ([]model.Share, error) {
	var shares []model.Share
	err := model.DB.Where("password != ? AND id > ?", "", lastID).
		Order("id asc").Limit(batchSize).Find(&shares).Error
	return shares, err
}

func upgradeSharePassword(share *model.Share, stats *passwordUpgradeStats) {
	if share.Password == "" || isBcryptHash(share.Password) {
		stats.skipped++
		return
	}

	plainPassword := share.Password
	if err := share.SetPassword(plainPassword); err != nil {
		util.Log().Warning("分享 %d 密码哈希失败: %s", share.ID, err)
		stats.failed++
		return
	}

	if err := model.DB.Model(share).Update("password", share.Password).Error; err != nil {
		util.Log().Warning("分享 %d 密码更新失败: %s", share.ID, err)
		stats.failed++
		return
	}
	stats.upgraded++
}

func isBcryptHash(password string) bool {
	_, err := bcrypt.Cost([]byte(password))
	return err == nil
}
