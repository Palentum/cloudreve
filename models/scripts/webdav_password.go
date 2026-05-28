package scripts

import (
	"context"
	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/cloudreve/Cloudreve/v3/pkg/util"
)

type UpgradeWebdavPasswords int

// Run 将所有明文 WebDAV 密码升级为 bcrypt 哈希
func (script UpgradeWebdavPasswords) Run(ctx context.Context) {
	count, err := countWebdavPasswords()
	if err != nil {
		util.Log().Error("查询 WebDAV 账户数量失败: %s", err)
		return
	}

	if count == 0 {
		util.Log().Info("无 WebDAV 账户需要升级")
		return
	}

	util.Log().Info("开始升级 %d 条 WebDAV 密码...", count)
	stats := upgradeWebdavPasswordBatches()
	util.Log().Info("WebDAV 密码升级完成: %d 条已哈希, %d 条已跳过, %d 条失败",
		stats.upgraded, stats.skipped, stats.failed)
	if stats.failed > 0 {
		util.Log().Warning("有 %d 条密码升级失败，建议重新运行脚本", stats.failed)
	}
}

func countWebdavPasswords() (int, error) {
	var count int
	err := model.DB.Model(&model.Webdav{}).Where("password != ?", "").Count(&count).Error
	return count, err
}

func upgradeWebdavPasswordBatches() passwordUpgradeStats {
	stats := passwordUpgradeStats{}
	lastID := uint(0)
	for {
		accounts, err := listWebdavPasswordBatch(lastID, passwordUpgradeBatchSize)
		if err != nil {
			util.Log().Error("查询 WebDAV 账户批次 (last_id=%d) 失败: %s", lastID, err)
			return stats
		}
		if len(accounts) == 0 {
			return stats
		}

		for i := range accounts {
			lastID = accounts[i].ID
			upgradeWebdavPassword(&accounts[i], &stats)
		}
	}
}

func listWebdavPasswordBatch(lastID uint, batchSize int) ([]model.Webdav, error) {
	var accounts []model.Webdav
	err := model.DB.Where("password != ? AND id > ?", "", lastID).
		Order("id asc").Limit(batchSize).Find(&accounts).Error
	return accounts, err
}

func upgradeWebdavPassword(account *model.Webdav, stats *passwordUpgradeStats) {
	if account.Password == "" || isBcryptHash(account.Password) {
		stats.skipped++
		return
	}

	hash, err := model.HashWebdavPassword(account.Password)
	if err != nil {
		util.Log().Warning("WebDAV 账户 %d 密码哈希失败: %s", account.ID, err)
		stats.failed++
		return
	}

	if err := model.DB.Model(account).Update("password", hash).Error; err != nil {
		util.Log().Warning("WebDAV 账户 %d 密码更新失败: %s", account.ID, err)
		stats.failed++
		return
	}
	stats.upgraded++
}
