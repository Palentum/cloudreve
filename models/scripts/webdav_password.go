package scripts

import (
	"context"
	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/cloudreve/Cloudreve/v3/pkg/util"
	"strings"
)

type UpgradeWebdavPasswords int

// Run 将所有明文 WebDAV 密码升级为 bcrypt 哈希
func (script UpgradeWebdavPasswords) Run(ctx context.Context) {
	var count int
	if err := model.DB.Model(&model.Webdav{}).Count(&count).Error; err != nil {
		util.Log().Error("查询 WebDAV 账户数量失败: %s", err)
		return
	}

	if count == 0 {
		util.Log().Info("无 WebDAV 账户需要升级")
		return
	}

	util.Log().Info("开始升级 %d 条 WebDAV 密码...", count)

	var upgraded, skipped, failed int
	batchSize := 100
	for offset := 0; offset < count; offset += batchSize {
		var accounts []model.Webdav
		if err := model.DB.Offset(offset).Limit(batchSize).Find(&accounts).Error; err != nil {
			util.Log().Error("查询 WebDAV 账户批次 (offset=%d) 失败: %s", offset, err)
			return
		}

		for _, account := range accounts {
			// 跳过空密码
			if account.Password == "" {
				skipped++
				continue
			}

			// 已经是 bcrypt 哈希则跳过
			if strings.HasPrefix(account.Password, "$2a$") || strings.HasPrefix(account.Password, "$2b$") {
				skipped++
				continue
			}

			hash, err := model.HashWebdavPassword(account.Password)
			if err != nil {
				util.Log().Warning("WebDAV 账户 %d 密码哈希失败: %s", account.ID, err)
				failed++
				continue
			}

			if err := model.DB.Model(&account).Update("password", hash).Error; err != nil {
				util.Log().Warning("WebDAV 账户 %d 密码更新失败: %s", account.ID, err)
				failed++
				continue
			}
			upgraded++
		}
	}

	util.Log().Info("WebDAV 密码升级完成: %d 条已哈希, %d 条已跳过, %d 条失败", upgraded, skipped, failed)
	if failed > 0 {
		util.Log().Warning("有 %d 条密码升级失败，建议重新运行脚本", failed)
	}
}
