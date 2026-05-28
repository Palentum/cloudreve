package scripts

import (
	"context"

	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/cloudreve/Cloudreve/v3/pkg/cipher"
	"github.com/cloudreve/Cloudreve/v3/pkg/util"
)

type UpgradeTo390 int

// Run 将 policies 和 nodes 表中的敏感字段从明文加密为 AES-GCM 密文。
// 使用 cipher.IsEncrypted 检测，确保幂等性。
func (script UpgradeTo390) Run(ctx context.Context) {
	UpgradeSharePasswords(0).Run(ctx)
	UpgradeWebdavPasswords(0).Run(ctx)

	if !cipher.IsAvailable() {
		util.Log().Warning("加密引擎未初始化，跳过密钥加密迁移")
		return
	}

	encryptPolicies()
	encryptNodes()
}

func encryptPolicies() {
	var count int
	if err := model.DB.Model(&model.Policy{}).Count(&count).Error; err != nil {
		util.Log().Error("查询存储策略数量失败: %s", err)
		return
	}
	if count == 0 {
		return
	}

	util.Log().Info("开始加密 %d 条存储策略的敏感字段...", count)

	var upgraded, skipped, failed int
	batchSize := 100
	for offset := 0; offset < count; offset += batchSize {
		var policies []model.Policy
		if err := model.DB.Offset(offset).Limit(batchSize).Find(&policies).Error; err != nil {
			util.Log().Error("查询存储策略批次 (offset=%d) 失败: %s", offset, err)
			return
		}

		for _, p := range policies {
			if p.AccessKey == "" && p.SecretKey == "" {
				skipped++
				continue
			}

			// AfterFind 已将加密数据解密为明文存入结构体，
			// 需要直接读取数据库原始值来判断是否已加密
			accessKey, secretKey := getRawPolicyKeys(p.ID)
			if cipher.IsEncrypted(accessKey) && cipher.IsEncrypted(secretKey) {
				skipped++
				continue
			}

			encAK, err := cipher.Encrypt(p.AccessKey)
			if err != nil {
				util.Log().Warning("存储策略 %d AccessKey 加密失败: %s", p.ID, err)
				failed++
				continue
			}
			encSK, err := cipher.Encrypt(p.SecretKey)
			if err != nil {
				util.Log().Warning("存储策略 %d SecretKey 加密失败: %s", p.ID, err)
				failed++
				continue
			}

			if err := model.DB.Exec("UPDATE policies SET access_key = ?, secret_key = ? WHERE id = ?",
				encAK, encSK, p.ID).Error; err != nil {
				util.Log().Warning("存储策略 %d 更新失败: %s", p.ID, err)
				failed++
				continue
			}
			upgraded++
		}
	}

	util.Log().Info("存储策略加密完成: %d 条已加密, %d 条已跳过, %d 条失败", upgraded, skipped, failed)
}

func encryptNodes() {
	var count int
	if err := model.DB.Model(&model.Node{}).Count(&count).Error; err != nil {
		util.Log().Error("查询节点数量失败: %s", err)
		return
	}
	if count == 0 {
		return
	}

	util.Log().Info("开始加密 %d 条节点的敏感字段...", count)

	var upgraded, skipped, failed int
	batchSize := 100
	for offset := 0; offset < count; offset += batchSize {
		var nodes []model.Node
		if err := model.DB.Offset(offset).Limit(batchSize).Find(&nodes).Error; err != nil {
			util.Log().Error("查询节点批次 (offset=%d) 失败: %s", offset, err)
			return
		}

		for _, n := range nodes {
			if n.SlaveKey == "" && n.MasterKey == "" {
				skipped++
				continue
			}

			slaveKey, masterKey := getRawNodeKeys(n.ID)
			if cipher.IsEncrypted(slaveKey) && cipher.IsEncrypted(masterKey) {
				skipped++
				continue
			}

			encSK, err := cipher.Encrypt(n.SlaveKey)
			if err != nil {
				util.Log().Warning("节点 %d SlaveKey 加密失败: %s", n.ID, err)
				failed++
				continue
			}
			encMK, err := cipher.Encrypt(n.MasterKey)
			if err != nil {
				util.Log().Warning("节点 %d MasterKey 加密失败: %s", n.ID, err)
				failed++
				continue
			}

			if err := model.DB.Exec("UPDATE nodes SET slave_key = ?, master_key = ? WHERE id = ?",
				encSK, encMK, n.ID).Error; err != nil {
				util.Log().Warning("节点 %d 更新失败: %s", n.ID, err)
				failed++
				continue
			}
			upgraded++
		}
	}

	util.Log().Info("节点加密完成: %d 条已加密, %d 条已跳过, %d 条失败", upgraded, skipped, failed)
}

// getRawPolicyKeys 直接通过 SQL 读取数据库中未经过 AfterFind 解密的原始值。
func getRawPolicyKeys(id uint) (string, string) {
	var ak, sk string
	model.DB.Raw("SELECT access_key, secret_key FROM policies WHERE id = ?", id).Row().Scan(&ak, &sk)
	return ak, sk
}

// getRawNodeKeys 直接通过 SQL 读取数据库中未经过 AfterFind 解密的原始值。
func getRawNodeKeys(id uint) (string, string) {
	var sk, mk string
	model.DB.Raw("SELECT slave_key, master_key FROM nodes WHERE id = ?", id).Row().Scan(&sk, &mk)
	return sk, mk
}
