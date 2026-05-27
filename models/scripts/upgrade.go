package scripts

import (
	"context"
	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/cloudreve/Cloudreve/v3/pkg/util"
	"strconv"
)

type UpgradeTo340 int

// Run upgrade from older version to 3.4.0
func (script UpgradeTo340) Run(ctx context.Context) {
	// 取回老版本 aria2 设定
	old := model.GetSettingByType([]string{"aria2"})
	if len(old) == 0 {
		return
	}

	// 写入到新版本的节点设定
	n, err := model.GetNodeByID(1)
	if err != nil {
		util.Log().Error("找不到主机节点, %s", err)
	}

	n.Aria2Enabled = old["aria2_rpcurl"] != ""
	n.Aria2OptionsSerialized.Options = old["aria2_options"]
	n.Aria2OptionsSerialized.Server = old["aria2_rpcurl"]

	interval, err := strconv.Atoi(old["aria2_interval"])
	if err != nil {
		interval = 10
	}
	n.Aria2OptionsSerialized.Interval = interval
	n.Aria2OptionsSerialized.TempPath = old["aria2_temp_path"]
	n.Aria2OptionsSerialized.Token = old["aria2_token"]
	if err := model.DB.Save(&n).Error; err != nil {
		util.Log().Error("无法保存主机节点 Aria2 配置信息, %s", err)
	} else {
		model.DB.Where("type = ?", "aria2").Delete(model.Setting{})
		util.Log().Info("Aria2 配置信息已成功迁移至 3.4.0+ 版本的模式")
	}
}

type ClearSharePasswords int

// Run clears all plaintext share passwords so they can be re-set with bcrypt hashing.
func (script ClearSharePasswords) Run(ctx context.Context) {
	result := model.DB.Model(&model.Share{}).Where("password != ?", "").
		Update("password", "")
	if result.Error != nil {
		util.Log().Error("清除分享密码失败: %s", result.Error)
		return
	}
	util.Log().Info("已清除 %d 条分享的明文密码，用户需重新设置密码", result.RowsAffected)
}
