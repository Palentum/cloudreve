package model

import (
	"encoding/json"
	"github.com/cloudreve/Cloudreve/v3/pkg/cipher"
	"github.com/jinzhu/gorm"
)

// Node 从机节点信息模型
type Node struct {
	gorm.Model
	Status       NodeStatus // 节点状态
	Name         string     // 节点别名
	Type         ModelType  // 节点状态
	Server       string     // 服务器地址
	SlaveKey     string     `gorm:"type:text"` // 主->从 通信密钥
	MasterKey    string     `gorm:"type:text"` // 从->主 通信密钥
	Aria2Enabled bool       // 是否支持用作离线下载节点
	Aria2Options string     `gorm:"type:text"` // 离线下载配置
	Rank         int        // 负载均衡权重

	// 数据库忽略字段
	Aria2OptionsSerialized Aria2Option `gorm:"-"`
	plaintextSlaveKey      string      `gorm:"-"`
	plaintextMasterKey     string      `gorm:"-"`
}

// Aria2Option 非公有的Aria2配置属性
type Aria2Option struct {
	// RPC 服务器地址
	Server string `json:"server,omitempty"`
	// RPC 密钥
	Token string `json:"token,omitempty"`
	// 临时下载目录
	TempPath string `json:"temp_path,omitempty"`
	// 附加下载配置
	Options string `json:"options,omitempty"`
	// 下载监控间隔
	Interval int `json:"interval,omitempty"`
	// RPC API 请求超时
	Timeout int `json:"timeout,omitempty"`
}

type NodeStatus int
type ModelType int

const (
	NodeActive NodeStatus = iota
	NodeSuspend
)

const (
	SlaveNodeType ModelType = iota
	MasterNodeType
)

// GetNodeByID 用ID获取节点
func GetNodeByID(ID interface{}) (Node, error) {
	var node Node
	result := DB.First(&node, ID)
	return node, result.Error
}

// GetNodesByStatus 根据给定状态获取节点
func GetNodesByStatus(status ...NodeStatus) ([]Node, error) {
	var nodes []Node
	result := DB.Where("status in (?)", status).Find(&nodes)
	return nodes, result.Error
}

// AfterFind 找到节点后的钩子
func (node *Node) AfterFind() (err error) {
	// 解密敏感字段
	node.SlaveKey, _ = cipher.Decrypt(node.SlaveKey)
	node.MasterKey, _ = cipher.Decrypt(node.MasterKey)

	// 解析离线下载设置到 Aria2OptionsSerialized
	if node.Aria2Options != "" {
		err = json.Unmarshal([]byte(node.Aria2Options), &node.Aria2OptionsSerialized)
		if err == nil && node.Aria2OptionsSerialized.Token != "" {
			node.Aria2OptionsSerialized.Token, _ = cipher.Decrypt(node.Aria2OptionsSerialized.Token)
		}
	}

	return err
}

// BeforeSave Save策略前的钩子
func (node *Node) BeforeSave() (err error) {
	// 保存明文以便还原
	origToken := node.Aria2OptionsSerialized.Token
	defer func() {
		if err != nil {
			node.Aria2OptionsSerialized.Token = origToken
		}
	}()

	// 加密 Aria2 Token（兼容旧明文：非密文输入 Encrypt 不报错）
	if origToken != "" {
		node.Aria2OptionsSerialized.Token, err = cipher.Encrypt(origToken)
		if err != nil {
			return err
		}
	}

	optionsValue, err := json.Marshal(&node.Aria2OptionsSerialized)
	node.Aria2Options = string(optionsValue)
	node.Aria2OptionsSerialized.Token = origToken // 还原明文供调用方继续使用
	if err != nil {
		return err
	}

	// 保存明文以便还原
	origSK := node.SlaveKey
	origMK := node.MasterKey
	defer func() {
		if err != nil {
			node.SlaveKey = origSK
			node.MasterKey = origMK
		}
	}()

	// 加密敏感字段（成功时 AfterSave 还原，失败时 defer 还原）
	node.SlaveKey, err = cipher.Encrypt(node.SlaveKey)
	if err != nil {
		return err
	}
	node.MasterKey, err = cipher.Encrypt(node.MasterKey)
	if err != nil {
		return err
	}

	node.plaintextSlaveKey = origSK
	node.plaintextMasterKey = origMK
	return nil
}

// AfterSave Save完成后的钩子，还原明文供调用方继续使用
func (node *Node) AfterSave() {
	node.SlaveKey = node.plaintextSlaveKey
	node.MasterKey = node.plaintextMasterKey
}

// SetStatus 设置节点启用状态
func (node *Node) SetStatus(status NodeStatus) error {
	node.Status = status
	return DB.Model(node).UpdateColumn("status", status).Error
}
