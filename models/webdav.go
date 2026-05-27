package model

import (
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
)

// Webdav 应用账户
type Webdav struct {
	gorm.Model
	Name     string // 应用名称
	Password string `gorm:"unique_index:password_only_on" json:"-"` // 应用密码（bcrypt 哈希）
	UserID   uint   `gorm:"unique_index:password_only_on"` // 用户ID
	Root     string `gorm:"type:text"`                     // 根目录
	Readonly bool   `gorm:"type:bool"`                     // 是否只读
	UseProxy bool   `gorm:"type:bool"`                     // 是否进行反代
}

// Create 创建账户
func (webdav *Webdav) Create() (uint, error) {
	if err := DB.Create(webdav).Error; err != nil {
		return 0, err
	}
	return webdav.ID, nil
}

// HashWebdavPassword 对密码进行 bcrypt 哈希，返回哈希字符串。
// WebDAV 使用 cost=10（~100ms），低于用户密码的 cost=12（~250ms），
// 因为 WebDAV 客户端在每个 HTTP 请求中都携带 Basic Auth。
const webdavBcryptCost = 10

func HashWebdavPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), webdavBcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// SetPassword 对密码进行 bcrypt 哈希后存储
func (webdav *Webdav) SetPassword(password string) error {
	hash, err := HashWebdavPassword(password)
	if err != nil {
		return err
	}
	webdav.Password = hash
	return nil
}

// CheckPassword 验证密码是否匹配
func (webdav *Webdav) CheckPassword(password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(webdav.Password), []byte(password)) == nil
}

// GetWebdavByAccount 根据密码和用户查找Webdav应用。
// 限制最多检查 maxWebdavAccounts 个账户，防止大量账户时 bcrypt 比较耗时过长。
const maxWebdavAccounts = 10

func GetWebdavByAccount(password string, uid uint) (*Webdav, error) {
	var accounts []Webdav
	res := DB.Where("user_id = ?", uid).Limit(maxWebdavAccounts).Find(&accounts)
	if res.Error != nil {
		return nil, res.Error
	}
	for i := range accounts {
		if accounts[i].CheckPassword(password) {
			return &accounts[i], nil
		}
	}
	return nil, gorm.ErrRecordNotFound
}

// ListWebDAVAccounts 列出用户的所有账号
func ListWebDAVAccounts(uid uint) []Webdav {
	var accounts []Webdav
	DB.Where("user_id = ?", uid).Order("created_at desc").Find(&accounts)
	return accounts
}

// DeleteWebDAVAccountByID 根据账户ID和UID删除账户
func DeleteWebDAVAccountByID(id, uid uint) {
	DB.Where("user_id = ? and id = ?", uid, id).Delete(&Webdav{})
}

// UpdateWebDAVAccountByID 根据账户ID和UID更新账户
func UpdateWebDAVAccountByID(id, uid uint, updates map[string]interface{}) {
	DB.Model(&Webdav{Model: gorm.Model{ID: id}, UserID: uid}).Updates(updates)
}
