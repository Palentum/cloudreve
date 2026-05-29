package model

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/cloudreve/Cloudreve/v3/pkg/cipher"
	"github.com/cloudreve/Cloudreve/v3/pkg/util"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)
const (
	// Active 账户正常状态
	Active = iota
	// NotActivicated 未激活
	NotActivicated
	// Baned 被封禁
	Baned
	// OveruseBaned 超额使用被封禁
	OveruseBaned
)

// dummyBcryptHash 用于恒定时间比较，防止时序侧信道枚举用户
// 对应明文 "cloudreve-dummy-timing-sidechannel"，cost=12
const dummyBcryptHash = "$2a$12$3/2H3bmfj3TOdrxb4WPbU.d6mxLPixDW0XU/Afi63ZNkIO0T7.THm"

// ErrInsufficientStorage 存储配额不足
var ErrInsufficientStorage = errors.New("insufficient storage quota")

// User 用户模型
type User struct {
	// 表字段
	gorm.Model
	Email     string `gorm:"type:varchar(100);unique_index"`
	Nick      string `gorm:"size:50"`
	Password  string `json:"-"`
	Status    int
	GroupID   uint
	Storage   uint64
	TwoFactor string
	Avatar    string
	Options   string `json:"-" gorm:"size:4294967295"`
	Authn     string `gorm:"size:4294967295"`

	// 关联模型
	Group  Group  `gorm:"save_associations:false:false"`
	Policy Policy `gorm:"PRELOAD:false,association_autoupdate:false"`

	// 数据库忽略字段
	OptionsSerialized UserOption `gorm:"-"`
}

func init() {
	gob.Register(User{})
}

// UserOption 用户个性化配置字段
type UserOption struct {
	ProfileOff     bool   `json:"profile_off,omitempty"`
	PreferredTheme string `json:"preferred_theme,omitempty"`
}

// Root 获取用户的根目录
func (user *User) Root() (*Folder, error) {
	var folder Folder
	err := DB.Where("parent_id is NULL AND owner_id = ?", user.ID).First(&folder).Error
	return &folder, err
}

// DeductionStorage 减少用户已用容量
func (user *User) DeductionStorage(size uint64) bool {
	if size == 0 {
		return true
	}
	result := DB.Model(user).Where("storage >= ?", size).Update("storage", gorm.Expr("storage - ?", size))
	if result.RowsAffected > 0 {
		user.Storage -= size
		return true
	}
	// 如果要减少的容量超出已用容量，则设为零（带条件保护并发安全）
	DB.Model(user).Where("storage > ?", 0).Update("storage", 0)
	user.Storage = 0

	return false
}

// IncreaseStorage 检查并增加用户已用容量
func (user *User) IncreaseStorage(size uint64) bool {
	if size == 0 {
		return true
	}
	// 确保 Group 信息已加载，用于配额上限判断
	if user.Group.ID == 0 {
		if err := DB.First(&user.Group, user.GroupID).Error; err != nil {
			return false
		}
	}
	result := DB.Model(user).
		Where("storage + ? <= ?", size, user.Group.MaxStorage).
		Update("storage", gorm.Expr("storage + ?", size))
	if result.RowsAffected > 0 {
		user.Storage += size
		return true
	}
	return false
}

// ChangeStorage 更新用户容量
// ChangeStorage 更新用户容量。operator 必须为 "+" 或 "-"。
func (user *User) ChangeStorage(tx *gorm.DB, operator string, size uint64, maxStorage uint64) error {
	if maxStorage > 0 && operator == "+" {
		result := tx.Model(user).
			Where("storage + ? <= ?", size, maxStorage).
			Update("storage", gorm.Expr("storage + ?", size))
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return ErrInsufficientStorage
		}
		return nil
	}

	switch operator {
	case "+":
		return tx.Model(user).Update("storage", gorm.Expr("storage + ?", size)).Error
	case "-":
		return tx.Model(user).Update("storage", gorm.Expr("storage - ?", size)).Error
	default:
		return errors.New("invalid storage operator: " + operator)
	}
}

// IncreaseStorageWithoutCheck 忽略可用容量，增加用户已用容量
func (user *User) IncreaseStorageWithoutCheck(size uint64) {
	if size == 0 {
		return
	}
	user.Storage += size
	DB.Model(user).Update("storage", gorm.Expr("storage + ?", size))

}

// GetRemainingCapacity 获取剩余配额
func (user *User) GetRemainingCapacity() uint64 {
	total := user.Group.MaxStorage
	if total <= user.Storage {
		return 0
	}
	return total - user.Storage
}

// GetPolicyID 获取用户当前的存储策略ID
func (user *User) GetPolicyID(prefer uint) uint {
	if len(user.Group.PolicyList) > 0 {
		return user.Group.PolicyList[0]
	}
	return 0
}

// GetUserByID 用ID获取用户
func GetUserByID(ID interface{}) (User, error) {
	var user User
	result := DB.Set("gorm:auto_preload", true).First(&user, ID)
	return user, result.Error
}

// GetActiveUserByID 用ID获取可登录用户
func GetActiveUserByID(ID interface{}) (User, error) {
	var user User
	result := DB.Set("gorm:auto_preload", true).Where("status = ?", Active).First(&user, ID)
	return user, result.Error
}

// GetActiveUserByOpenID 用OpenID获取可登录用户
func GetActiveUserByOpenID(openid string) (User, error) {
	var user User
	result := DB.Set("gorm:auto_preload", true).Where("status = ? and open_id = ?", Active, openid).Find(&user)
	return user, result.Error
}

// GetUserByEmail 用Email获取用户
func GetUserByEmail(email string) (User, error) {
	var user User
	result := DB.Set("gorm:auto_preload", true).Where("email = ?", email).First(&user)
	return user, result.Error
}

// GetActiveUserByEmail 用Email获取可登录用户
func GetActiveUserByEmail(email string) (User, error) {
	var user User
	result := DB.Set("gorm:auto_preload", true).Where("status = ? and email = ?", Active, email).First(&user)
	return user, result.Error
}

// NewUser 返回一个新的空 User
func NewUser() User {
	options := UserOption{}
	return User{
		OptionsSerialized: options,
	}
}

// BeforeSave Save用户前的钩子
func (user *User) BeforeSave() (err error) {
	err = user.SerializeOptions()
	// 加密 TwoFactor 字段（仅当非空且未加密时）
	if user.TwoFactor != "" && !cipher.IsEncrypted(user.TwoFactor) {
		encrypted, cryptErr := cipher.Encrypt(user.TwoFactor)
		if cryptErr != nil {
			util.Log().Warning("BeforeSave: TwoFactor 加密失败: %s", cryptErr)
		} else {
			user.TwoFactor = encrypted
		}
	}
	return err
}

// AfterCreate 创建用户后的钩子
func (user *User) AfterCreate(tx *gorm.DB) (err error) {
	// 创建用户的默认根目录
	defaultFolder := &Folder{
		Name:    "/",
		OwnerID: user.ID,
	}
	tx.Create(defaultFolder)
	return err
}

// AfterFind 找到用户后的钩子
func (user *User) AfterFind() (err error) {
	// 解析用户设置到OptionsSerialized
	if user.Options != "" {
		err = json.Unmarshal([]byte(user.Options), &user.OptionsSerialized)
	}

	// 预加载存储策略
	user.Policy, _ = GetPolicyByID(user.GetPolicyID(0))

	// 解密 TwoFactor 字段（仅当为密文时）
	if cipher.IsEncrypted(user.TwoFactor) {
		decrypted, cryptErr := cipher.Decrypt(user.TwoFactor)
		if cryptErr != nil {
			util.Log().Warning("AfterFind: TwoFactor 解密失败: %s", cryptErr)
		} else {
			user.TwoFactor = decrypted
		}
	}

	return err
}

//SerializeOptions 将序列后的Option写入到数据库字段
func (user *User) SerializeOptions() (err error) {
	optionsValue, err := json.Marshal(&user.OptionsSerialized)
	user.Options = string(optionsValue)
	return err
}

// CheckPassword 根据明文校验密码
func (user *User) CheckPassword(password string) (bool, error) {
	if user.Password == "" {
		return false, errors.New("Unknown password type")
	}

	// bcrypt 格式: bcrypt:$2a$...
	if strings.HasPrefix(user.Password, "bcrypt:") {
		hash := strings.TrimPrefix(user.Password, "bcrypt:")
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		if err != nil {
			return false, nil
		}
		return true, nil
	}

	// 根据存储密码拆分为 Salt 和 Digest
	passwordStore := strings.Split(user.Password, ":")
	if len(passwordStore) != 2 && len(passwordStore) != 3 {
		return false, errors.New("Unknown password type")
	}

	// 兼容V2密码，升级后存储格式为: md5:$HASH:$SALT
	if len(passwordStore) == 3 {
		if passwordStore[0] != "md5" {
			return false, errors.New("Unknown password type")
		}
		hash := md5.New()
		_, err := hash.Write([]byte(passwordStore[2] + password))
		bs := hex.EncodeToString(hash.Sum(nil))
		if err != nil {
			return false, err
		}
		if bs == passwordStore[1] {
			user.upgradePassword(password)
			return true, nil
		}
		return false, nil
	}

	//计算 Salt 和密码组合的SHA1摘要
	hash := sha1.New()
	_, err := hash.Write([]byte(password + passwordStore[0]))
	bs := hex.EncodeToString(hash.Sum(nil))
	if err != nil {
		return false, err
	}

	if bs == passwordStore[1] {
		user.upgradePassword(password)
		return true, nil
	}
	return false, nil
}
// DummyCheckPassword 在用户不存在时执行一次 bcrypt 验证，防止通过时序侧信道枚举用户。
// 使用预计算的 dummy hash，结果被丢弃，仅用于消耗与正常密码验证一致的 CPU 时间。
func DummyCheckPassword(password string) {
	_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(password))
}
// upgradePassword 将旧格式密码透明升级为 bcrypt 并持久化
func (user *User) upgradePassword(password string) {
	// bcrypt 截断超过 72 字节的密码，跳过升级避免下次登录失败
	if len(password) > 72 {
		util.Log().Warning("密码超过 72 字节，跳过 bcrypt 升级 (user ID: %d)", user.ID)
		return
	}
	if err := user.SetPassword(password); err != nil {
		util.Log().Warning("密码升级失败: %s", err)
		return
	}
	if err := DB.Model(user).Update("password", user.Password).Error; err != nil {
		util.Log().Warning("密码升级持久化失败: %s", err)
	}
}

// SetPassword 根据给定明文设定 User 的 Password 字段
func (user *User) SetPassword(password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return err
	}
	user.Password = "bcrypt:" + string(hash)
	return nil
}

// NewAnonymousUser 返回一个匿名用户
func NewAnonymousUser() *User {
	user := User{}
	user.Policy.Type = "anonymous"
	user.Group, _ = GetGroupByID(3)
	return &user
}

// IsAnonymous 返回是否为未登录用户
func (user *User) IsAnonymous() bool {
	return user.ID == 0
}

// SetStatus 设定用户状态
func (user *User) SetStatus(status int) {
	DB.Model(&user).Update("status", status)
}

// Update 更新用户
func (user *User) Update(val map[string]interface{}) error {
	return DB.Model(user).Updates(val).Error
}

// UpdateOptions 更新用户偏好设定
func (user *User) UpdateOptions() error {
	if err := user.SerializeOptions(); err != nil {
		return err
	}
	return user.Update(map[string]interface{}{"options": user.Options})
}
