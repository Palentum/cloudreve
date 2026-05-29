package admin

import (
	"testing"

	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/cloudreve/Cloudreve/v3/pkg/cache"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupUserTestDB(t *testing.T) {
	t.Helper()

	oldDB := model.DB
	cache.Store = cache.NewMemoStore()

	db, err := gorm.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.LogMode(false)
	model.DB = db

	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Group{}, &model.Folder{}).Error)

	t.Cleanup(func() {
		db.Close()
		model.DB = oldDB
	})
}

func TestAddUser_MassAssignmentProtection(t *testing.T) {
	setupUserTestDB(t)
	asserts := assert.New(t)

	// 创建普通用户组 (id=2) 和管理员组 (id=1)
	adminGroup := model.Group{Name: "管理员"}
	require.NoError(t, model.DB.Create(&adminGroup).Error)
	userGroup := model.Group{Name: "注册用户"}
	require.NoError(t, model.DB.Create(&userGroup).Error)

	// 尝试通过 JSON 注入敏感字段
	service := AddUserService{
		User: model.User{
			Email:     "attacker@example.com",
			Nick:      "attacker",
			GroupID:   1,        // 尝试注入管理员组
			Status:    model.Baned, // 尝试注入封禁状态
			Storage:   999999999, // 尝试注入无限配额
			TwoFactor: "injected_secret",
			Options:   "{\"malicious\":true}",
			Authn:     "injected_authn",
		},
		Password: "testpassword",
	}

	res := service.Add()
	asserts.Equal(0, res.Code)

	// 验证创建的用户
	created, err := model.GetUserByID(service.User.ID)
	asserts.NoError(err)

	// GroupID=1 (管理员组) 可以被设置，因为管理员有权选择用户组且组存在
	asserts.Equal(uint(1), created.GroupID)

	// Storage 不应被注入
	asserts.Equal(uint64(0), created.Storage)

	// Status 应始终为 Active
	asserts.Equal(model.Active, created.Status)

	// TwoFactor 不应被注入
	asserts.Empty(created.TwoFactor)

	// Options 不应被注入（NewUser 默认为 JSON 空对象）
	asserts.NotContains(created.Options, "malicious")

	// Authn 不应被注入
	asserts.Empty(created.Authn)

	// Email 和 Nick 应正常设置
	asserts.Equal("attacker@example.com", created.Email)
	asserts.Equal("attacker", created.Nick)
}

func TestAddUser_GroupIDValidation(t *testing.T) {
	setupUserTestDB(t)
	asserts := assert.New(t)

	// 只创建普通用户组 (id=1)，不创建管理员组
	userGroup := model.Group{Name: "注册用户"}
	require.NoError(t, model.DB.Create(&userGroup).Error)

	// 尝试注入不存在的管理员组
	service := AddUserService{
		User: model.User{
			Email:   "user@example.com",
			Nick:    "user",
			GroupID: 999, // 不存在的组
		},
		Password: "testpassword",
	}

	res := service.Add()
	asserts.Equal(0, res.Code)

	created, err := model.GetUserByID(service.User.ID)
	asserts.NoError(err)

	// GroupID 不应被设置为不存在的组，保持默认值 0
	asserts.Equal(uint(0), created.GroupID)
}

func TestAddUser_GroupIDZeroDefault(t *testing.T) {
	setupUserTestDB(t)
	asserts := assert.New(t)

	// 不指定 GroupID 时使用默认值
	service := AddUserService{
		User: model.User{
			Email: "normal@example.com",
			Nick:  "normal",
		},
		Password: "testpassword",
	}

	res := service.Add()
	asserts.Equal(0, res.Code)

	created, err := model.GetUserByID(service.User.ID)
	asserts.NoError(err)

	// GroupID 为 0（未设置）
	asserts.Equal(uint(0), created.GroupID)
	// Status 为 Active
	asserts.Equal(model.Active, created.Status)
}
