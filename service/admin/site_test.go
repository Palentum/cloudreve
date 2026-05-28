package admin

import (
	"testing"

	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/cloudreve/Cloudreve/v3/pkg/cache"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withSettingTestDB(t *testing.T) func() {
	t.Helper()

	oldDB := model.DB
	oldCache := cache.Store
	db, err := gorm.Open("sqlite", ":memory:")
	require.NoError(t, err)
	model.DB = db
	cache.Store = cache.NewMemoStore()
	require.NoError(t, model.DB.AutoMigrate(&model.Setting{}).Error)

	return func() {
		db.Close()
		model.DB = oldDB
		cache.Store = oldCache
	}
}

func TestBatchSettingChangeCreatesMissingDefaultSetting(t *testing.T) {
	defer withSettingTestDB(t)()
	asserts := assert.New(t)

	service := BatchSettingChangeService{Options: []SettingChangeService{{
		Key:   "hot_share_num",
		Value: "1",
	}}}
	res := service.Change()

	asserts.Equal(0, res.Code)
	var setting model.Setting
	asserts.NoError(model.DB.Where("name = ?", "hot_share_num").First(&setting).Error)
	asserts.Equal("share", setting.Type)
	asserts.Equal("1", setting.Value)
}

func TestBatchSettingChangeDoesNotCreateUnknownSetting(t *testing.T) {
	defer withSettingTestDB(t)()
	asserts := assert.New(t)

	service := BatchSettingChangeService{Options: []SettingChangeService{{
		Key:   "unknown_setting",
		Value: "1",
	}}}
	res := service.Change()

	asserts.Equal(0, res.Code)
	var count int
	asserts.NoError(model.DB.Model(&model.Setting{}).Where("name = ?", "unknown_setting").Count(&count).Error)
	asserts.Equal(0, count)
}
