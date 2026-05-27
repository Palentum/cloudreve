package admin

import (
	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/cloudreve/Cloudreve/v3/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v3/pkg/serializer"
	"github.com/gin-gonic/gin"
)

// ShareBatchService 分享批量操作服务
type ShareBatchService struct {
	ID []uint `json:"id" binding:"min=1"`
}

// Delete 删除文件
func (service *ShareBatchService) Delete(c *gin.Context) serializer.Response {
	if err := model.DB.Where("id in (?)", service.ID).Delete(&model.Share{}).Error; err != nil {
		return serializer.DBErr("Failed to delete share record", err)
	}
	return serializer.Response{}
}

// shareSearchColumns 分享表允许搜索/过滤/排序的列
var shareSearchColumns = map[string]bool{
	"id": true, "source_name": true, "user_id": true, "source_id": true,
	"is_dir": true, "preview_enabled": true, "password": true,
	"views": true, "downloads": true,
}

// Shares 列出分享
func (service *AdminListService) Shares() serializer.Response {
	var res []model.Share
	total := 0

	tx := model.DB.Model(&model.Share{})
	if orderBy := sanitizeOrderBy(service.OrderBy, shareSearchColumns); orderBy != "" {
		tx = tx.Order(orderBy)
	}

	if cond, args := buildSafeConditions(service.Conditions, shareSearchColumns); cond != "" {
		tx = tx.Where(cond, args...)
	}

	if search, args := buildSafeSearch(service.Searches, shareSearchColumns); search != "" {
		tx = tx.Where(search, args...)
	}

	// 计算总数用于分页
	tx.Count(&total)

	// 查询记录
	tx.Limit(service.PageSize).Offset((service.Page - 1) * service.PageSize).Find(&res)

	// 查询对应用户，同时计算HashID
	users := make(map[uint]model.User)
	hashIDs := make(map[uint]string, len(res))
	for _, file := range res {
		users[file.UserID] = model.User{}
		hashIDs[file.ID] = hashid.HashID(file.ID, hashid.ShareID)
	}

	userIDs := make([]uint, 0, len(users))
	for k := range users {
		userIDs = append(userIDs, k)
	}

	var userList []model.User
	model.DB.Where("id in (?)", userIDs).Find(&userList)

	for _, v := range userList {
		users[v.ID] = v
	}

	// 隐藏密码哈希，避免通过 API 泄露
	for i := range res {
		if res[i].Password != "" {
			res[i].Password = "***"
		}
	}

	return serializer.Response{Data: map[string]interface{}{
		"total": total,
		"items": res,
		"users": users,
		"ids":   hashIDs,
	}}
}
