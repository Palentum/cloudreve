package admin

import (
	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/cloudreve/Cloudreve/v3/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v3/pkg/task"
	"github.com/gin-gonic/gin"
)

// TaskBatchService 任务批量操作服务
type TaskBatchService struct {
	ID []uint `json:"id" binding:"min=1"`
}

// ImportTaskService 导入任务
type ImportTaskService struct {
	UID       uint   `json:"uid" binding:"required"`
	PolicyID  uint   `json:"policy_id" binding:"required"`
	Src       string `json:"src" binding:"required,min=1,max=65535"`
	Dst       string `json:"dst" binding:"required,min=1,max=65535"`
	Recursive bool   `json:"recursive"`
}

// Create 新建导入任务
func (service *ImportTaskService) Create(c *gin.Context, user *model.User) serializer.Response {
	// 创建任务
	job, err := task.NewImportTask(service.UID, service.PolicyID, service.Src, service.Dst, service.Recursive)
	if err != nil {
		return serializer.DBErr("Failed to create task record.", err)
	}
	if err := task.TaskPoll.Submit(job); err != nil {
		return serializer.Err(serializer.CodeCreateTaskError, "", err)
	}
	return serializer.Response{}
}

// Delete 删除任务
func (service *TaskBatchService) Delete(c *gin.Context) serializer.Response {
	if err := model.DB.Where("id in (?)", service.ID).Delete(&model.Download{}).Error; err != nil {
		return serializer.DBErr("Failed to delete task records", err)
	}
	return serializer.Response{}
}

// DeleteGeneral 删除常规任务
func (service *TaskBatchService) DeleteGeneral(c *gin.Context) serializer.Response {
	if err := model.DB.Where("id in (?)", service.ID).Delete(&model.Task{}).Error; err != nil {
		return serializer.DBErr("Failed to delete task records", err)
	}
	return serializer.Response{}
}

// taskSearchColumns 任务表允许搜索/过滤/排序的列
var taskSearchColumns = map[string]bool{
	"id": true, "status": true, "type": true, "user_id": true,
	"progress": true, "error": true,
}

// downloadSearchColumns 离线下载表允许搜索/过滤/排序的列
var downloadSearchColumns = map[string]bool{
	"id": true, "status": true, "type": true, "user_id": true, "node_id": true,
	"gid": true, "source": true, "error": true, "parent": true, "total_size": true,
}

// Tasks 列出常规任务
func (service *AdminListService) Tasks() serializer.Response {
	var res []model.Task
	total := 0

	tx := model.DB.Model(&model.Task{})
	if orderBy := sanitizeOrderBy(service.OrderBy, taskSearchColumns); orderBy != "" {
		tx = tx.Order(orderBy)
	}

	if cond, args := buildSafeConditions(service.Conditions, taskSearchColumns); cond != "" {
		tx = tx.Where(cond, args...)
	}

	if search, args := buildSafeSearch(service.Searches, taskSearchColumns); search != "" {
		tx = tx.Where(search, args...)
	}

	// 计算总数用于分页
	tx.Count(&total)

	// 查询记录
	tx.Limit(service.PageSize).Offset((service.Page - 1) * service.PageSize).Find(&res)

	// 查询对应用户，同时计算HashID
	users := make(map[uint]model.User)
	for _, file := range res {
		users[file.UserID] = model.User{}
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

	return serializer.Response{Data: map[string]interface{}{
		"total": total,
		"items": res,
		"users": users,
	}}
}

// Downloads 列出离线下载任务
func (service *AdminListService) Downloads() serializer.Response {
	var res []model.Download
	total := 0

	tx := model.DB.Model(&model.Download{})
	if orderBy := sanitizeOrderBy(service.OrderBy, downloadSearchColumns); orderBy != "" {
		tx = tx.Order(orderBy)
	}

	if cond, args := buildSafeConditions(service.Conditions, downloadSearchColumns); cond != "" {
		tx = tx.Where(cond, args...)
	}

	if search, args := buildSafeSearch(service.Searches, downloadSearchColumns); search != "" {
		tx = tx.Where(search, args...)
	}

	// 计算总数用于分页
	tx.Count(&total)

	// 查询记录
	tx.Limit(service.PageSize).Offset((service.Page - 1) * service.PageSize).Find(&res)

	// 查询对应用户，同时计算HashID
	users := make(map[uint]model.User)
	for _, file := range res {
		users[file.UserID] = model.User{}
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

	return serializer.Response{Data: map[string]interface{}{
		"total": total,
		"items": res,
		"users": users,
	}}
}
