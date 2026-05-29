package controllers

import (
	"github.com/cloudreve/Cloudreve/v3/pkg/cluster"
	"github.com/cloudreve/Cloudreve/v3/pkg/mq"

	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/cloudreve/Cloudreve/v3/pkg/aria2"
	"github.com/cloudreve/Cloudreve/v3/pkg/email"
	"github.com/cloudreve/Cloudreve/v3/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v3/pkg/wopi"
	"github.com/cloudreve/Cloudreve/v3/service/admin"
	"github.com/gin-gonic/gin"
)

// AdminSummary 获取管理站点概况
func AdminSummary(c *gin.Context) {
	var service admin.NoParamService
	if err := c.ShouldBindUri(&service); err == nil {
		res := service.Summary()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminChangeSetting 获取站点设定项
func AdminChangeSetting(c *gin.Context) {
	var service admin.BatchSettingChangeService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Change()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminGetSetting 获取站点设置
func AdminGetSetting(c *gin.Context) {
	var service admin.BatchSettingGet
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Get()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminGetGroups 获取用户组列表
func AdminGetGroups(c *gin.Context) {
	var service admin.NoParamService
	if err := c.ShouldBindUri(&service); err == nil {
		res := service.GroupList()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminReloadService 重新加载子服务
func AdminReloadService(c *gin.Context) {
	service := c.Param("service")
	switch service {
	case "email":
		email.Init()
	case "aria2":
		aria2.Init(true, cluster.Default, mq.GlobalMQ)
	case "wopi":
		wopi.Init()
	}

	respond(c, serializer.Response{})
}

// AdminSendTestMail 发送测试邮件
func AdminSendTestMail(c *gin.Context) {
	var service admin.MailTestService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Send()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminTestThumbGenerator Tests thumb generator
func AdminTestThumbGenerator(c *gin.Context) {
	var service admin.ThumbGeneratorTestService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Test(c)
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminTestAria2 测试aria2连接
func AdminTestAria2(c *gin.Context) {
	var service admin.Aria2TestService
	if err := c.ShouldBindJSON(&service); err == nil {
		var res serializer.Response
		if service.Type == model.MasterNodeType {
			res = service.TestMaster()
		} else {
			res = service.TestSlave()
		}

		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminListPolicy 列出存储策略
func AdminListPolicy(c *gin.Context) {
	var service admin.AdminListService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Policies()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminTestPath 测试本地路径可用性
func AdminTestPath(c *gin.Context) {
	var service admin.PathTestService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Test()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminTestSlave 测试从机可用性
func AdminTestSlave(c *gin.Context) {
	var service admin.SlaveTestService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Test()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminAddPolicy 新建存储策略
func AdminAddPolicy(c *gin.Context) {
	var service admin.AddPolicyService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Add()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminAddCORS 创建跨域策略
func AdminAddCORS(c *gin.Context) {
	var service admin.PolicyService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.AddCORS()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminAddSCF 创建回调函数
func AdminAddSCF(c *gin.Context) {
	var service admin.PolicyService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.AddSCF()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminOAuthURL 获取 OneDrive OAuth URL
func AdminOAuthURL(policyType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var service admin.PolicyService
		if err := c.ShouldBindUri(&service); err == nil {
			res := service.GetOAuth(c, policyType)
			respond(c, res)
		} else {
			respond(c, ErrorResponse(err))
		}
	}
}

// AdminGetPolicy 获取存储策略详情
func AdminGetPolicy(c *gin.Context) {
	var service admin.PolicyService
	if err := c.ShouldBindUri(&service); err == nil {
		res := service.Get()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminDeletePolicy 删除存储策略
func AdminDeletePolicy(c *gin.Context) {
	var service admin.PolicyService
	if err := c.ShouldBindUri(&service); err == nil {
		res := service.Delete()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminListGroup 列出用户组
func AdminListGroup(c *gin.Context) {
	var service admin.AdminListService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Groups()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminAddGroup 新建用户组
func AdminAddGroup(c *gin.Context) {
	var service admin.AddGroupService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Add()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminDeleteGroup 删除用户组
func AdminDeleteGroup(c *gin.Context) {
	var service admin.GroupService
	if err := c.ShouldBindUri(&service); err == nil {
		res := service.Delete()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminGetGroup 获取用户组详情
func AdminGetGroup(c *gin.Context) {
	var service admin.GroupService
	if err := c.ShouldBindUri(&service); err == nil {
		res := service.Get()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminListUser 列出用户
func AdminListUser(c *gin.Context) {
	var service admin.AdminListService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Users()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminAddUser 新建用户组
func AdminAddUser(c *gin.Context) {
	var service admin.AddUserService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Add()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminGetUser 获取用户详情
func AdminGetUser(c *gin.Context) {
	var service admin.UserService
	if err := c.ShouldBindUri(&service); err == nil {
		res := service.Get()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminDeleteUser 批量删除用户
func AdminDeleteUser(c *gin.Context) {
	var service admin.UserBatchService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Delete()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminBanUser 封禁/解封用户
func AdminBanUser(c *gin.Context) {
	var service admin.UserService
	if err := c.ShouldBindUri(&service); err == nil {
		res := service.Ban()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminListFile 列出文件
func AdminListFile(c *gin.Context) {
	var service admin.AdminListService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Files()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminGetFile 获取文件
func AdminGetFile(c *gin.Context) {
	var service admin.FileService
	if err := c.ShouldBindUri(&service); err == nil {
		res := service.Get(c)
		// 是否需要重定向
		if res.Code == -301 {
			c.Redirect(302, res.Data.(string))
			return
		}
		// 是否有错误发生
		if res.Code != 0 {
			respond(c, res)
		}
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminDeleteFile 批量删除文件
func AdminDeleteFile(c *gin.Context) {
	var service admin.FileBatchService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Delete(c)
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminListShare 列出分享
func AdminListShare(c *gin.Context) {
	var service admin.AdminListService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Shares()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminDeleteShare 批量删除分享
func AdminDeleteShare(c *gin.Context) {
	var service admin.ShareBatchService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Delete(c)
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminListDownload 列出离线下载任务
func AdminListDownload(c *gin.Context) {
	var service admin.AdminListService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Downloads()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminDeleteDownload 批量删除任务
func AdminDeleteDownload(c *gin.Context) {
	var service admin.TaskBatchService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Delete(c)
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminListTask 列出任务
func AdminListTask(c *gin.Context) {
	var service admin.AdminListService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Tasks()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminDeleteTask 批量删除任务
func AdminDeleteTask(c *gin.Context) {
	var service admin.TaskBatchService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.DeleteGeneral(c)
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminCreateImportTask 新建文件导入任务
func AdminCreateImportTask(c *gin.Context) {
	var service admin.ImportTaskService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Create(c, CurrentUser(c))
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminListFolders 列出用户或外部文件系统目录
func AdminListFolders(c *gin.Context) {
	var service admin.ListFolderService
	if err := c.ShouldBindUri(&service); err == nil {
		res := service.List(c)
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminListNodes 列出从机节点
func AdminListNodes(c *gin.Context) {
	var service admin.AdminListService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Nodes()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminAddNode 新建节点
func AdminAddNode(c *gin.Context) {
	var service admin.AddNodeService
	if err := c.ShouldBindJSON(&service); err == nil {
		res := service.Add()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminToggleNode 启用/暂停节点
func AdminToggleNode(c *gin.Context) {
	var service admin.ToggleNodeService
	if err := c.ShouldBindUri(&service); err == nil {
		res := service.Toggle()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminDeleteGroup 删除用户组
func AdminDeleteNode(c *gin.Context) {
	var service admin.NodeService
	if err := c.ShouldBindUri(&service); err == nil {
		res := service.Delete()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}

// AdminGetNode 获取节点详情
func AdminGetNode(c *gin.Context) {
	var service admin.NodeService
	if err := c.ShouldBindUri(&service); err == nil {
		res := service.Get()
		respond(c, res)
	} else {
		respond(c, ErrorResponse(err))
	}
}
