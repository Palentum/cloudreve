package admin

import (
	"regexp"
	"strings"

	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/cloudreve/Cloudreve/v3/pkg/serializer"
)

// AdminListService 仪表盘列条目服务
type AdminListService struct {
	Page       int               `json:"page" binding:"min=1,required"`
	PageSize   int               `json:"page_size" binding:"min=1,required"`
	OrderBy    string            `json:"order_by"`
	Conditions map[string]string `form:"conditions"`
	Searches   map[string]string `form:"searches"`
}

// validColumnRe 只允许合法的 SQL 列名（字母/数字/下划线，可带表前缀）
var validColumnRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.]*$`)

// validOrderByRe 允许 "column asc" 或 "column desc" 格式
var validOrderByRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.]*(\s+(?i)(asc|desc))?$`)

// buildSafeSearch 将 Searches map 转为参数化的 LIKE 条件。
// 只处理列名在 allowed 白名单中的条目，值通过 ? 占位符传入。
func buildSafeSearch(searches map[string]string, allowed map[string]bool) (string, []interface{}) {
	conditions := make([]string, 0, len(searches))
	args := make([]interface{}, 0, len(searches))
	for k, v := range searches {
		if !allowed[k] || !validColumnRe.MatchString(k) {
			continue
		}
		conditions = append(conditions, k+" LIKE ?")
		args = append(args, "%"+v+"%")
	}
	if len(conditions) == 0 {
		return "", nil
	}
	return strings.Join(conditions, " OR "), args
}

// buildSafeConditions 将 Conditions map 转为参数化的 = 条件。
// 只处理列名在 allowed 白名单中的条目。
func buildSafeConditions(conditions map[string]string, allowed map[string]bool) (string, []interface{}) {
	clauses := make([]string, 0, len(conditions))
	args := make([]interface{}, 0, len(conditions))
	for k, v := range conditions {
		if !allowed[k] || !validColumnRe.MatchString(k) {
			continue
		}
		clauses = append(clauses, k+" = ?")
		args = append(args, v)
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return strings.Join(clauses, " AND "), args
}

// sanitizeOrderBy 校验 OrderBy 是否为合法的列名（可带 asc/desc），
// 不在白名单中或格式不合法时返回空字符串。
func sanitizeOrderBy(orderBy string, allowed map[string]bool) string {
	if orderBy == "" {
		return ""
	}
	if !validOrderByRe.MatchString(orderBy) {
		return ""
	}
	// 提取列名部分（去掉 asc/desc）
	col := strings.Fields(orderBy)[0]
	if !allowed[col] {
		return ""
	}
	return orderBy
}

// GroupList 获取用户组列表
func (service *NoParamService) GroupList() serializer.Response {
	var res []model.Group
	model.DB.Model(&model.Group{}).Find(&res)
	return serializer.Response{Data: res}
}
