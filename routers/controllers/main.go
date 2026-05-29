package controllers

import (
	"encoding/json"
	"net/http"

	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/cloudreve/Cloudreve/v3/pkg/serializer"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

// respond 根据 serializer.Response 的 Code 选择 HTTP 状态码写入响应，
// 与 middleware/common.go 中 httpStatusForCode 保持相同映射逻辑。
func respond(c *gin.Context, res serializer.Response) {
	var httpStatus int
	code := res.Code
	switch {
	case code == 0:
		httpStatus = http.StatusOK
	case code >= 200 && code < 600:
		httpStatus = code
	case code >= 40000 && code < 50000:
		httpStatus = http.StatusBadRequest
	default:
		httpStatus = http.StatusInternalServerError
	}
	c.JSON(httpStatus, res)
}

// ParamErrorMsg 根据Validator返回的错误信息给出错误提示
func ParamErrorMsg(filed string, tag string) string {
	// 未通过验证的表单域与中文对应
	fieldMap := map[string]string{
		"UserName": "Email",
		"Password": "Password",
		"Path":     "Path",
		"SourceID": "Source resource",
		"URL":      "URL",
		"Nick":     "Nickname",
	}
	// 未通过的规则与中文对应
	tagMap := map[string]string{
		"required": "cannot be empty",
		"min":      "too short",
		"max":      "too long",
		"email":    "format error",
	}
	fieldVal, findField := fieldMap[filed]
	if !findField {
		fieldVal = filed
	}
	tagVal, findTag := tagMap[tag]
	if findTag {
		// 返回拼接出来的错误信息
		return fieldVal + " " + tagVal
	}
	return ""
}

// ErrorResponse 返回错误消息
func ErrorResponse(err error) serializer.Response {
	// 处理 Validator 产生的错误
	if ve, ok := err.(validator.ValidationErrors); ok {
		for _, e := range ve {
			return serializer.ParamErr(
				ParamErrorMsg(e.Field(), e.Tag()),
				err,
			)
		}
	}

	if _, ok := err.(*json.UnmarshalTypeError); ok {
		return serializer.ParamErr("JSON marshall error", err)
	}

	return serializer.ParamErr("Parameter error", err)
}

// CurrentUser 获取当前用户
func CurrentUser(c *gin.Context) *model.User {
	if user, _ := c.Get("user"); user != nil {
		if u, ok := user.(*model.User); ok {
			return u
		}
	}
	return nil
}
