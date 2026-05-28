package controllers

import (
	capservice "github.com/cloudreve/Cloudreve/v3/pkg/cap"
	"github.com/gin-gonic/gin"
)

// CreateCapChallenge 创建 Cap 工作量证明挑战。
func CreateCapChallenge(c *gin.Context) {
	challenge, err := capservice.CreateChallengeForIP(c.ClientIP())
	if err != nil {
		c.JSON(500, gin.H{"success": false, "error": "Failed to create challenge"})
		return
	}

	c.JSON(200, challenge)
}

// RedeemCapChallenge 校验 Cap 解题结果并签发验证 token。
func RedeemCapChallenge(c *gin.Context) {
	var req capservice.RedeemRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(200, capservice.RedeemResponse{Success: false, Error: "Invalid body"})
		return
	}

	c.JSON(200, capservice.RedeemChallenge(req))
}
