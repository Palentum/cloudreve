package util

import (
	cryptorand "crypto/rand"
	"path/filepath"
	"regexp"
	"strings"
)

const letterRunes = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const letterRunesLen = len(letterRunes) // 62

// RandStringRunes 返回密码学安全的随机字符串（拒绝采样消除偏差）
func RandStringRunes(n int) string {
	b := make([]byte, n)
	// 256 - (256 % 62) = 248，丢弃 [248,255] 以消除模偏差
	const maxValid = byte(256 - 256%letterRunesLen)
	buf := make([]byte, n)
	i := 0
	for i < n {
		if _, err := cryptorand.Read(buf); err != nil {
			panic("util: 无法生成安全随机数: " + err.Error())
		}
		for _, v := range buf {
			if v < maxValid {
				b[i] = letterRunes[v%byte(letterRunesLen)]
				i++
				if i >= n {
					break
				}
			}
		}
	}
	return string(b)
}

// ContainsUint 返回list中是否包含
func ContainsUint(s []uint, e uint) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// IsInExtensionList 返回文件的扩展名是否在给定的列表范围内
func IsInExtensionList(extList []string, fileName string) bool {
	ext := strings.ToLower(filepath.Ext(fileName))
	// 无扩展名时
	if len(ext) == 0 {
		return false
	}

	if ContainsString(extList, ext[1:]) {
		return true
	}

	return false
}

// ContainsString 返回list中是否包含
func ContainsString(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// Replace 根据替换表执行批量替换
func Replace(table map[string]string, s string) string {
	for key, value := range table {
		s = strings.Replace(s, key, value, -1)
	}
	return s
}

// BuildRegexp 构建用于SQL查询用的多条件正则
func BuildRegexp(search []string, prefix, suffix, condition string) string {
	var res string
	for key, value := range search {
		res += prefix + regexp.QuoteMeta(value) + suffix
		if key < len(search)-1 {
			res += condition
		}
	}
	return res
}

// BuildConcat 根据数据库类型构建字符串连接表达式
func BuildConcat(str1, str2 string, DBType string) string {
	switch DBType {
	case "mysql":
		return "CONCAT(" + str1 + "," + str2 + ")"
	default:
		return str1 + "||" + str2
	}
}

// SliceIntersect 求两个切片交集
func SliceIntersect(slice1, slice2 []string) []string {
	m := make(map[string]int)
	nn := make([]string, 0)
	for _, v := range slice1 {
		m[v]++
	}

	for _, v := range slice2 {
		times, _ := m[v]
		if times == 1 {
			nn = append(nn, v)
		}
	}
	return nn
}

// SliceDifference 求两个切片差集
func SliceDifference(slice1, slice2 []string) []string {
	m := make(map[string]int)
	nn := make([]string, 0)
	inter := SliceIntersect(slice1, slice2)
	for _, v := range inter {
		m[v]++
	}

	for _, value := range slice1 {
		times, _ := m[value]
		if times == 0 {
			nn = append(nn, value)
		}
	}
	return nn
}
