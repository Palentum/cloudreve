package model

import (
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"regexp"
	"testing"
)

func TestWebdav_Create(t *testing.T) {
	asserts := assert.New(t)
	// 成功
	{
		mock.ExpectBegin()
		mock.ExpectExec("INSERT(.+)").WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()
		task := Webdav{}
		id, err := task.Create()
		asserts.NoError(mock.ExpectationsWereMet())
		asserts.NoError(err)
		asserts.EqualValues(1, id)
	}

	// 失败
	{
		mock.ExpectBegin()
		mock.ExpectExec("INSERT(.+)").WillReturnError(errors.New("error"))
		mock.ExpectRollback()
		task := Webdav{}
		id, err := task.Create()
		asserts.NoError(mock.ExpectationsWereMet())
		asserts.Error(err)
		asserts.EqualValues(0, id)
	}
}

func TestHashWebdavPassword(t *testing.T) {
	asserts := assert.New(t)

	hash, err := HashWebdavPassword("testpassword")
	asserts.NoError(err)
	asserts.NotEmpty(hash)

	// 验证生成的哈希可以被 bcrypt 正确比较
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("testpassword"))
	asserts.NoError(err)

	// 验证错误密码不匹配
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrongpassword"))
	asserts.Error(err)
}

func TestWebdav_SetPassword(t *testing.T) {
	asserts := assert.New(t)

	webdav := &Webdav{}
	err := webdav.SetPassword("mypassword")
	asserts.NoError(err)
	asserts.NotEmpty(webdav.Password)

	// 验证 bcrypt 格式
	asserts.True(len(webdav.Password) > 0)
	err = bcrypt.CompareHashAndPassword([]byte(webdav.Password), []byte("mypassword"))
	asserts.NoError(err)
}

func TestWebdav_CheckPassword(t *testing.T) {
	asserts := assert.New(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("correct"), 12)
	webdav := &Webdav{Password: string(hash)}

	asserts.True(webdav.CheckPassword("correct"))
	asserts.False(webdav.CheckPassword("wrong"))
}

func TestGetWebdavByAccount(t *testing.T) {
	asserts := assert.New(t)

	// 生成测试用 bcrypt 哈希
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpass"), 12)

	// 成功匹配
	{
		rows := sqlmock.NewRows([]string{"id", "password", "user_id"}).
			AddRow(1, string(hash), 1)
		mock.ExpectQuery("SELECT(.+)").WillReturnRows(rows)
		webdav, err := GetWebdavByAccount("testpass", 1)
		asserts.NoError(mock.ExpectationsWereMet())
		asserts.NoError(err)
		asserts.EqualValues(1, webdav.ID)
	}

	// 密码不匹配
	{
		rows := sqlmock.NewRows([]string{"id", "password", "user_id"}).
			AddRow(1, string(hash), 1)
		mock.ExpectQuery("SELECT(.+)").WillReturnRows(rows)
		_, err := GetWebdavByAccount("wrongpass", 1)
		asserts.NoError(mock.ExpectationsWereMet())
		asserts.Error(err)
	}

	// 无记录
	{
		mock.ExpectQuery("SELECT(.+)").WillReturnRows(sqlmock.NewRows([]string{"id"}))
		_, err := GetWebdavByAccount("e", 1)
		asserts.NoError(mock.ExpectationsWereMet())
		asserts.Error(err)
	}

	// 超过 10 个账号时，后续账号也应可认证
	{
		hash, _ := HashWebdavPassword("latepass")
		rows := sqlmock.NewRows([]string{"id", "password", "user_id"})
		for i := 1; i <= 10; i++ {
			rows.AddRow(i, "invalid-bcrypt-hash", 1)
		}
		rows.AddRow(11, hash, 1)

		query := regexp.QuoteMeta("SELECT * FROM `webdavs` WHERE `webdavs`.`deleted_at` IS NULL AND ((user_id = ?))")
		mock.ExpectQuery(query).WithArgs(1).WillReturnRows(rows)
		webdav, err := GetWebdavByAccount("latepass", 1)
		asserts.NoError(mock.ExpectationsWereMet())
		asserts.NoError(err)
		if asserts.NotNil(webdav) {
			asserts.EqualValues(11, webdav.ID)
		}
	}
}

func TestListWebDAVAccounts(t *testing.T) {
	asserts := assert.New(t)
	mock.ExpectQuery("SELECT(.+)").WillReturnRows(sqlmock.NewRows([]string{"id"}))
	res := ListWebDAVAccounts(1)
	asserts.NoError(mock.ExpectationsWereMet())
	asserts.Len(res, 0)
}

func TestDeleteWebDAVAccountByID(t *testing.T) {
	asserts := assert.New(t)
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE(.+)").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	DeleteWebDAVAccountByID(1, 1)
	asserts.NoError(mock.ExpectationsWereMet())
}
