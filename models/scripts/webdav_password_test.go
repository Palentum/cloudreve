package scripts

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestUpgradeWebdavPasswords_Run(t *testing.T) {
	a := assert.New(t)
	script := UpgradeWebdavPasswords(0)

	hash, err := bcrypt.GenerateFromPassword([]byte("already-hashed"), bcrypt.MinCost)
	a.NoError(err)
	rows := sqlmock.NewRows([]string{"id", "password"}).
		AddRow(1, "plain-password").
		AddRow(2, string(hash))

	mock.ExpectQuery("SELECT(.+)webdavs").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	mock.ExpectQuery("SELECT(.+)webdavs").WillReturnRows(rows)
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE(.+)webdavs").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	script.Run(context.Background())
	a.NoError(mock.ExpectationsWereMet())
}
