package scripts

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

func TestUpgradeTo390_RunMigratesPasswords(t *testing.T) {
	a := assert.New(t)
	script := UpgradeTo390(0)

	mock.ExpectQuery("SELECT(.+)shares").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT(.+)webdavs").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	script.Run(context.Background())
	a.NoError(mock.ExpectationsWereMet())
}
