package task

import (
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/cloudreve/Cloudreve/v3/pkg/cache"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

var mock sqlmock.Sqlmock

// TestMain 初始化数据库Mock
func TestMain(m *testing.M) {
	var db *sql.DB
	var err error
	db, mock, err = sqlmock.New()
	if err != nil {
		panic("An error was not expected when opening a stub database connection")
	}
	model.DB, _ = gorm.Open("mysql", db)
	defer db.Close()
	m.Run()
}

func TestInit(t *testing.T) {
	asserts := assert.New(t)
	cache.Set("setting_max_worker_num", "10", 0)
	mock.ExpectQuery("SELECT(.+)").WithArgs(Queued, Processing).WillReturnRows(sqlmock.NewRows([]string{"type"}).AddRow(-1))
	Init()
	asserts.NoError(mock.ExpectationsWereMet())
	asserts.Len(TaskPoll.(*AsyncPool).idleWorker, 10)
	asserts.Equal(20, cap(TaskPoll.(*AsyncPool).queue))
}

func TestPool_Submit(t *testing.T) {
	asserts := assert.New(t)
	pool := newAsyncPool(1)
	pool.Add(1)

	done := make(chan struct{})
	job := &MockJob{
		DoFunc: func() {
			close(done)
		},
	}

	asserts.NoError(pool.Submit(job))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("submitted job was not executed")
	}
}

func TestPool_SubmitReturnsErrorWhenQueueFull(t *testing.T) {
	asserts := assert.New(t)
	pool := &AsyncPool{
		idleWorker: make(chan int, 1),
		queue:      make(chan struct{}, 1),
	}

	done := make(chan struct{})
	job := &MockJob{
		DoFunc: func() {
			close(done)
		},
	}
	asserts.NoError(pool.Submit(job))

	rejected := &MockJob{
		DoFunc: func() {
			t.Fatal("rejected job must not run")
		},
	}
	asserts.Equal(ErrQueueFull, pool.Submit(rejected))
	asserts.Equal(Error, rejected.Status)
	if asserts.NotNil(rejected.Err) {
		asserts.Equal(ErrQueueFull.Error(), rejected.Err.Error)
	}

	pool.Add(1)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("accepted job was not released")
	}
}
