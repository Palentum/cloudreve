package task

import (
	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/cloudreve/Cloudreve/v3/pkg/conf"
	"github.com/cloudreve/Cloudreve/v3/pkg/util"
)

// TaskPoll 要使用的任务池
var TaskPoll Pool

type Pool interface {
	Add(num int)
	Submit(job Job) error
}

// AsyncPool 带有最大配额和队列深度限制的任务池
type AsyncPool struct {
	// 容量
	idleWorker chan int
	// 排队中和执行中的任务配额
	queue chan struct{}
}

const queueDepthFactor = 2

func newAsyncPool(maxWorker int) *AsyncPool {
	return &AsyncPool{
		idleWorker: make(chan int, maxWorker),
		queue:      make(chan struct{}, maxWorker*queueDepthFactor),
	}
}

// Add 增加可用Worker数量
func (pool *AsyncPool) Add(num int) {
	for i := 0; i < num; i++ {
		pool.idleWorker <- 1
	}
}

// ObtainWorker 阻塞直到获取新的Worker
func (pool *AsyncPool) obtainWorker() Worker {
	select {
	case <-pool.idleWorker:
		// 有空闲Worker名额时，返回新Worker
		return &GeneralWorker{}
	}
}

// FreeWorker 添加空闲Worker
func (pool *AsyncPool) freeWorker() {
	pool.Add(1)
}

// Submit 开始提交任务
func (pool *AsyncPool) Submit(job Job) error {
	select {
	case pool.queue <- struct{}{}:
	default:
		job.SetError(&JobError{Msg: "Task queue is full.", Error: ErrQueueFull.Error()})
		job.SetStatus(Error)
		return ErrQueueFull
	}

	go func() {
		defer func() {
			<-pool.queue
		}()

		util.Log().Debug("Waiting for Worker.")
		worker := pool.obtainWorker()
		defer func() {
			pool.freeWorker()
			util.Log().Debug("Worker released.")
		}()
		util.Log().Debug("Worker obtained.")
		worker.Do(job)
	}()

	return nil
}

// Init 初始化任务池
func Init() {
	maxWorker := model.GetIntSetting("max_worker_num", 10)
	TaskPoll = newAsyncPool(maxWorker)
	TaskPoll.Add(maxWorker)
	util.Log().Info("Initialize task queue with WorkerNum = %d", maxWorker)

	if conf.SystemConfig.Mode == "master" {
		Resume(TaskPoll)
	}
}
