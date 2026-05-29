package task

import "errors"

var (
	// ErrUnknownTaskType 未知任务类型
	ErrUnknownTaskType = errors.New("unknown task type")
	// ErrQueueFull 任务队列已满
	ErrQueueFull = errors.New("task queue is full")
)
