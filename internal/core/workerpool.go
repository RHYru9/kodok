package core

import (
    "context"
    "sync"
    "time"
)

// WorkerPool manages a pool of worker goroutines
type WorkerPool struct {
    workers     int
    taskQueue   chan func()
    wg          sync.WaitGroup
    ctx         context.Context
    cancel      context.CancelFunc
    started     bool
    mu          sync.Mutex
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(workers int) *WorkerPool {
    if workers < 1 {
        workers = 1
    }
    if workers > 100 {
        workers = 100
    }
    
    return &WorkerPool{
        workers:   workers,
        taskQueue: make(chan func(), 1000), // Buffered channel
    }
}

// Start begins processing tasks
func (wp *WorkerPool) Start(ctx context.Context) {
    wp.mu.Lock()
    defer wp.mu.Unlock()
    
    if wp.started {
        return
    }
    
    wp.ctx, wp.cancel = context.WithCancel(ctx)
    wp.started = true
    
    // Start worker goroutines
    for i := 0; i < wp.workers; i++ {
        wp.wg.Add(1)
        go wp.worker()
    }
}

// worker processes tasks from the queue
func (wp *WorkerPool) worker() {
    defer wp.wg.Done()
    
    for {
        select {
        case task, ok := <-wp.taskQueue:
            if !ok {
                return // Channel closed, exit cleanly
            }
            
            // Execute the task
            if task != nil {
                task()
            }
            
        case <-wp.ctx.Done():
            return // Context cancelled, exit cleanly
        }
    }
}

// Submit adds a task to the queue
func (wp *WorkerPool) Submit(task func()) bool {
    wp.mu.Lock()
    started := wp.started
    ctx := wp.ctx
    wp.mu.Unlock()
    
    if !started {
        return false
    }
    
    select {
    case wp.taskQueue <- task:
        return true
    case <-ctx.Done():
        return false
    case <-time.After(100 * time.Millisecond):
        // Queue is full, try with timeout
        select {
        case wp.taskQueue <- task:
            return true
        case <-ctx.Done():
            return false
        default:
            return false
        }
    }
}

// Wait waits for all tasks to complete
func (wp *WorkerPool) Wait() {
    wp.mu.Lock()
    if !wp.started {
        wp.mu.Unlock()
        return
    }
    wp.mu.Unlock()
    
    wp.wg.Wait()
}

// Stop gracefully stops the worker pool
func (wp *WorkerPool) Stop() {
    wp.mu.Lock()
    defer wp.mu.Unlock()
    
    if !wp.started {
        return
    }
    
    // Cancel context to stop workers and prevent new work from being accepted.
    // We intentionally do NOT close the taskQueue channel here to avoid a
    // race condition where Submit() panics sending to a closed channel.
    // Workers exit via ctx.Done(); remaining buffered tasks are discarded.
    if wp.cancel != nil {
        wp.cancel()
    }

    wp.started = false
}

// ActiveWorkers returns the number of active workers
func (wp *WorkerPool) ActiveWorkers() int {
    wp.mu.Lock()
    defer wp.mu.Unlock()
    
    if !wp.started {
        return 0
    }
    return wp.workers
}

// QueuedTasks returns the number of queued tasks
func (wp *WorkerPool) QueuedTasks() int {
    return len(wp.taskQueue)
}

// Context returns the worker pool context
func (wp *WorkerPool) Context() context.Context {
    wp.mu.Lock()
    defer wp.mu.Unlock()
    return wp.ctx
}