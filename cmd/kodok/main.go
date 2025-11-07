package main

import (
    "context"
    "os"
    "fmt"
    "os/signal"
    "syscall"

    "github.com/fatih/color"
    "github.com/rhyru9/kodok/internal/cache"
    "github.com/rhyru9/kodok/internal/core"
    "github.com/rhyru9/kodok/internal/fetch"
    "github.com/rhyru9/kodok/internal/output"
    "github.com/rhyru9/kodok/internal/parse"
    "github.com/rhyru9/kodok/internal/scan"
)

func main() {
    // banner
    printBanner()
    // Parse configuration - FIX: Return url and filePath separately
    config, singleURL, filePath := core.ParseFlags()
    // Validate configuration
    if err := core.ValidateConfig(config); err != nil {
        color.Red("❌ Configuration error: %s", err)
        os.Exit(1)
    }
    
    // FIX: Get URLs from correct sources
    urls, err := core.GetURLsFromInput(singleURL, filePath)
    if err != nil {
        color.Red("❌ Error getting URLs: %s", err)
        os.Exit(1)
    }
    
    if len(urls) == 0 {
        color.Red("❌ No URLs to process")
        os.Exit(1)
    }
    
    // Initialize components
    workerPool := core.NewWorkerPool(config.MaxWorkers)
    dedup := cache.NewDeduplicator(config.CacheSize)
    fetcher := fetch.NewFetcher(config.RequestTimeout, config.RetryAttempts)
    parser := parse.NewExtractor()
    scanner := scan.NewSecretScanner()
    outputWriter, err := output.NewWriter(config.OutputFile)
    if err != nil {
        color.Red("❌ Error creating output files: %s", err)
        os.Exit(1)
    }
    defer outputWriter.Close()
    
    // Create processor
    processor := core.NewProcessor(
        config,
        workerPool,
        dedup,
        fetcher,
        parser,
        scanner,
        outputWriter,
    )
    
    // Setup context with cancellation
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    // Setup signal handling for graceful shutdown
    setupSignalHandler(workerPool, processor, cancel)
    
    // Start worker pool with context
    workerPool.Start(ctx)
    defer func() {
        workerPool.Stop()
        workerPool.Wait()
    }()
    
    // Process URLs
    if err := processor.ProcessURLs(urls); err != nil {
        color.Red("❌ Processing error: %s", err)
        os.Exit(1)
    }
    
    // Print final summary
    processor.PrintSummary()
}

// setupSignalHandler sets up signal handling for graceful shutdown
func setupSignalHandler(workerPool *core.WorkerPool, processor *core.Processor, cancel context.CancelFunc) {
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    
    go func() {
        <-sigChan
        color.Yellow("\n⚠️  Received interrupt signal, shutting down gracefully...")
        
        // Cancel context to stop new tasks
        cancel()
        
        // Cancel processor
        processor.Cancel()
        
        // Stop worker pool
        workerPool.Stop()
        
        color.Yellow("👋 Shutdown complete")
        os.Exit(0)
    }()
}

// init function for color setup
func init() {
    // Enable color output
    color.NoColor = false
}

func printBanner() {
    banner := `
░██     ░██   ░██████   ░███████     ░██████   ░██     ░██ 
░██    ░██   ░██   ░██  ░██   ░██   ░██   ░██  ░██    ░██  
░██   ░██   ░██     ░██ ░██    ░██ ░██     ░██ ░██   ░██   
░███████    ░██     ░██ ░██    ░██ ░██     ░██ ░███████    
░██   ░██   ░██     ░██ ░██    ░██ ░██     ░██ ░██   ░██   
░██    ░██   ░██   ░██  ░██   ░██   ░██   ░██  ░██    ░██  
░██     ░██   ░██████   ░███████     ░██████   ░██     ░██ 
                                                           
Author   : rhyru9
GitHub   : https://github.com/rhyru9/kodok
License  : MIT
`
    fmt.Print(banner)
}