package Logger

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

var (
	baseLogDir = ".Logs"
	loggers    = make(map[string]*ModuleLogger)
	globalLock sync.Mutex
)

// ModuleLogger defines a logger for a specific module
type ModuleLogger struct {
	FileLogger *log.Logger
	ModuleName string
	lock       sync.Mutex
}

// GetLogger returns a thread-safe logger for a module with automatic file naming
func GetLogger(moduleName string) (*ModuleLogger, error) {
	globalLock.Lock()
	defer globalLock.Unlock()

	if logger, exists := loggers[moduleName]; exists {
		return logger, nil
	}

	// Ensure the Logs/ directory exists
	if err := os.MkdirAll(baseLogDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base log dir: %v", err)
	}

	// Auto-generate log file name: Logs/<ModuleName>.log
	logFilePath := filepath.Join(baseLogDir, moduleName+".log")

	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return nil, fmt.Errorf("could not open log file for %s: %v", moduleName, err)
	}

	fileLogger := log.New(logFile, "", log.Ldate|log.Ltime|log.Lshortfile)

	modLogger := &ModuleLogger{
		FileLogger: fileLogger,
		ModuleName: moduleName,
	}

	loggers[moduleName] = modLogger
	return modLogger, nil
}

// Emoji-enhanced log functions
func (l *ModuleLogger) Info(msg string) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.FileLogger.Printf("[✅ %s][INFO ] %s", l.ModuleName, msg)
}

func (l *ModuleLogger) Warn(msg string) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.FileLogger.Printf("[⚠️ %s][WARN ] %s", l.ModuleName, msg)
}

func (l *ModuleLogger) Error(msg string) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.FileLogger.Printf("[🔥 %s][ERROR] %s", l.ModuleName, msg)
}
