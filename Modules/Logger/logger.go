package Logger

import (
	"log"
	"os"
	"fmt"
	"path"
)

var (
	// Paths for the log files using path.Join for cross-platform compatibility
	LogDir        = "Logs"
	AppLogPath    = path.Join(LogDir, "application.log")
	QueryLogPath  = path.Join(LogDir, "query.log")
	// Loggers
	AppLogger     *log.Logger
	QueryLogger   *log.Logger
)

func init() {
	// Ensure Logs directory exists
	if err := ensureDirExists(LogDir); err != nil {
		log.Fatalf("Could not create log directory: %v", err)
	}

	// Ensure log files exist and open them for appending
	appLogFile, err := openLogFile(AppLogPath)
	if err != nil {
		log.Fatalf("Error opening application log file: %v", err)
	}

	queryLogFile, err := openLogFile(QueryLogPath)
	if err != nil {
		log.Fatalf("Error opening query log file: %v", err)
	}

	// Create loggers
	AppLogger = log.New(appLogFile, "[APP] ", log.Ldate|log.Ltime|log.Lshortfile)
	QueryLogger = log.New(queryLogFile, "[QUERY] ", log.Ldate|log.Ltime|log.Lshortfile)
}

// ensureDirExists checks if the directory exists, and creates it if not
func ensureDirExists(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}
	return nil
}

// openLogFile opens the log file for appending, creates it if it doesn't exist
func openLogFile(filePath string) (*os.File, error) {
	// Open file for appending, create if doesn't exist
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return nil, fmt.Errorf("could not open log file %s: %v", filePath, err)
	}
	return file, nil
}

// LogApplication logs general application-related messages
func LogApplication(message string) {
	AppLogger.Println(message)
}

// LogQuery logs query-specific messages (e.g., SQL queries)
func LogQuery(query string) {
	QueryLogger.Println(query)
}

// LogError logs error messages to both loggers
func LogError(message string, err error) {
	AppLogger.Printf("ERROR: %s - %v", message, err)
	QueryLogger.Printf("ERROR: %s - %v", message, err)
}

// Example usage of the logger (can be removed later)
func main() {
	// Example usage of the logging system
	LogApplication("This is an application-level log")
	LogQuery("SELECT * FROM users WHERE id = 1")
	LogError("Failed to execute query", fmt.Errorf("Query timeout"))
}
