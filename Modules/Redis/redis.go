package Redis

import (
	"context"
	"fmt"

	"github.com/official-biswadeb941/HopZero-DNS/Modules/Loader"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Logger"
	"github.com/redis/go-redis/v9"
)

var (
	RedisClient *redis.Client
	Ctx         = context.Background()
	redisLogger *Logger.ModuleLogger
)

// InitRedis initializes Redis client and sets up logger
func InitRedis() {
	conf := Loader.AppConfig.Redis

	var err error
	redisLogger, err = Logger.GetLogger("Redis_Logs.log")
	if err != nil {
		fmt.Printf("[Redis][ERROR] Logger init failed: %v\n", err)
		return
	}

	LogInfo(fmt.Sprintf("Connecting to Redis server at %s...", conf.Addr))

	RedisClient = redis.NewClient(&redis.Options{
		Addr:         conf.Addr,
		Password:     conf.Password,
		DB:           conf.DB,
		PoolSize:     conf.ConnectionPool.MaxConnections,
		MinIdleConns: conf.ConnectionPool.MaxConnections,
	})

	// Test connection
	_, err = RedisClient.Ping(Ctx).Result()
	if err != nil {
		LogError(fmt.Sprintf("Failed to connect to Redis server at %s - %v", conf.Addr, err))
	} else {
		LogInfo(fmt.Sprintf("Successfully connected to Redis server at %s", conf.Addr))
	}
}

// LogInfo logs an info-level message to Redis logger
func LogInfo(message string) {
	if redisLogger != nil {
		redisLogger.Info(message)
	} else {
		fmt.Printf("[Redis][INFO] %s\n", message)
	}
}

// LogWarn logs a warning-level message to Redis logger
func LogWarn(message string) {
	if redisLogger != nil {
		redisLogger.Warn(message)
	} else {
		fmt.Printf("[Redis][WARN] %s\n", message)
	}
}

// LogError logs an error-level message to Redis logger
func LogError(message string) {
	if redisLogger != nil {
		redisLogger.Error(message)
	} else {
		fmt.Printf("[Redis][ERROR] %s\n", message)
	}
}
