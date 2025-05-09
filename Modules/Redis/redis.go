package Redis

import (
	"context"
	"fmt"

	"github.com/official-biswadeb941/HopZero-DNS/Modules/Logger"
	"github.com/official-biswadeb941/HopZero-DNS/Modules/Loader"
	"github.com/redis/go-redis/v9"
)

var RedisClient *redis.Client
var Ctx = context.Background()

func InitRedis() {
	conf := Loader.AppConfig.Redis // ✅ Fetch config from Loader

	// Log the Redis connection attempt
	Logger.LogApplication(fmt.Sprintf("Connecting to Redis server at %s...", conf.Addr))

	RedisClient = redis.NewClient(&redis.Options{
		Addr:         conf.Addr,
		Password:     conf.Password,
		DB:           conf.DB,
		PoolSize:     conf.ConnectionPool.MaxConnections,
		MinIdleConns: conf.ConnectionPool.MaxConnections,
	})

	// Test connection to Redis
	_, err := RedisClient.Ping(Ctx).Result()
	if err != nil {
		// Log the error if Redis connection fails
		Logger.LogError(fmt.Sprintf("Failed to connect to Redis server at %s", conf.Addr), err)
	} else {
		// Log successful connection
		Logger.LogApplication(fmt.Sprintf("Successfully connected to Redis server at %s", conf.Addr))
	}
}
