package Loader

import (
	"fmt"
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Redis struct {
		Addr           string `yaml:"addr"`
		Password       string `yaml:"password"`
		DB             int    `yaml:"db"`
		ConnectionPool struct {
			MaxConnections int `yaml:"max_connections"`
			Timeout        int `yaml:"timeout"`
		} `yaml:"connection_pool"`
	} `yaml:"redis"`

	MySQL struct {
		User           string `yaml:"user"`
		Password       string `yaml:"password"`
		Host           string `yaml:"host"`
		Port           int    `yaml:"port"`
		Database       string `yaml:"database"`
		ConnectionPool struct {
			PoolSize         int    `yaml:"pool_size"`
			PoolName         string `yaml:"pool_name"`
			PoolResetSession bool   `yaml:"pool_reset_session"`
			Timeout          int    `yaml:"timeout"`
		} `yaml:"connection_pool"`
	} `yaml:"mysql"`
}

var AppConfig Config

// LoadConfig reads and loads the configuration from the given file
func LoadConfig(path string) error {
	// Read the configuration file
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("❌ Failed to read config file: %v", err)
	}

	// Unmarshal the YAML data into the AppConfig struct
	if err := yaml.Unmarshal(data, &AppConfig); err != nil {
		return fmt.Errorf("❌ Failed to parse config: %v", err)
	}

	// Validate the loaded config
	if err := validateConfig(); err != nil {
		return fmt.Errorf("❌ Invalid config: %v", err)
	}

	log.Println("✅ Config loaded successfully")
	return nil
}

// validateConfig performs basic validation on the loaded config
func validateConfig() error {
	// Check Redis configuration
	if AppConfig.Redis.Addr == "" {
		return fmt.Errorf("redis address is missing")
	}
	if AppConfig.Redis.ConnectionPool.MaxConnections <= 0 {
		return fmt.Errorf("redis max_connections must be a positive number")
	}
	if AppConfig.Redis.ConnectionPool.Timeout <= 0 {
		return fmt.Errorf("redis timeout must be a positive number")
	}

	// Check MySQL configuration
	if AppConfig.MySQL.User == "" || AppConfig.MySQL.Password == "" || AppConfig.MySQL.Host == "" || AppConfig.MySQL.Database == "" {
		return fmt.Errorf("MySQL configuration is incomplete")
	}
	if AppConfig.MySQL.Port <= 0 {
		return fmt.Errorf("MySQL port must be a positive number")
	}
	if AppConfig.MySQL.ConnectionPool.PoolSize <= 0 {
		return fmt.Errorf("MySQL pool_size must be a positive number")
	}
	if AppConfig.MySQL.ConnectionPool.Timeout <= 0 {
		return fmt.Errorf("MySQL timeout must be a positive number")
	}

	return nil
}
