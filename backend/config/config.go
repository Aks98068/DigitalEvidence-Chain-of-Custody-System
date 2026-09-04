
package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	Port       string
	JWTSecret  string
	SessionTTL time.Duration
	UploadDir  string
}

var AppConfig Config

func LoadConfig() {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, using defaults")
	}

	AppConfig.DBHost = getEnv("DB_HOST", "localhost")
	AppConfig.DBPort = getEnv("DB_PORT", "3306")
	AppConfig.DBUser = getEnv("DB_USER", "root")
	AppConfig.DBPassword = getEnv("DB_PASSWORD", "")
	AppConfig.DBName = getEnv("DB_NAME", "forensix")
	AppConfig.Port = getEnv("PORT", "8080")
	AppConfig.JWTSecret = getEnv("JWT_SECRET", "your-secret-key-change-in-production")
	ttl, _ := strconv.Atoi(getEnv("SESSION_TTL_MINUTES", "60"))
	AppConfig.SessionTTL = time.Duration(ttl) * time.Minute
	AppConfig.UploadDir = getEnv("UPLOAD_DIR", "./uploads")
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

