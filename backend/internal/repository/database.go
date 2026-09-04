
package repository

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"forensix-backend/config"
)

var DB *sql.DB

func InitDB() error {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		config.AppConfig.DBUser,
		config.AppConfig.DBPassword,
		config.AppConfig.DBHost,
		config.AppConfig.DBPort,
		config.AppConfig.DBName)

	var err error
	DB, err = sql.Open("mysql", dsn)
	if err != nil {
		return err
	}

	DB.SetMaxOpenConns(25)
	DB.SetMaxIdleConns(25)
	DB.SetConnMaxLifetime(5 * time.Minute)

	if err = DB.Ping(); err != nil {
		return err
	}

	log.Println("Database connected successfully!")
	return nil
}

