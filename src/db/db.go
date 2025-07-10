// db/db.go (simplified database configuration)
package db

import (
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB(cfg *Config) {

	// Initialize database
	dsn := cfg.DatabaseURL

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// // Auto-migrate models
	// if err := DB.AutoMigrate(&models.User{}, &models.Project{}, &models.Client{}, &models.Scope{}, &models.Role{}, &models.Group{}, &models.Resource{}); err != nil {
	// 	log.Fatal("Failed to migrate database:", err)
	// }

	log.Println("Database connected successfully")
}
