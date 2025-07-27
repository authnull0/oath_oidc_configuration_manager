package middlewares

import (
	"fmt"
	"time"

	"oath_oidc_configuration_manager/src/db"
	"oath_oidc_configuration_manager/src/dto"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// ConnectToTenantDB connects to tenant DB using either email or tenant ID
func ConnectToTenantDB(masterDB *gorm.DB, userEmail *string, tenantID *string) (*gorm.DB, error) {
	if userEmail == nil && tenantID == nil {
		return nil, fmt.Errorf("either userEmail or tenantID must be provided")
	}

	if userEmail != nil && tenantID != nil {
		return nil, fmt.Errorf("provide either userEmail or tenantID, not both")
	}

	var tenant dto.Tenant
	var err error

	// Query based on the provided parameter
	if userEmail != nil {
		err = masterDB.First(&tenant, "email = ?", *userEmail).Error
	} else {
		err = masterDB.First(&tenant, "tenant_id = ?", *tenantID).Error
	}

	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	tenantDBName := tenant.TenantDB

	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
		db.AppConfig.DBHost, db.AppConfig.DBUser, db.AppConfig.DBPassword, tenantDBName, db.AppConfig.DBPort,
	)

	tenantDB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to tenant DB '%s': %w", tenantDBName, err)
	}

	// Configure connection pool settings
	sqlDB, err := tenantDB.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw DB: %w", err)
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)
	sqlDB.SetConnMaxIdleTime(10 * time.Minute)

	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("failed to ping tenant DB '%s': %w", tenantDBName, err)
	}

	return tenantDB, nil
}

// Helper function to safely close tenant DB connection
func CloseTenantDB(tenantDB *gorm.DB) error {
	if tenantDB == nil {
		return nil
	}

	sqlDB, err := tenantDB.DB()
	if err != nil {
		return err
	}

	return sqlDB.Close()
}

// Connection pool manager for tenant databases
type TenantDBManager struct {
	connections map[string]*gorm.DB
}

var dbManager = &TenantDBManager{
	connections: make(map[string]*gorm.DB),
}

// GetOrCreateTenantDB gets existing connection or creates new one using email or tenant ID
func GetConnectionDynamically(masterDB *gorm.DB, userEmail *string, tenantID *string) (*gorm.DB, error) {
	if userEmail == nil && tenantID == nil {
		return nil, fmt.Errorf("either userEmail or tenantID must be provided")
	}

	if userEmail != nil && tenantID != nil {
		return nil, fmt.Errorf("provide either userEmail or tenantID, not both")
	}

	var tenant dto.Tenant
	var err error

	// Query based on the provided parameter
	if userEmail != nil {
		err = masterDB.First(&tenant, "email = ?", *userEmail).Error
	} else {
		err = masterDB.First(&tenant, "tenant_id = ?", *tenantID).Error
	}

	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	tenantDBName := tenant.TenantDB

	// Check if we already have a connection
	if db, exists := dbManager.connections[tenantDBName]; exists {
		// Test if connection is still alive
		if sqlDB, err := db.DB(); err == nil {
			if err := sqlDB.Ping(); err == nil {
				return db, nil
			}
		}
		// Connection is dead, remove it
		delete(dbManager.connections, tenantDBName)
	}

	// Create new connection
	tenantDB, err := ConnectToTenantDB(masterDB, userEmail, tenantID)
	if err != nil {
		return nil, err
	}

	// Cache the connection
	dbManager.connections[tenantDBName] = tenantDB

	return tenantDB, nil
}
