// src/middlewares/tenant_middleware.go
package middlewares

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"oath_oidc_configuration_manager/src/db"
	models "oath_oidc_configuration_manager/src/models/dto"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// TenantDBMiddleware extracts tenant info from request and sets up tenant database connection
func TenantDBMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip tenant DB setup for health check and other non-tenant endpoints
		if c.Request.URL.Path == "/api/v1/health" {
			c.Next()
			return
		}

		// Parse request body to extract tenant_id and org_id
		var requestBody map[string]interface{}

		// Read the request body
		bodyBytes, err := c.GetRawData()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
			c.Abort()
			return
		}

		// Parse JSON
		if err := json.Unmarshal(bodyBytes, &requestBody); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON in request body"})
			c.Abort()
			return
		}

		// Restore the request body for downstream handlers
		c.Request.Body = &BodyReader{data: bodyBytes}

		// Extract tenant_id and org_id
		tenantIDStr, tenantExists := requestBody["tenant_id"].(string)
		orgIDStr, orgExists := requestBody["org_id"].(string)

		if !tenantExists || !orgExists {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "tenant_id and org_id are required in request body",
			})
			c.Abort()
			return
		}

		// Validate UUIDs
		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant_id format"})
			c.Abort()
			return
		}

		orgID, err := uuid.Parse(orgIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid org_id format"})
			c.Abort()
			return
		}

		// Get tenant database connection
		tenantDB, tenantDBName, err := GetTenantDatabase(tenantID, orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to connect to tenant database",
				"message": err.Error(),
			})
			c.Abort()
			return
		}

		// Set tenant info in context
		c.Set("tenant_id", tenantID)
		c.Set("org_id", orgID)
		c.Set("tenant_db", tenantDB)
		c.Set("tenant_db_name", tenantDBName)

		// Continue to next handler
		c.Next()

		// Optional: Close tenant DB connection after request
		// (You might want to use connection pooling instead)
		defer func() {
			if sqlDB, err := tenantDB.DB(); err == nil {
				sqlDB.Close()
			}
		}()
	}
}

// BodyReader allows reading request body multiple times
type BodyReader struct {
	data []byte
	pos  int
}

func (br *BodyReader) Read(p []byte) (n int, err error) {
	if br.pos >= len(br.data) {
		return 0, fmt.Errorf("EOF")
	}
	n = copy(p, br.data[br.pos:])
	br.pos += n
	return n, nil
}

func (br *BodyReader) Close() error {
	return nil
}

// GetTenantDatabase connects to the appropriate tenant database
func GetTenantDatabase(tenantID, orgID uuid.UUID) (*gorm.DB, string, error) {
	// First, get tenant info from main database
	user, err := getTenantInfo(tenantID, orgID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get tenant info: %w", err)
	}

	if user.TenantDB == "" {
		return nil, "", fmt.Errorf("tenant database name not found for tenant_id: %s", tenantID)
	}

	// Connect to tenant-specific database
	tenantDB, err := connectToTenantDB(user.TenantDB)
	if err != nil {
		return nil, "", fmt.Errorf("failed to connect to tenant database '%s': %w", user.TenantDB, err)
	}

	return tenantDB, user.TenantDB, nil
}

// getTenantInfo retrieves tenant information from main database
func getTenantInfo(tenantID, orgID uuid.UUID) (*models.User, error) {
	var user models.User

	// Query main database for tenant info
	err := db.DB.Where("tenant_id = ? AND id = ?", tenantID, orgID).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("tenant not found for tenant_id: %s, org_id: %s", tenantID, orgID)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	return &user, nil
}

// connectToTenantDB creates connection to tenant-specific database
func connectToTenantDB(tenantDBName string) (*gorm.DB, error) {
	cfg := db.GetConfig()

	// Build DSN for tenant database
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable search_path=%s",
		cfg.DBHost, cfg.DBUser, cfg.DBPassword, tenantDBName, cfg.DBPort, cfg.DBSchema,
	)

	// Open connection to tenant database
	tenantDB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to open tenant database connection: %w", err)
	}

	// Configure connection pool
	sqlDB, err := tenantDB.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw database connection: %w", err)
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)
	sqlDB.SetConnMaxIdleTime(10 * time.Minute)

	// Test connection
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("failed to ping tenant database: %w", err)
	}

	// Auto-migrate configuration tables in tenant database
	if err := tenantDB.AutoMigrate(&models.OAuthOIDCConfiguration{}); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("failed to migrate tenant database: %w", err)
	}

	return tenantDB, nil
}

// TenantConnectionPool manages tenant database connections
type TenantConnectionPool struct {
	connections map[string]*gorm.DB
	maxAge      time.Duration
	lastUsed    map[string]time.Time
}

var tenantPool = &TenantConnectionPool{
	connections: make(map[string]*gorm.DB),
	lastUsed:    make(map[string]time.Time),
	maxAge:      30 * time.Minute, // Close connections after 30 minutes of inactivity
}

// GetOrCreateTenantConnection gets existing connection or creates new one with pooling
func GetOrCreateTenantConnection(tenantID, orgID uuid.UUID) (*gorm.DB, error) {
	// Get tenant info
	user, err := getTenantInfo(tenantID, orgID)
	if err != nil {
		return nil, err
	}

	tenantDBName := user.TenantDB

	// Check if we have a valid existing connection
	if db, exists := tenantPool.connections[tenantDBName]; exists {
		// Check if connection is still alive and not too old
		if time.Since(tenantPool.lastUsed[tenantDBName]) < tenantPool.maxAge {
			if sqlDB, err := db.DB(); err == nil {
				if err := sqlDB.Ping(); err == nil {
					tenantPool.lastUsed[tenantDBName] = time.Now()
					return db, nil
				}
			}
		}
		// Connection is dead or too old, remove it
		if sqlDB, err := db.DB(); err == nil {
			sqlDB.Close()
		}
		delete(tenantPool.connections, tenantDBName)
		delete(tenantPool.lastUsed, tenantDBName)
	}

	// Create new connection
	tenantDB, err := connectToTenantDB(tenantDBName)
	if err != nil {
		return nil, err
	}

	// Cache the connection
	tenantPool.connections[tenantDBName] = tenantDB
	tenantPool.lastUsed[tenantDBName] = time.Now()

	return tenantDB, nil
}

// CleanupOldConnections removes old unused connections
func CleanupOldConnections() {
	for dbName, lastUsed := range tenantPool.lastUsed {
		if time.Since(lastUsed) > tenantPool.maxAge {
			if db, exists := tenantPool.connections[dbName]; exists {
				if sqlDB, err := db.DB(); err == nil {
					sqlDB.Close()
				}
				delete(tenantPool.connections, dbName)
				delete(tenantPool.lastUsed, dbName)
			}
		}
	}
}

// Helper function to get tenant DB from context
func GetTenantDBFromContext(c *gin.Context) (*gorm.DB, error) {
	tenantDB, exists := c.Get("tenant_db")
	if !exists {
		return nil, fmt.Errorf("tenant database not found in context")
	}

	db, ok := tenantDB.(*gorm.DB)
	if !ok {
		return nil, fmt.Errorf("invalid tenant database type in context")
	}

	return db, nil
}

// Helper function to get tenant info from context
func GetTenantInfoFromContext(c *gin.Context) (uuid.UUID, uuid.UUID, error) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		return uuid.Nil, uuid.Nil, fmt.Errorf("tenant_id not found in context")
	}

	orgID, exists := c.Get("org_id")
	if !exists {
		return uuid.Nil, uuid.Nil, fmt.Errorf("org_id not found in context")
	}

	tID, ok := tenantID.(uuid.UUID)
	if !ok {
		return uuid.Nil, uuid.Nil, fmt.Errorf("invalid tenant_id type in context")
	}

	oID, ok := orgID.(uuid.UUID)
	if !ok {
		return uuid.Nil, uuid.Nil, fmt.Errorf("invalid org_id type in context")
	}

	return tID, oID, nil
}
