// src/middlewares/tenant_middleware.go - FIXED VERSION
package middlewares

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"oath_oidc_configuration_manager/src/db"
	models "oath_oidc_configuration_manager/src/models/dto"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Updated Tenant model to match your database schema
type Tenant struct {
	ID           string     `json:"id" gorm:"primary_key"`
	TenantID     string     `json:"tenant_id"`
	TenantDB     string     `json:"tenant_db"`
	Email        string     `json:"email"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"password_hash"`
	Provider     string     `json:"provider" gorm:"default:local"`
	ProviderID   string     `json:"provider_id"`
	Name         string     `json:"name"`
	Avatar       string     `json:"avatar"`
	Source       string     `json:"source"`
	Status       string     `json:"status"`
	LastLogin    *time.Time `json:"last_login"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

func (Tenant) TableName() string {
	return "tenants"
}

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

		// Extract tenant_id and org_id as strings (not UUIDs)
		tenantIDStr, tenantExists := requestBody["tenant_id"].(string)
		orgIDStr, orgExists := requestBody["org_id"].(string)

		if !tenantExists || !orgExists {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "tenant_id and org_id are required in request body",
			})
			c.Abort()
			return
		}

		// Validate that they're not empty
		if tenantIDStr == "" || orgIDStr == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id and org_id cannot be empty"})
			c.Abort()
			return
		}

		// Get tenant database connection
		tenantDB, tenantDBName, err := GetTenantDatabase(tenantIDStr, orgIDStr)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to connect to tenant database",
				"message": err.Error(),
			})
			c.Abort()
			return
		}

		// Set tenant info in context
		c.Set("tenant_id", tenantIDStr)
		c.Set("org_id", orgIDStr)
		c.Set("tenant_db", tenantDB)
		c.Set("tenant_db_name", tenantDBName)

		// Continue to next handler
		c.Next()

		// Optional: Close tenant DB connection after request
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
func GetTenantDatabase(tenantID, orgID string) (*gorm.DB, string, error) {
	// First, get tenant info from main database
	tenant, err := getTenantInfo(tenantID, orgID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get tenant info: %w", err)
	}

	if tenant.TenantDB == "" {
		return nil, "", fmt.Errorf("tenant database name not found for tenant_id: %s", tenantID)
	}

	// Connect to tenant-specific database
	tenantDB, err := connectToTenantDB(tenant.TenantDB)
	if err != nil {
		return nil, "", fmt.Errorf("failed to connect to tenant database '%s': %w", tenant.TenantDB, err)
	}

	return tenantDB, tenant.TenantDB, nil
}

// getTenantInfo retrieves tenant information from main database using FIXED table name and fields
func getTenantInfo(tenantID, orgID string) (*Tenant, error) {
	var tenant Tenant

	// Query main database for tenant info using the CORRECT table name "tenants"
	// and using string comparison for tenant_id and id (org_id)
	err := db.DB.Where("tenant_id = ? AND id = ?", tenantID, orgID).First(&tenant).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("tenant not found for tenant_id: %s, org_id: %s", tenantID, orgID)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	return &tenant, nil
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

// Helper functions remain the same but updated for string IDs
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

func GetTenantInfoFromContext(c *gin.Context) (string, string, error) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		return "", "", fmt.Errorf("tenant_id not found in context")
	}

	orgID, exists := c.Get("org_id")
	if !exists {
		return "", "", fmt.Errorf("org_id not found in context")
	}

	tID, ok := tenantID.(string)
	if !ok {
		return "", "", fmt.Errorf("invalid tenant_id type in context")
	}

	oID, ok := orgID.(string)
	if !ok {
		return "", "", fmt.Errorf("invalid org_id type in context")
	}

	return tID, oID, nil
}
