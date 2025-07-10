// app/service.go (FIXED - Router setup bug)
package main

import (
	"log"
	"oath_oidc_configuration_manager/src/controller"
	"oath_oidc_configuration_manager/src/db"
	"oath_oidc_configuration_manager/src/middlewares"
	"oath_oidc_configuration_manager/src/repository"
	"oath_oidc_configuration_manager/src/service"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found: %v", err)
	}
	cfg := db.LoadConfig()

	// Initialize database
	db.InitDB(cfg)

	// Initialize dependencies
	authRepo := repository.NewAuthRepository()
	authService := service.NewAuthService(authRepo)
	authController := controller.NewAuthController(authService)

	// Initialize Gin router - FIXED: Use the configured router
	router := setupRouter()

	// Setup routes
	setupRoutes(router, authController)

	log.Printf("Starting authentication service on port %s", cfg.Port)
	router.Run(":" + cfg.Port) // FIXED: Run the configured router, not the original
}

// Setup Gin router - FIXED: Return *gin.Engine instead of creating new instance
func setupRouter() *gin.Engine {
	// Set Gin mode based on environment
	if getEnv("GIN_MODE", "debug") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Add middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// CORS middleware
	router.Use(corsMiddleware())

	// Multi-tenant database middleware - IMPORTANT: Add this
	router.Use(middlewares.TenantDBMiddleware())

	return router
}

// CORS middleware
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// Setup routes - ALL POST REQUESTS WITH MANDATORY TENANT/ORG IDS
func setupRoutes(router *gin.Engine, authController *controller.AuthController) {
	// API version group
	v1 := router.Group("/api/v1")

	// Health check endpoint
	v1.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "healthy",
			"service": "authn-service",
			"version": "1.0.0",
		})
	})

	// ===== CONFIGURATION MANAGEMENT ROUTES (ALL POST) =====
	configs := v1.Group("/configs")
	{
		// Basic CRUD operations - ALL POST with request body containing tenant_id and org_id
		configs.POST("/create", authController.CreateConfig)          // Create config
		configs.POST("/list", authController.GetConfigs)              // List configs with filters
		configs.POST("/list-active", authController.GetActiveConfigs) // Get active configs with filters
		configs.POST("/get-by-id", authController.GetConfigByID)      // Get config by ID
		configs.POST("/get-by-name", authController.GetConfigByName)  // Get config by name
		configs.POST("/update", authController.UpdateConfig)          // Update config
		configs.POST("/delete", authController.DeleteConfig)          // Delete config
	}

	// ===== SPECIFIC CONFIGURATION ENDPOINTS =====
	configure := v1.Group("/configure")
	{
		// Local Authentication Configuration
		configure.POST("/local-auth", authController.ConfigureLocalAuth)
		
		// OIDC Configuration
		configure.POST("/oidc", authController.ConfigureOIDC)

		// OAuth Server Configuration
		configure.POST("/oauth-server", authController.ConfigureOAuthServer)
		// WebAuthn MFA Configuration
		configure.POST("/webauthn-mfa", authController.ConfigureWebAuthnMFA)
		// SAML2 Configuration
		configure.POST("/saml2", authController.ConfigureSAML2)
		// Entra ID Sync Configuration
		configure.POST("/entra-sync", authController.ConfigureEntraSync)
		// Active Directory Sync Configuration
		configure.POST("/ad-sync", authController.ConfigureADSync)
	}

	// ===== CONFIGURATION MANAGEMENT ENDPOINTS =====
	manage := v1.Group("/manage")
	{
		// Configuration testing and validation
		manage.POST("/test-config", func(c *gin.Context) {
			// TODO: Implement configuration testing
			// Request body: {"id": "uuid", "org_id": "uuid", "tenant_id": "uuid"}
			c.JSON(200, gin.H{"message": "Configuration test endpoint - TODO"})
		})

		manage.POST("/validate-config", func(c *gin.Context) {
			// TODO: Implement configuration validation
			// Request body: {"id": "uuid", "org_id": "uuid", "tenant_id": "uuid"}
			c.JSON(200, gin.H{"message": "Configuration validation endpoint - TODO"})
		})

		// Configuration statistics
		manage.POST("/stats", func(c *gin.Context) {
			// TODO: Implement configuration statistics
			// Request body: {"org_id": "uuid", "tenant_id": "uuid"}
			c.JSON(200, gin.H{"message": "Configuration statistics endpoint - TODO"})
		})

		// Sync status for AD/Entra configurations
		manage.POST("/sync-status", func(c *gin.Context) {
			// TODO: Implement sync status
			// Request body: {"id": "uuid", "org_id": "uuid", "tenant_id": "uuid"}
			c.JSON(200, gin.H{"message": "Sync status endpoint - TODO"})
		})

		// Manual sync trigger
		manage.POST("/trigger-sync", func(c *gin.Context) {
			// TODO: Implement manual sync trigger
			// Request body: {"id": "uuid", "org_id": "uuid", "tenant_id": "uuid"}
			c.JSON(200, gin.H{"message": "Manual sync trigger endpoint - TODO"})
		})
	}

	// ===== AUDIT AND LOGGING ENDPOINTS =====
	audit := v1.Group("/audit")
	{
		// Configuration audit logs
		audit.POST("/config-logs", func(c *gin.Context) {
			// TODO: Implement audit log retrieval
			// Request body: {"config_id": "uuid", "org_id": "uuid", "tenant_id": "uuid", "page": 1, "limit": 10}
			c.JSON(200, gin.H{"message": "Audit logs endpoint - TODO"})
		})

		// All audit logs with filtering
		audit.POST("/all-logs", func(c *gin.Context) {
			// TODO: Implement comprehensive audit log retrieval
			// Request body: {"org_id": "uuid", "tenant_id": "uuid", "page": 1, "limit": 10, "filters": {...}}
			c.JSON(200, gin.H{"message": "All audit logs endpoint - TODO"})
		})
	}

	// ===== MULTI-TENANT QUERY ENDPOINTS =====
	query := v1.Group("/query")
	{
		// Get all configurations for a tenant
		query.POST("/tenant-configs", func(c *gin.Context) {
			// TODO: Get all configs for a specific tenant
			// Request body: {"tenant_id": "uuid", "org_id": "uuid"}
			c.JSON(200, gin.H{"message": "Tenant configurations endpoint - TODO"})
		})

		// Get configurations by type for tenant
		query.POST("/configs-by-type", func(c *gin.Context) {
			// TODO: Get configs by type for tenant
			// Request body: {"tenant_id": "uuid", "org_id": "uuid", "config_type": "local_auth"}
			c.JSON(200, gin.H{"message": "Configurations by type endpoint - TODO"})
		})

		// Check if tenant has specific configuration
		query.POST("/has-config", func(c *gin.Context) {
			// TODO: Check if tenant has specific config type
			// Request body: {"tenant_id": "uuid", "org_id": "uuid", "config_type": "oidc"}
			c.JSON(200, gin.H{"message": "Has configuration check endpoint - TODO"})
		})
	}
}

// Get environment variable with default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
