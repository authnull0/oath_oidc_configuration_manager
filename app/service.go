// OIDC Configuration Manager Service - Updated for OAuth Integration
package main

import (
	"log"
	"oath_oidc_configuration_manager/src/controller"
	"oath_oidc_configuration_manager/src/db"
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

	// Initialize Gin router
	router := setupRouter()

	// Setup routes
	setupRoutes(router, authController)

	log.Printf("Starting OIDC Configuration Manager service on port %s", cfg.Port)
	router.Run(":" + cfg.Port)
}

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

	return router
}

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
	v1 := router.Group("/oocmgr")

	// Health check endpoint
	v1.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "healthy",
			"service": "oidc-config-manager",
			"version": "2.0.0",
		})
	})

	// ===== MAIN CONFIGURATION ENDPOINT =====
	// Single API call to configure everything
	v1.POST("/configure-complete-oidc", authController.CompleteOIDCConfiguration)

	// ===== TENANT MANAGEMENT ENDPOINTS =====
	tenant := v1.Group("/tenant")
	{
		// Create base Hydra client for tenant (Step 1)
		tenant.POST("/create-base-client", authController.CreateBaseTenantClient)

		// Check if tenant exists
		tenant.POST("/check-exists", authController.CheckTenantExists)

		// List all tenants
		tenant.POST("/list-all", authController.ListAllTenants)

		// Delete complete tenant configuration
		tenant.POST("/delete-complete", authController.DeleteCompleteTenantConfig)

		// Update complete tenant configuration
		tenant.POST("/update-complete", authController.UpdateCompleteTenantConfig)

		// Get login page data for tenant
		tenant.POST("/login-page-data", authController.GetTenantLoginPageData)
	}

	// ===== OIDC MANAGEMENT ENDPOINTS =====
	oidc := v1.Group("/oidc")
	{
		// Add OIDC provider to existing tenant (Step 2)
		oidc.POST("/add-provider", authController.AddOIDCProviderToTenant)

		// Get tenant's complete OIDC configuration
		oidc.POST("/get-config", authController.GetTenantOIDCConfig)

		// Get specific provider configuration
		oidc.POST("/get-provider", authController.GetOIDCProvider)

		// Update specific provider
		oidc.POST("/update-provider", authController.UpdateOIDCProvider)

		// Delete specific provider
		oidc.POST("/delete-provider", authController.DeleteOIDCProvider)

		// Provider templates
		oidc.POST("/templates", authController.GetProviderTemplates)

		// Validation
		oidc.POST("/validate", authController.ValidateOIDCConfig)
	}
	hydraClients := v1.Group("/hydra-clients")
	{
		// List all Hydra client mappings
		hydraClients.POST("/list", authController.ListTenantHydraClients)

		// Get specific tenant's Hydra clients
		hydraClients.POST("/get-by-tenant", authController.GetTenantHydraClients)

		// Sync Hydra clients with database
		hydraClients.POST("/sync", authController.SyncHydraClients)
	}
	// ===== TESTING ENDPOINTS =====
	test := v1.Group("/test")
	{
		// Test OIDC flow
		test.POST("/oidc-flow", authController.TestOIDCFlow)
	}

	// ===== MONITORING ENDPOINTS =====
	stats := v1.Group("/stats")
	{
		// Get tenant statistics
		stats.POST("/tenant", authController.GetTenantStats)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
