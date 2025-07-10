// src/repository/auth_repository.go (Updated for Multi-Tenant)
package repository

import (
	"fmt"

	"oath_oidc_configuration_manager/src/db"
	"oath_oidc_configuration_manager/src/models/dto"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type AuthRepository struct {
	masterDB *gorm.DB // Main database connection
}

func NewAuthRepository() *AuthRepository {
	return &AuthRepository{
		masterDB: db.DB, // Main database for tenant lookup
	}
}

// Helper method to get tenant database from Gin context
func (ar *AuthRepository) getTenantDB(c *gin.Context) (*gorm.DB, error) {
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

// ===== CONFIGURATION CRUD OPERATIONS WITH MULTI-TENANT SUPPORT =====

// CreateConfig creates a new authentication configuration in tenant database
func (ar *AuthRepository) CreateConfig(c *gin.Context, config *dto.OAuthOIDCConfiguration) (*dto.OAuthOIDCConfiguration, error) {
	// Get tenant database from context
	tenantDB, err := ar.getTenantDB(c)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant database: %w", err)
	}

	// Check if configuration with same name already exists for the tenant/org
	var existingConfig dto.OAuthOIDCConfiguration
	result := tenantDB.Where("name = ? AND org_id = ? AND tenant_id = ? AND deleted_at IS NULL",
		config.Name, config.OrgID, config.TenantID).First(&existingConfig)

	if result.Error == nil {
		return nil, fmt.Errorf("configuration with name '%s' already exists for this organization", config.Name)
	}

	if result.Error != gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("error checking existing configuration: %w", result.Error)
	}

	// Create the configuration in tenant database
	if err := tenantDB.Create(config).Error; err != nil {
		return nil, fmt.Errorf("failed to create configuration: %w", err)
	}

	return config, nil
}

// GetConfigs retrieves configurations from tenant database with mandatory tenant/org filtering and pagination
func (ar *AuthRepository) GetConfigs(c *gin.Context, req *dto.GetConfigsRequest) ([]*dto.OAuthOIDCConfiguration, int64, error) {
	var configs []*dto.OAuthOIDCConfiguration
	var total int64

	// Get tenant database from context
	tenantDB, err := ar.getTenantDB(c)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get tenant database: %w", err)
	}

	// Build query with mandatory tenant/org filtering
	query := tenantDB.Model(&dto.OAuthOIDCConfiguration{}).
		Where("tenant_id = ? AND org_id = ?", req.TenantID, req.OrgID)

	// Apply additional filters
	if req.ConfigType != "" {
		query = query.Where("config_type = ?", req.ConfigType)
	}

	if req.ActiveOnly {
		query = query.Where("is_active = ?", true)
	}

	// Get total count
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count configurations: %w", err)
	}

	// Apply pagination and retrieve records
	offset := (req.Page - 1) * req.Limit
	if err := query.Order("created_at DESC").
		Offset(offset).
		Limit(req.Limit).
		Find(&configs).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to retrieve configurations: %w", err)
	}

	return configs, total, nil
}

// GetConfigByID retrieves a configuration by ID from tenant database with tenant/org validation
func (ar *AuthRepository) GetConfigByID(c *gin.Context, req *dto.GetConfigByIDRequest) (*dto.OAuthOIDCConfiguration, error) {
	var config dto.OAuthOIDCConfiguration

	// Get tenant database from context
	tenantDB, err := ar.getTenantDB(c)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant database: %w", err)
	}

	if err := tenantDB.Where("id = ? AND tenant_id = ? AND org_id = ?",
		req.ID, req.TenantID, req.OrgID).First(&config).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("configuration not found")
		}
		return nil, fmt.Errorf("failed to retrieve configuration: %w", err)
	}

	return &config, nil
}

// GetConfigByName retrieves a configuration by name from tenant database with tenant/org validation
func (ar *AuthRepository) GetConfigByName(c *gin.Context, req *dto.GetConfigByNameRequest) (*dto.OAuthOIDCConfiguration, error) {
	var config dto.OAuthOIDCConfiguration

	// Get tenant database from context
	tenantDB, err := ar.getTenantDB(c)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant database: %w", err)
	}

	if err := tenantDB.Where("name = ? AND tenant_id = ? AND org_id = ?",
		req.Name, req.TenantID, req.OrgID).First(&config).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("configuration not found")
		}
		return nil, fmt.Errorf("failed to retrieve configuration: %w", err)
	}

	return &config, nil
}

// UpdateConfig updates an existing configuration in tenant database with tenant/org validation
func (ar *AuthRepository) UpdateConfig(c *gin.Context, req *dto.UpdateConfigRequest) (*dto.OAuthOIDCConfiguration, error) {
	var config dto.OAuthOIDCConfiguration

	// Get tenant database from context
	tenantDB, err := ar.getTenantDB(c)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant database: %w", err)
	}

	// First, check if the configuration exists with tenant/org validation
	if err := tenantDB.Where("id = ? AND tenant_id = ? AND org_id = ?",
		req.ID, req.TenantID, req.OrgID).First(&config).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("configuration not found")
		}
		return nil, fmt.Errorf("failed to retrieve configuration: %w", err)
	}

	// Prepare update data
	updateData := make(map[string]interface{})

	if req.Name != nil {
		// Check if new name conflicts with existing configurations in same tenant/org
		var existingConfig dto.OAuthOIDCConfiguration
		result := tenantDB.Where("name = ? AND org_id = ? AND tenant_id = ? AND id != ? AND deleted_at IS NULL",
			*req.Name, req.OrgID, req.TenantID, req.ID).First(&existingConfig)

		if result.Error == nil {
			return nil, fmt.Errorf("configuration with name '%s' already exists for this organization", *req.Name)
		}

		if result.Error != gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("error checking existing configuration: %w", result.Error)
		}

		updateData["name"] = *req.Name
	}

	if req.ConfigFiles != nil {
		updateData["config_files"] = dto.JSONMap(req.ConfigFiles)
	}

	if req.IsActive != nil {
		updateData["is_active"] = *req.IsActive
	}

	if req.UpdatedBy != "" {
		updateData["updated_by"] = req.UpdatedBy
	}

	// Perform update
	if err := tenantDB.Model(&config).Updates(updateData).Error; err != nil {
		return nil, fmt.Errorf("failed to update configuration: %w", err)
	}

	// Reload the updated configuration
	if err := tenantDB.Where("id = ? AND tenant_id = ? AND org_id = ?",
		req.ID, req.TenantID, req.OrgID).First(&config).Error; err != nil {
		return nil, fmt.Errorf("failed to reload updated configuration: %w", err)
	}

	return &config, nil
}

// DeleteConfig soft deletes a configuration from tenant database with tenant/org validation
func (ar *AuthRepository) DeleteConfig(c *gin.Context, req *dto.DeleteConfigRequest) error {
	// Get tenant database from context
	tenantDB, err := ar.getTenantDB(c)
	if err != nil {
		return fmt.Errorf("failed to get tenant database: %w", err)
	}

	result := tenantDB.Where("id = ? AND tenant_id = ? AND org_id = ?",
		req.ID, req.TenantID, req.OrgID).Delete(&dto.OAuthOIDCConfiguration{})

	if result.Error != nil {
		return fmt.Errorf("failed to delete configuration: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("configuration not found")
	}

	return nil
}

// ===== MULTI-TENANT SPECIFIC HELPERS =====

// GetTenantConfigs retrieves all configurations for a specific tenant from tenant database
func (ar *AuthRepository) GetTenantConfigs(c *gin.Context, req *dto.GetTenantConfigsRequest) ([]*dto.OAuthOIDCConfiguration, int64, error) {
	var configs []*dto.OAuthOIDCConfiguration
	var total int64

	// Get tenant database from context
	tenantDB, err := ar.getTenantDB(c)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get tenant database: %w", err)
	}

	// Build query with tenant/org filtering
	query := tenantDB.Model(&dto.OAuthOIDCConfiguration{}).
		Where("tenant_id = ? AND org_id = ?", req.TenantID, req.OrgID)

	// Apply filters if provided
	if req.ActiveOnly {
		query = query.Where("is_active = ?", true)
	}

	// Get total count
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count tenant configurations: %w", err)
	}

	// Apply pagination if specified
	if req.Page > 0 && req.Limit > 0 {
		offset := (req.Page - 1) * req.Limit
		query = query.Offset(offset).Limit(req.Limit)
	}

	// Retrieve records
	if err := query.Order("config_type ASC, created_at DESC").Find(&configs).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to retrieve tenant configurations: %w", err)
	}

	return configs, total, nil
}

// GetConfigsByType retrieves configurations by type for a tenant from tenant database
func (ar *AuthRepository) GetConfigsByType(c *gin.Context, req *dto.GetConfigsByTypeRequest) ([]*dto.OAuthOIDCConfiguration, error) {
	var configs []*dto.OAuthOIDCConfiguration

	// Get tenant database from context
	tenantDB, err := ar.getTenantDB(c)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant database: %w", err)
	}

	query := tenantDB.Where("tenant_id = ? AND org_id = ? AND config_type = ?",
		req.TenantID, req.OrgID, req.ConfigType)

	if req.ActiveOnly {
		query = query.Where("is_active = ?", true)
	}

	if err := query.Order("created_at DESC").Find(&configs).Error; err != nil {
		return nil, fmt.Errorf("failed to retrieve configurations by type: %w", err)
	}

	return configs, nil
}

// CheckTenantHasConfig checks if tenant has a specific configuration type in tenant database
func (ar *AuthRepository) CheckTenantHasConfig(c *gin.Context, req *dto.CheckTenantConfigRequest) (*dto.TenantConfigCheckResponse, error) {
	var count int64

	// Get tenant database from context
	tenantDB, err := ar.getTenantDB(c)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant database: %w", err)
	}

	query := tenantDB.Model(&dto.OAuthOIDCConfiguration{}).
		Where("tenant_id = ? AND org_id = ? AND config_type = ?",
			req.TenantID, req.OrgID, req.ConfigType)

	if req.ActiveOnly {
		query = query.Where("is_active = ?", true)
	}

	if err := query.Count(&count).Error; err != nil {
		return nil, fmt.Errorf("failed to check tenant configuration: %w", err)
	}

	response := &dto.TenantConfigCheckResponse{
		HasConfig:  count > 0,
		Count:      count,
		ConfigType: req.ConfigType,
		TenantID:   req.TenantID,
		OrgID:      req.OrgID,
		ActiveOnly: req.ActiveOnly,
	}

	return response, nil
}

// GetActiveConfigByType retrieves active configuration by type for a tenant from tenant database
func (ar *AuthRepository) GetActiveConfigByType(c *gin.Context, tenantID, orgID uuid.UUID, configType string) (*dto.OAuthOIDCConfiguration, error) {
	var config dto.OAuthOIDCConfiguration

	// Get tenant database from context
	tenantDB, err := ar.getTenantDB(c)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant database: %w", err)
	}

	if err := tenantDB.Where("tenant_id = ? AND org_id = ? AND config_type = ? AND is_active = ?",
		tenantID, orgID, configType, true).First(&config).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("no active %s configuration found for tenant", configType)
		}
		return nil, fmt.Errorf("failed to retrieve %s configuration: %w", configType, err)
	}

	return &config, nil
}

// DeactivateOtherConfigs deactivates other configurations of the same type when a new one is activated
func (ar *AuthRepository) DeactivateOtherConfigs(c *gin.Context, tenantID, orgID uuid.UUID, configType string, excludeID uuid.UUID) error {
	// Get tenant database from context
	tenantDB, err := ar.getTenantDB(c)
	if err != nil {
		return fmt.Errorf("failed to get tenant database: %w", err)
	}

	result := tenantDB.Model(&dto.OAuthOIDCConfiguration{}).
		Where("tenant_id = ? AND org_id = ? AND config_type = ? AND id != ? AND is_active = ?",
			tenantID, orgID, configType, excludeID, true).
		Update("is_active", false)

	if result.Error != nil {
		return fmt.Errorf("failed to deactivate other %s configurations: %w", configType, result.Error)
	}

	return nil
}

// ===== CONFIGURATION STATISTICS AND MONITORING =====

// GetConfigStats returns statistics about configurations for a tenant from tenant database
func (ar *AuthRepository) GetConfigStats(c *gin.Context, req *dto.GetConfigStatsRequest) (*dto.ConfigStatsResponse, error) {
	stats := &dto.ConfigStatsResponse{
		TenantID: req.TenantID,
		OrgID:    req.OrgID,
		ByType:   make(map[string]int64),
	}

	// Get tenant database from context
	tenantDB, err := ar.getTenantDB(c)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant database: %w", err)
	}

	// Total configurations
	if err := tenantDB.Model(&dto.OAuthOIDCConfiguration{}).
		Where("tenant_id = ? AND org_id = ?", req.TenantID, req.OrgID).
		Count(&stats.Total).Error; err != nil {
		return nil, fmt.Errorf("failed to count total configurations: %w", err)
	}

	// Active configurations
	if err := tenantDB.Model(&dto.OAuthOIDCConfiguration{}).
		Where("tenant_id = ? AND org_id = ? AND is_active = ?", req.TenantID, req.OrgID, true).
		Count(&stats.Active).Error; err != nil {
		return nil, fmt.Errorf("failed to count active configurations: %w", err)
	}

	// Inactive configurations
	stats.Inactive = stats.Total - stats.Active

	// Configurations by type
	rows, err := tenantDB.Model(&dto.OAuthOIDCConfiguration{}).
		Select("config_type, COUNT(*) as count").
		Where("tenant_id = ? AND org_id = ?", req.TenantID, req.OrgID).
		Group("config_type").
		Rows()
	if err != nil {
		return nil, fmt.Errorf("failed to get configuration counts by type: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var configType string
		var count int64
		if err := rows.Scan(&configType, &count); err != nil {
			return nil, fmt.Errorf("failed to scan configuration type stats: %w", err)
		}
		stats.ByType[configType] = count
	}

	return stats, nil
}

// ===== HEALTH CHECK AND UTILITIES =====

// HealthCheck performs a health check on both master and tenant databases
func (ar *AuthRepository) HealthCheck(c *gin.Context) error {
	// Check master database
	var result int
	if err := ar.masterDB.Raw("SELECT 1").Scan(&result).Error; err != nil {
		return fmt.Errorf("master database health check failed: %w", err)
	}

	// Check tenant database if available in context
	if tenantDB, err := ar.getTenantDB(c); err == nil {
		if err := tenantDB.Raw("SELECT 1").Scan(&result).Error; err != nil {
			return fmt.Errorf("tenant database health check failed: %w", err)
		}
	}

	return nil
}

// BatchUpdateConfigs updates multiple configurations in a transaction in tenant database
func (ar *AuthRepository) BatchUpdateConfigs(c *gin.Context, tenantID, orgID uuid.UUID, updates []dto.BatchConfigUpdate) error {
	// Get tenant database from context
	tenantDB, err := ar.getTenantDB(c)
	if err != nil {
		return fmt.Errorf("failed to get tenant database: %w", err)
	}

	return tenantDB.Transaction(func(tx *gorm.DB) error {
		for _, update := range updates {
			result := tx.Model(&dto.OAuthOIDCConfiguration{}).
				Where("id = ? AND tenant_id = ? AND org_id = ?", update.ID, tenantID, orgID).
				Updates(update.UpdateData)

			if result.Error != nil {
				return fmt.Errorf("failed to update configuration %s: %w", update.ID, result.Error)
			}

			if result.RowsAffected == 0 {
				return fmt.Errorf("configuration %s not found", update.ID)
			}
		}
		return nil
	})
}

// CleanupInactiveConfigs removes configurations that have been inactive for a specified period from tenant database
func (ar *AuthRepository) CleanupInactiveConfigs(c *gin.Context, tenantID, orgID uuid.UUID, daysInactive int) (int64, error) {
	// Get tenant database from context
	tenantDB, err := ar.getTenantDB(c)
	if err != nil {
		return 0, fmt.Errorf("failed to get tenant database: %w", err)
	}

	result := tenantDB.Where("tenant_id = ? AND org_id = ? AND is_active = ? AND updated_at < NOW() - INTERVAL ? DAY",
		tenantID, orgID, false, daysInactive).Delete(&dto.OAuthOIDCConfiguration{})

	if result.Error != nil {
		return 0, fmt.Errorf("failed to cleanup inactive configurations: %w", result.Error)
	}

	return result.RowsAffected, nil
}

// ===== VALIDATION HELPERS =====

// ValidateConfigConstraints validates configuration-specific constraints in tenant database
func (ar *AuthRepository) ValidateConfigConstraints(c *gin.Context, config *dto.OAuthOIDCConfiguration) error {
	switch config.ConfigType {
	case "local_auth":
		return ar.validateLocalAuthConstraints(c, config)
	case "oidc":
		return ar.validateOIDCConstraints(c, config)
	case "oauth_server":
		return ar.validateOAuthServerConstraints(c, config)
	case "webauthn_mfa":
		return ar.validateWebAuthnMFAConstraints(c, config)
	case "saml2":
		return ar.validateSAML2Constraints(c, config)
	case "entra_sync":
		return ar.validateEntraSyncConstraints(c, config)
	case "ad_sync":
		return ar.validateADSyncConstraints(c, config)
	default:
		return fmt.Errorf("unknown configuration type: %s", config.ConfigType)
	}
}

func (ar *AuthRepository) validateLocalAuthConstraints(c *gin.Context, config *dto.OAuthOIDCConfiguration) error {
	// Get tenant database from context
	tenantDB, err := ar.getTenantDB(c)
	if err != nil {
		return fmt.Errorf("failed to get tenant database: %w", err)
	}

	// Check if there's already an active local auth configuration for the tenant
	var existingConfig dto.OAuthOIDCConfiguration
	result := tenantDB.Where("tenant_id = ? AND org_id = ? AND config_type = ? AND is_active = ? AND id != ?",
		config.TenantID, config.OrgID, "local_auth", true, config.ID).First(&existingConfig)

	if result.Error == nil && config.IsActive {
		return fmt.Errorf("only one active local authentication configuration is allowed per tenant")
	}

	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		return fmt.Errorf("error validating local auth constraints: %w", result.Error)
	}

	return nil
}

func (ar *AuthRepository) validateOIDCConstraints(c *gin.Context, config *dto.OAuthOIDCConfiguration) error {
	// Extract OIDC config from JSON
	oidcConfigData, exists := config.ConfigFiles["oidc_config"]
	if !exists {
		return fmt.Errorf("OIDC configuration data is missing")
	}

	// Additional OIDC-specific validation can be added here
	_ = oidcConfigData // Placeholder for future validation logic

	return nil
}

func (ar *AuthRepository) validateOAuthServerConstraints(c *gin.Context, config *dto.OAuthOIDCConfiguration) error {
	// Extract OAuth server config from JSON
	oauthConfigData, exists := config.ConfigFiles["oauth_server_config"]
	if !exists {
		return fmt.Errorf("OAuth server configuration data is missing")
	}

	// Additional OAuth server-specific validation can be added here
	_ = oauthConfigData // Placeholder for future validation logic

	return nil
}

func (ar *AuthRepository) validateWebAuthnMFAConstraints(c *gin.Context, config *dto.OAuthOIDCConfiguration) error {
	// Extract WebAuthn MFA config from JSON
	webauthnConfigData, exists := config.ConfigFiles["webauthn_mfa_config"]
	if !exists {
		return fmt.Errorf("WebAuthn MFA configuration data is missing")
	}

	// Additional WebAuthn MFA-specific validation can be added here
	_ = webauthnConfigData // Placeholder for future validation logic

	return nil
}

func (ar *AuthRepository) validateSAML2Constraints(c *gin.Context, config *dto.OAuthOIDCConfiguration) error {
	// Extract SAML2 config from JSON
	saml2ConfigData, exists := config.ConfigFiles["saml2_config"]
	if !exists {
		return fmt.Errorf("SAML2 configuration data is missing")
	}

	// Additional SAML2-specific validation can be added here
	_ = saml2ConfigData // Placeholder for future validation logic

	return nil
}

func (ar *AuthRepository) validateEntraSyncConstraints(c *gin.Context, config *dto.OAuthOIDCConfiguration) error {
	// Extract Entra sync config from JSON
	entraSyncConfigData, exists := config.ConfigFiles["entra_sync_config"]
	if !exists {
		return fmt.Errorf("Entra sync configuration data is missing")
	}

	// Additional Entra sync-specific validation can be added here
	_ = entraSyncConfigData // Placeholder for future validation logic

	return nil
}

func (ar *AuthRepository) validateADSyncConstraints(c *gin.Context, config *dto.OAuthOIDCConfiguration) error {
	// Extract AD sync config from JSON
	adSyncConfigData, exists := config.ConfigFiles["ad_sync_config"]
	if !exists {
		return fmt.Errorf("AD sync configuration data is missing")
	}

	// Additional AD sync-specific validation can be added here
	_ = adSyncConfigData // Placeholder for future validation logic

	return nil
}
