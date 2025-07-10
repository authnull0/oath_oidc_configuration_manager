// src/service/auth_service.go (Updated for Multi-Tenant)
package service

import (
	"fmt"

	"oath_oidc_configuration_manager/src/models/dto"
	"oath_oidc_configuration_manager/src/repository"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AuthService struct {
	authRepo *repository.AuthRepository
}

func NewAuthService(authRepo *repository.AuthRepository) *AuthService {
	return &AuthService{
		authRepo: authRepo,
	}
}

// ===== CONFIGURATION CRUD OPERATIONS =====

// CreateConfig creates a new authentication configuration in tenant database
func (as *AuthService) CreateConfig(c *gin.Context, req *dto.CreateConfigRequest) (*dto.ConfigResponse, error) {
	// Validate request
	if err := as.validateCreateConfigRequest(req); err != nil {
		return nil, fmt.Errorf("validation error: %w", err)
	}

	// Convert request to entity
	config := &dto.OAuthOIDCConfiguration{
		ID:          uuid.New(),
		Name:        req.Name,
		OrgID:       req.OrgID,
		TenantID:    req.TenantID,
		ConfigType:  req.ConfigType,
		ConfigFiles: dto.JSONMap(req.ConfigFiles),
		IsActive:    req.IsActive,
		CreatedBy:   req.CreatedBy,
		UpdatedBy:   req.CreatedBy,
	}

	// Save to tenant database via repository
	createdConfig, err := as.authRepo.CreateConfig(c, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create configuration: %w", err)
	}

	return createdConfig.ToResponse(), nil
}

// GetConfigs retrieves configurations from tenant database with optional filtering
func (as *AuthService) GetConfigs(c *gin.Context, req *dto.GetConfigsRequest) (*dto.ConfigListResponse, error) {
	// Validate pagination
	if req.Page < 1 {
		req.Page = 1
	}
	if req.Limit < 1 || req.Limit > 100 {
		req.Limit = 10
	}

	configs, total, err := as.authRepo.GetConfigs(c, req)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve configurations: %w", err)
	}

	// Convert to response DTOs
	var configResponses []*dto.ConfigResponse
	for _, config := range configs {
		configResponses = append(configResponses, config.ToResponse())
	}

	totalPages := (total + int64(req.Limit) - 1) / int64(req.Limit)

	return &dto.ConfigListResponse{
		Configs:    configResponses,
		Page:       req.Page,
		Limit:      req.Limit,
		Total:      total,
		TotalPages: totalPages,
	}, nil
}

// GetConfigByID retrieves a configuration by ID from tenant database
func (as *AuthService) GetConfigByID(c *gin.Context, req *dto.GetConfigByIDRequest) (*dto.ConfigResponse, error) {
	config, err := as.authRepo.GetConfigByID(c, req)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve configuration: %w", err)
	}

	return config.ToResponse(), nil
}

// GetConfigByName retrieves a configuration by name from tenant database
func (as *AuthService) GetConfigByName(c *gin.Context, req *dto.GetConfigByNameRequest) (*dto.ConfigResponse, error) {
	config, err := as.authRepo.GetConfigByName(c, req)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve configuration: %w", err)
	}

	return config.ToResponse(), nil
}

// UpdateConfig updates an existing configuration in tenant database
func (as *AuthService) UpdateConfig(c *gin.Context, req *dto.UpdateConfigRequest) (*dto.ConfigResponse, error) {
	// Validate request
	if err := as.validateUpdateConfigRequest(req); err != nil {
		return nil, fmt.Errorf("validation error: %w", err)
	}

	updatedConfig, err := as.authRepo.UpdateConfig(c, req)
	if err != nil {
		return nil, fmt.Errorf("failed to update configuration: %w", err)
	}

	return updatedConfig.ToResponse(), nil
}

// DeleteConfig deletes a configuration from tenant database
func (as *AuthService) DeleteConfig(c *gin.Context, req *dto.DeleteConfigRequest) error {
	err := as.authRepo.DeleteConfig(c, req)
	if err != nil {
		return fmt.Errorf("failed to delete configuration: %w", err)
	}

	return nil
}

// ===== SPECIFIC CONFIGURATION METHODS =====

// ConfigureLocalAuth configures local authentication in tenant database
func (as *AuthService) ConfigureLocalAuth(c *gin.Context, req *dto.ConfigureLocalAuthRequest) (*dto.ConfigResponse, error) {
	// Validate local auth specific requirements
	if err := as.validateLocalAuthConfig(&req.LocalAuthConfig); err != nil {
		return nil, fmt.Errorf("local auth validation error: %w", err)
	}

	// Convert to generic config request
	configReq := &dto.CreateConfigRequest{
		Name:       req.Name,
		OrgID:      req.OrgID,
		TenantID:   req.TenantID,
		ConfigType: "local_auth",
		ConfigFiles: map[string]interface{}{
			"local_auth_config": req.LocalAuthConfig,
		},
		IsActive:  req.IsActive,
		CreatedBy: req.CreatedBy,
	}

	return as.CreateConfig(c, configReq)
}

// ConfigureOIDC configures OIDC in tenant database
func (as *AuthService) ConfigureOIDC(c *gin.Context, req *dto.ConfigureOIDCRequest) (*dto.ConfigResponse, error) {
	// Validate OIDC specific requirements
	if err := as.validateOIDCConfig(&req.OIDCConfig); err != nil {
		return nil, fmt.Errorf("OIDC validation error: %w", err)
	}

	configReq := &dto.CreateConfigRequest{
		Name:       req.Name,
		OrgID:      req.OrgID,
		TenantID:   req.TenantID,
		ConfigType: "oidc",
		ConfigFiles: map[string]interface{}{
			"oidc_config": req.OIDCConfig,
		},
		IsActive:  req.IsActive,
		CreatedBy: req.CreatedBy,
	}

	return as.CreateConfig(c, configReq)
}

// ConfigureOAuthServer configures OAuth Server in tenant database
func (as *AuthService) ConfigureOAuthServer(c *gin.Context, req *dto.ConfigureOAuthServerRequest) (*dto.ConfigResponse, error) {
	if err := as.validateOAuthServerConfig(&req.OAuthServerConfig); err != nil {
		return nil, fmt.Errorf("OAuth server validation error: %w", err)
	}

	configReq := &dto.CreateConfigRequest{
		Name:       req.Name,
		OrgID:      req.OrgID,
		TenantID:   req.TenantID,
		ConfigType: "oauth_server",
		ConfigFiles: map[string]interface{}{
			"oauth_server_config": req.OAuthServerConfig,
		},
		IsActive:  req.IsActive,
		CreatedBy: req.CreatedBy,
	}

	return as.CreateConfig(c, configReq)
}

// ConfigureWebAuthnMFA configures WebAuthn MFA in tenant database
func (as *AuthService) ConfigureWebAuthnMFA(c *gin.Context, req *dto.ConfigureWebAuthnMFARequest) (*dto.ConfigResponse, error) {
	if err := as.validateWebAuthnMFAConfig(&req.WebAuthnMFAConfig); err != nil {
		return nil, fmt.Errorf("WebAuthn MFA validation error: %w", err)
	}

	configReq := &dto.CreateConfigRequest{
		Name:       req.Name,
		OrgID:      req.OrgID,
		TenantID:   req.TenantID,
		ConfigType: "webauthn_mfa",
		ConfigFiles: map[string]interface{}{
			"webauthn_mfa_config": req.WebAuthnMFAConfig,
		},
		IsActive:  req.IsActive,
		CreatedBy: req.CreatedBy,
	}

	return as.CreateConfig(c, configReq)
}

// ConfigureSAML2 configures SAML2 in tenant database
func (as *AuthService) ConfigureSAML2(c *gin.Context, req *dto.ConfigureSAML2Request) (*dto.ConfigResponse, error) {
	if err := as.validateSAML2Config(&req.SAML2Config); err != nil {
		return nil, fmt.Errorf("SAML2 validation error: %w", err)
	}

	configReq := &dto.CreateConfigRequest{
		Name:       req.Name,
		OrgID:      req.OrgID,
		TenantID:   req.TenantID,
		ConfigType: "saml2",
		ConfigFiles: map[string]interface{}{
			"saml2_config": req.SAML2Config,
		},
		IsActive:  req.IsActive,
		CreatedBy: req.CreatedBy,
	}

	return as.CreateConfig(c, configReq)
}

// ConfigureEntraSync configures Entra ID sync in tenant database
func (as *AuthService) ConfigureEntraSync(c *gin.Context, req *dto.ConfigureEntraSyncRequest) (*dto.ConfigResponse, error) {
	if err := as.validateEntraSyncConfig(&req.EntraSyncConfig); err != nil {
		return nil, fmt.Errorf("Entra sync validation error: %w", err)
	}

	configReq := &dto.CreateConfigRequest{
		Name:       req.Name,
		OrgID:      req.OrgID,
		TenantID:   req.TenantID,
		ConfigType: "entra_sync",
		ConfigFiles: map[string]interface{}{
			"entra_sync_config": req.EntraSyncConfig,
		},
		IsActive:  req.IsActive,
		CreatedBy: req.CreatedBy,
	}

	return as.CreateConfig(c, configReq)
}

// ConfigureADSync configures Active Directory sync in tenant database
func (as *AuthService) ConfigureADSync(c *gin.Context, req *dto.ConfigureADSyncRequest) (*dto.ConfigResponse, error) {
	if err := as.validateADSyncConfig(&req.ADSyncConfig); err != nil {
		return nil, fmt.Errorf("AD sync validation error: %w", err)
	}

	configReq := &dto.CreateConfigRequest{
		Name:       req.Name,
		OrgID:      req.OrgID,
		TenantID:   req.TenantID,
		ConfigType: "ad_sync",
		ConfigFiles: map[string]interface{}{
			"ad_sync_config": req.ADSyncConfig,
		},
		IsActive:  req.IsActive,
		CreatedBy: req.CreatedBy,
	}

	return as.CreateConfig(c, configReq)
}

// ===== MULTI-TENANT SPECIFIC METHODS =====

// GetTenantConfigs retrieves all configurations for a specific tenant from tenant database
func (as *AuthService) GetTenantConfigs(c *gin.Context, req *dto.GetTenantConfigsRequest) (*dto.TenantConfigListResponse, error) {
	// Set default pagination
	if req.Page < 1 {
		req.Page = 1
	}
	if req.Limit < 1 || req.Limit > 100 {
		req.Limit = 50 // Higher default for tenant queries
	}

	configs, total, err := as.authRepo.GetTenantConfigs(c, req)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve tenant configurations: %w", err)
	}

	// Convert to response DTOs
	var configResponses []*dto.ConfigResponse
	for _, config := range configs {
		configResponses = append(configResponses, config.ToResponse())
	}

	totalPages := (total + int64(req.Limit) - 1) / int64(req.Limit)

	return &dto.TenantConfigListResponse{
		Configs:    configResponses,
		TenantID:   req.TenantID,
		OrgID:      req.OrgID,
		Page:       req.Page,
		Limit:      req.Limit,
		Total:      total,
		TotalPages: totalPages,
		ActiveOnly: req.ActiveOnly,
	}, nil
}

// GetConfigsByType retrieves configurations by type for a tenant from tenant database
func (as *AuthService) GetConfigsByType(c *gin.Context, req *dto.GetConfigsByTypeRequest) (*dto.ConfigsByTypeResponse, error) {
	configs, err := as.authRepo.GetConfigsByType(c, req)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve configurations by type: %w", err)
	}

	// Convert to response DTOs
	var configResponses []*dto.ConfigResponse
	for _, config := range configs {
		configResponses = append(configResponses, config.ToResponse())
	}

	return &dto.ConfigsByTypeResponse{
		Configs:    configResponses,
		ConfigType: req.ConfigType,
		TenantID:   req.TenantID,
		OrgID:      req.OrgID,
		Count:      int64(len(configResponses)),
		ActiveOnly: req.ActiveOnly,
	}, nil
}

// CheckTenantHasConfig checks if tenant has a specific configuration type in tenant database
func (as *AuthService) CheckTenantHasConfig(c *gin.Context, req *dto.CheckTenantConfigRequest) (*dto.TenantConfigCheckResponse, error) {
	response, err := as.authRepo.CheckTenantHasConfig(c, req)
	if err != nil {
		return nil, fmt.Errorf("failed to check tenant configuration: %w", err)
	}

	return response, nil
}

// GetConfigStats retrieves configuration statistics for a tenant from tenant database
func (as *AuthService) GetConfigStats(c *gin.Context, req *dto.GetConfigStatsRequest) (*dto.ConfigStatsResponse, error) {
	stats, err := as.authRepo.GetConfigStats(c, req)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve configuration statistics: %w", err)
	}

	return stats, nil
}

// ===== BUSINESS LOGIC METHODS =====

// GetActiveConfigForTenant retrieves the active configuration of a specific type for a tenant from tenant database
func (as *AuthService) GetActiveConfigForTenant(c *gin.Context, tenantID, orgID uuid.UUID, configType string) (*dto.ConfigResponse, error) {
	config, err := as.authRepo.GetActiveConfigByType(c, tenantID, orgID, configType)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve active %s configuration: %w", configType, err)
	}

	return config.ToResponse(), nil
}

// ActivateConfig activates a configuration and deactivates others of the same type in tenant database
func (as *AuthService) ActivateConfig(c *gin.Context, req *dto.ActivateConfigRequest) (*dto.ConfigResponse, error) {
	// First, get the configuration to be activated
	getReq := &dto.GetConfigByIDRequest{
		ID:       req.ID,
		TenantID: req.TenantID,
		OrgID:    req.OrgID,
	}

	config, err := as.authRepo.GetConfigByID(c, getReq)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve configuration: %w", err)
	}

	// Deactivate other configurations of the same type
	if err := as.authRepo.DeactivateOtherConfigs(c, req.TenantID, req.OrgID, config.ConfigType, req.ID); err != nil {
		return nil, fmt.Errorf("failed to deactivate other configurations: %w", err)
	}

	// Activate the requested configuration
	updateReq := &dto.UpdateConfigRequest{
		ID:        req.ID,
		TenantID:  req.TenantID,
		OrgID:     req.OrgID,
		IsActive:  &[]bool{true}[0], // Helper to get pointer to true
		UpdatedBy: req.UpdatedBy,
	}

	return as.UpdateConfig(c, updateReq)
}

// ===== VALIDATION METHODS =====

func (as *AuthService) validateCreateConfigRequest(req *dto.CreateConfigRequest) error {
	if req.Name == "" {
		return fmt.Errorf("configuration name is required")
	}
	if req.OrgID == uuid.Nil {
		return fmt.Errorf("organization ID is required")
	}
	if req.TenantID == uuid.Nil {
		return fmt.Errorf("tenant ID is required")
	}
	if req.ConfigType == "" {
		return fmt.Errorf("configuration type is required")
	}

	validTypes := []string{"local_auth", "oidc", "oauth_server", "webauthn_mfa", "saml2", "entra_sync", "ad_sync"}
	isValid := false
	for _, validType := range validTypes {
		if req.ConfigType == validType {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("invalid configuration type: %s", req.ConfigType)
	}

	return nil
}

func (as *AuthService) validateUpdateConfigRequest(req *dto.UpdateConfigRequest) error {
	if req.ID == uuid.Nil {
		return fmt.Errorf("configuration ID is required")
	}
	if req.TenantID == uuid.Nil {
		return fmt.Errorf("tenant ID is required")
	}
	if req.OrgID == uuid.Nil {
		return fmt.Errorf("organization ID is required")
	}
	return nil
}

func (as *AuthService) validateLocalAuthConfig(config *dto.LocalAuthConfig) error {
	if config.PasswordPolicy.MinLength < 6 {
		return fmt.Errorf("minimum password length must be at least 6 characters")
	}
	if config.PasswordPolicy.MaxLength < config.PasswordPolicy.MinLength {
		return fmt.Errorf("maximum password length must be greater than minimum length")
	}
	if config.SessionTimeout < 5 {
		return fmt.Errorf("session timeout must be at least 5 minutes")
	}
	if config.MaxLoginAttempts < 3 || config.MaxLoginAttempts > 10 {
		return fmt.Errorf("max login attempts must be between 3 and 10")
	}
	if config.LockoutDuration < 5 {
		return fmt.Errorf("lockout duration must be at least 5 minutes")
	}
	if config.EnableRememberMe && config.RememberMeDuration < 1440 {
		return fmt.Errorf("remember me duration must be at least 24 hours (1440 minutes)")
	}
	return nil
}

func (as *AuthService) validateOIDCConfig(config *dto.OIDCConfig) error {
	if config.ClientID == "" {
		return fmt.Errorf("OIDC client ID is required")
	}
	if config.ClientSecret == "" {
		return fmt.Errorf("OIDC client secret is required")
	}
	if config.Issuer == "" {
		return fmt.Errorf("OIDC issuer is required")
	}
	if config.RedirectURL == "" {
		return fmt.Errorf("OIDC redirect URL is required")
	}
	if len(config.Scopes) == 0 {
		return fmt.Errorf("at least one OIDC scope is required")
	}
	if config.ResponseType == "" {
		config.ResponseType = "code" // Default to authorization code flow
	}
	validResponseTypes := []string{"code", "id_token", "token"}
	isValidResponseType := false
	for _, valid := range validResponseTypes {
		if config.ResponseType == valid {
			isValidResponseType = true
			break
		}
	}
	if !isValidResponseType {
		return fmt.Errorf("invalid OIDC response type: %s", config.ResponseType)
	}
	return nil
}

func (as *AuthService) validateOAuthServerConfig(config *dto.OAuthServerConfig) error {
	if config.ServerURL == "" {
		return fmt.Errorf("OAuth server URL is required")
	}
	if config.ClientID == "" {
		return fmt.Errorf("OAuth client ID is required")
	}
	if config.ClientSecret == "" {
		return fmt.Errorf("OAuth client secret is required")
	}
	if config.TokenEndpoint == "" {
		return fmt.Errorf("OAuth token endpoint is required")
	}
	if config.AuthEndpoint == "" {
		return fmt.Errorf("OAuth auth endpoint is required")
	}
	if len(config.GrantTypes) == 0 {
		return fmt.Errorf("at least one OAuth grant type is required")
	}
	if len(config.RedirectURIs) == 0 {
		return fmt.Errorf("at least one redirect URI is required")
	}
	if config.TokenLifetime < 300 || config.TokenLifetime > 86400 {
		return fmt.Errorf("token lifetime must be between 300 and 86400 seconds")
	}
	if config.RefreshTokenLifetime < 3600 {
		return fmt.Errorf("refresh token lifetime must be at least 3600 seconds")
	}
	return nil
}

func (as *AuthService) validateWebAuthnMFAConfig(config *dto.WebAuthnMFAConfig) error {
	if config.RPDisplayName == "" {
		return fmt.Errorf("WebAuthn RP display name is required")
	}
	if config.RPID == "" {
		return fmt.Errorf("WebAuthn RP ID is required")
	}
	if config.RPOrigin == "" {
		return fmt.Errorf("WebAuthn RP origin is required")
	}
	if config.UserVerification != "required" && config.UserVerification != "preferred" && config.UserVerification != "discouraged" {
		return fmt.Errorf("invalid user verification option: %s", config.UserVerification)
	}
	if config.Timeout < 30 || config.Timeout > 300 {
		return fmt.Errorf("WebAuthn timeout must be between 30 and 300 seconds")
	}
	if config.MaxCredentialsPerUser < 1 || config.MaxCredentialsPerUser > 20 {
		return fmt.Errorf("max credentials per user must be between 1 and 20")
	}
	return nil
}

func (as *AuthService) validateSAML2Config(config *dto.SAML2Config) error {
	if config.EntityID == "" {
		return fmt.Errorf("SAML2 entity ID is required")
	}
	if config.SSOURL == "" {
		return fmt.Errorf("SAML2 SSO URL is required")
	}
	if config.Certificate == "" {
		return fmt.Errorf("SAML2 certificate is required")
	}
	if config.NameIDFormat == "" {
		return fmt.Errorf("SAML2 NameID format is required")
	}
	if config.SessionTimeout < 300 {
		return fmt.Errorf("SAML2 session timeout must be at least 300 seconds")
	}
	if config.AllowedClockDrift > 300 {
		return fmt.Errorf("SAML2 allowed clock drift cannot exceed 300 seconds")
	}
	return nil
}

func (as *AuthService) validateEntraSyncConfig(config *dto.EntraSyncConfig) error {
	if config.TenantID == "" {
		return fmt.Errorf("Entra tenant ID is required")
	}
	if config.ClientID == "" {
		return fmt.Errorf("Entra client ID is required")
	}
	if config.ClientSecret == "" {
		return fmt.Errorf("Entra client secret is required")
	}
	if config.SyncInterval < 15 {
		return fmt.Errorf("sync interval must be at least 15 minutes")
	}
	if config.BatchSize < 10 || config.BatchSize > 1000 {
		return fmt.Errorf("batch size must be between 10 and 1000")
	}
	if config.MaxSyncErrors < 1 || config.MaxSyncErrors > 100 {
		return fmt.Errorf("max sync errors must be between 1 and 100")
	}
	return nil
}

func (as *AuthService) validateADSyncConfig(config *dto.ADSyncConfig) error {
	if config.ServerAddress == "" {
		return fmt.Errorf("AD server address is required")
	}
	if config.Username == "" {
		return fmt.Errorf("AD username is required")
	}
	if config.Password == "" {
		return fmt.Errorf("AD password is required")
	}
	if config.BaseDN == "" {
		return fmt.Errorf("AD base DN is required")
	}
	if config.Port <= 0 || config.Port > 65535 {
		return fmt.Errorf("invalid AD server port: %d", config.Port)
	}
	if config.SyncInterval < 15 {
		return fmt.Errorf("sync interval must be at least 15 minutes")
	}
	if config.BatchSize < 10 || config.BatchSize > 1000 {
		return fmt.Errorf("batch size must be between 10 and 1000")
	}
	if config.ConnectionTimeout < 5 || config.ConnectionTimeout > 300 {
		return fmt.Errorf("connection timeout must be between 5 and 300 seconds")
	}
	if config.SearchTimeout < 5 || config.SearchTimeout > 300 {
		return fmt.Errorf("search timeout must be between 5 and 300 seconds")
	}
	if config.MaxSyncErrors < 1 || config.MaxSyncErrors > 100 {
		return fmt.Errorf("max sync errors must be between 1 and 100")
	}
	if config.EnablePaging && (config.PageSize < 100 || config.PageSize > 5000) {
		return fmt.Errorf("page size must be between 100 and 5000 when paging is enabled")
	}
	return nil
}
