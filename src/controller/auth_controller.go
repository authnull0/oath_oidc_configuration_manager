// src/controller/auth_controller.go (Updated for Multi-Tenant)
package controller

import (
	"fmt"
	"net/http"
	"time"

	"oath_oidc_configuration_manager/src/models/dto"
	"oath_oidc_configuration_manager/src/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AuthController struct {
	authService *service.AuthService
}

func NewAuthController(authService *service.AuthService) *AuthController {
	return &AuthController{
		authService: authService,
	}
}

// ===== CONFIGURATION CRUD OPERATIONS (ALL POST WITH MANDATORY TENANT/ORG) =====

// CreateConfig creates a new authentication configuration in tenant database
func (ac *AuthController) CreateConfig(c *gin.Context) {
	var req dto.CreateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:     "Invalid request",
			Message:   err.Error(),
			Code:      http.StatusBadRequest,
			Timestamp: time.Now(),
		})
		return
	}

	// Validate mandatory tenant and org IDs
	if err := ac.validateTenantAndOrg(req.TenantID, req.OrgID); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Missing required fields",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Extract user_id from middleware (if using auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		req.CreatedBy = "system" // fallback
	} else {
		req.CreatedBy = userID.(string)
	}

	// Call service with context - tenant database will be automatically selected
	response, err := ac.authService.CreateConfig(c, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to create configuration",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusCreated, dto.MessageResponse{
		Message:   "Configuration created successfully",
		Success:   true,
		Data:      response,
		Timestamp: time.Now(),
	})
}

// GetConfigs retrieves configurations with filtering (POST with body) from tenant database
func (ac *AuthController) GetConfigs(c *gin.Context) {
	var req dto.GetConfigsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Validate mandatory tenant and org IDs
	if err := ac.validateTenantAndOrg(req.TenantID, req.OrgID); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Missing required fields",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Set defaults
	if req.Page < 1 {
		req.Page = 1
	}
	if req.Limit < 1 || req.Limit > 100 {
		req.Limit = 10
	}

	// Call service with context - tenant database will be automatically selected
	response, err := ac.authService.GetConfigs(c, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to retrieve configurations",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetActiveConfigs retrieves only active configurations (POST with body) from tenant database
func (ac *AuthController) GetActiveConfigs(c *gin.Context) {
	var req dto.GetConfigsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Validate mandatory tenant and org IDs
	if err := ac.validateTenantAndOrg(req.TenantID, req.OrgID); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Missing required fields",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Force active only
	req.ActiveOnly = true

	// Set defaults
	if req.Page < 1 {
		req.Page = 1
	}
	if req.Limit < 1 || req.Limit > 100 {
		req.Limit = 10
	}

	response, err := ac.authService.GetConfigs(c, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to retrieve active configurations",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetConfigByID retrieves a specific configuration by ID (POST with body) from tenant database
func (ac *AuthController) GetConfigByID(c *gin.Context) {
	var req dto.GetConfigByIDRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Validate mandatory fields
	if err := ac.validateTenantAndOrg(req.TenantID, req.OrgID); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Missing required fields",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	response, err := ac.authService.GetConfigByID(c, &req)
	if err != nil {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{
			Error:   "Configuration not found",
			Message: err.Error(),
			Code:    http.StatusNotFound,
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetConfigByName retrieves a configuration by name (POST with body) from tenant database
func (ac *AuthController) GetConfigByName(c *gin.Context) {
	var req dto.GetConfigByNameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Validate mandatory fields
	if err := ac.validateTenantAndOrg(req.TenantID, req.OrgID); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Missing required fields",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	if req.Name == "" {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Configuration name is required",
			Message: "Name parameter cannot be empty",
			Code:    http.StatusBadRequest,
		})
		return
	}

	response, err := ac.authService.GetConfigByName(c, &req)
	if err != nil {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{
			Error:   "Configuration not found",
			Message: err.Error(),
			Code:    http.StatusNotFound,
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// UpdateConfig updates an existing configuration (POST with body) in tenant database
func (ac *AuthController) UpdateConfig(c *gin.Context) {
	var req dto.UpdateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Validate mandatory fields
	if err := ac.validateTenantAndOrg(req.TenantID, req.OrgID); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Missing required fields",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Extract user_id from middleware
	userID, exists := c.Get("user_id")
	if !exists {
		req.UpdatedBy = "system"
	} else {
		req.UpdatedBy = userID.(string)
	}

	response, err := ac.authService.UpdateConfig(c, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to update configuration",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message: "Configuration updated successfully",
		Success: true,
		Data:    response,
	})
}

// DeleteConfig deletes a configuration (POST with body) from tenant database
func (ac *AuthController) DeleteConfig(c *gin.Context) {
	var req dto.DeleteConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Validate mandatory fields
	if err := ac.validateTenantAndOrg(req.TenantID, req.OrgID); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Missing required fields",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	err := ac.authService.DeleteConfig(c, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to delete configuration",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message: "Configuration deleted successfully",
		Success: true,
	})
}

// ===== SPECIFIC CONFIGURATION ENDPOINTS =====

// ConfigureLocalAuth configures local authentication in tenant database
func (ac *AuthController) ConfigureLocalAuth(c *gin.Context) {
	var req dto.ConfigureLocalAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Validate mandatory fields
	if err := ac.validateTenantAndOrg(req.TenantID, req.OrgID); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Missing required fields",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		req.CreatedBy = "system"
	} else {
		req.CreatedBy = userID.(string)
	}

	response, err := ac.authService.ConfigureLocalAuth(c, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to configure local authentication",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message: "Local authentication configured successfully",
		Success: true,
		Data:    response,
	})
}

// ConfigureOIDC configures OIDC in tenant database
func (ac *AuthController) ConfigureOIDC(c *gin.Context) {
	var req dto.ConfigureOIDCRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Validate mandatory fields
	if err := ac.validateTenantAndOrg(req.TenantID, req.OrgID); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Missing required fields",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		req.CreatedBy = "system"
	} else {
		req.CreatedBy = userID.(string)
	}

	response, err := ac.authService.ConfigureOIDC(c, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to configure OIDC",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message: "OIDC configured successfully",
		Success: true,
		Data:    response,
	})
}

// ConfigureOAuthServer configures OAuth Server in tenant database
func (ac *AuthController) ConfigureOAuthServer(c *gin.Context) {
	var req dto.ConfigureOAuthServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Validate mandatory fields
	if err := ac.validateTenantAndOrg(req.TenantID, req.OrgID); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Missing required fields",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		req.CreatedBy = "system"
	} else {
		req.CreatedBy = userID.(string)
	}

	response, err := ac.authService.ConfigureOAuthServer(c, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to configure OAuth server",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message: "OAuth server configured successfully",
		Success: true,
		Data:    response,
	})
}

// ConfigureWebAuthnMFA configures WebAuthn MFA in tenant database
func (ac *AuthController) ConfigureWebAuthnMFA(c *gin.Context) {
	var req dto.ConfigureWebAuthnMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Validate mandatory fields
	if err := ac.validateTenantAndOrg(req.TenantID, req.OrgID); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Missing required fields",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		req.CreatedBy = "system"
	} else {
		req.CreatedBy = userID.(string)
	}

	response, err := ac.authService.ConfigureWebAuthnMFA(c, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to configure WebAuthn MFA",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message: "WebAuthn MFA configured successfully",
		Success: true,
		Data:    response,
	})
}

// ConfigureSAML2 configures SAML2 in tenant database
func (ac *AuthController) ConfigureSAML2(c *gin.Context) {
	var req dto.ConfigureSAML2Request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Validate mandatory fields
	if err := ac.validateTenantAndOrg(req.TenantID, req.OrgID); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Missing required fields",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		req.CreatedBy = "system"
	} else {
		req.CreatedBy = userID.(string)
	}

	response, err := ac.authService.ConfigureSAML2(c, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to configure SAML2",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message: "SAML2 configured successfully",
		Success: true,
		Data:    response,
	})
}

// ConfigureEntraSync configures Entra ID sync in tenant database
func (ac *AuthController) ConfigureEntraSync(c *gin.Context) {
	var req dto.ConfigureEntraSyncRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Validate mandatory fields
	if err := ac.validateTenantAndOrg(req.TenantID, req.OrgID); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Missing required fields",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		req.CreatedBy = "system"
	} else {
		req.CreatedBy = userID.(string)
	}

	response, err := ac.authService.ConfigureEntraSync(c, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to configure Entra sync",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message: "Entra sync configured successfully",
		Success: true,
		Data:    response,
	})
}

// ConfigureADSync configures Active Directory sync in tenant database
func (ac *AuthController) ConfigureADSync(c *gin.Context) {
	var req dto.ConfigureADSyncRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Validate mandatory fields
	if err := ac.validateTenantAndOrg(req.TenantID, req.OrgID); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Missing required fields",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		req.CreatedBy = "system"
	} else {
		req.CreatedBy = userID.(string)
	}

	response, err := ac.authService.ConfigureADSync(c, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to configure AD sync",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message: "AD sync configured successfully",
		Success: true,
		Data:    response,
	})
}

// ===== MULTI-TENANT QUERY ENDPOINTS =====

// GetTenantConfigs gets all configurations for a specific tenant from tenant database
func (ac *AuthController) GetTenantConfigs(c *gin.Context) {
	var req dto.GetTenantConfigsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Validate mandatory fields
	if err := ac.validateTenantAndOrg(req.TenantID, req.OrgID); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Missing required fields",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	response, err := ac.authService.GetTenantConfigs(c, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to retrieve tenant configurations",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetConfigsByType gets configurations by type for a tenant from tenant database
func (ac *AuthController) GetConfigsByType(c *gin.Context) {
	var req dto.GetConfigsByTypeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Validate mandatory fields
	if err := ac.validateTenantAndOrg(req.TenantID, req.OrgID); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Missing required fields",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	if req.ConfigType == "" {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Configuration type is required",
			Message: "config_type parameter cannot be empty",
			Code:    http.StatusBadRequest,
		})
		return
	}

	response, err := ac.authService.GetConfigsByType(c, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to retrieve configurations by type",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// CheckTenantHasConfig checks if tenant has a specific configuration type in tenant database
func (ac *AuthController) CheckTenantHasConfig(c *gin.Context) {
	var req dto.CheckTenantConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Validate mandatory fields
	if err := ac.validateTenantAndOrg(req.TenantID, req.OrgID); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Missing required fields",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	if req.ConfigType == "" {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Configuration type is required",
			Message: "config_type parameter cannot be empty",
			Code:    http.StatusBadRequest,
		})
		return
	}

	response, err := ac.authService.CheckTenantHasConfig(c, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to check tenant configuration",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetConfigStats gets configuration statistics for a tenant from tenant database
func (ac *AuthController) GetConfigStats(c *gin.Context) {
	var req dto.GetConfigStatsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Validate mandatory fields
	if err := ac.validateTenantAndOrg(req.TenantID, req.OrgID); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Missing required fields",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	response, err := ac.authService.GetConfigStats(c, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to retrieve configuration statistics",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// Validation helper function
func (ac *AuthController) validateTenantAndOrg(tenantID, orgID interface{}) error {
	if tenantID == nil || tenantID == uuid.Nil {
		return fmt.Errorf("tenant_id is mandatory and cannot be empty")
	}
	if orgID == nil || orgID == uuid.Nil {
		return fmt.Errorf("org_id is mandatory and cannot be empty")
	}
	return nil
}
