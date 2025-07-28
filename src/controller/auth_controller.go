// OIDC Configuration Manager Controller - Corrected Architecture
package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"oath_oidc_configuration_manager/src/db"
	"oath_oidc_configuration_manager/src/dto"
	"oath_oidc_configuration_manager/src/repository"
	"oath_oidc_configuration_manager/src/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AuthController struct {
	authService           *service.AuthService
	hydraConfig           HydraConfig
	tenantHydraClientRepo *repository.TenantHydraClientRepository // Add this
}

type HydraConfig struct {
	AdminURL  string
	PublicURL string
}

// Complete OIDC Configuration Request - Single API Call
type CompleteOIDCConfigRequest struct {
	// Tenant Information
	TenantID   string `json:"tenant_id" validate:"required"`
	OrgID      string `json:"org_id" validate:"required"`
	TenantName string `json:"tenant_name" validate:"required"`

	// Tenant OAuth Client Configuration
	TenantClient TenantClientConfig `json:"tenant_client" validate:"required"`

	// OIDC Provider Configurations
	OIDCProviders []OIDCProviderConfig `json:"oidc_providers" validate:"required,min=1"`

	// Metadata
	CreatedBy string `json:"created_by"`
}

type TenantClientConfig struct {
	ClientName   string   `json:"client_name" validate:"required"`
	RedirectURIs []string `json:"redirect_uris" validate:"required,min=1"`
	Scopes       []string `json:"scopes,omitempty"`      // Default: ["openid", "profile", "email"]
	GrantTypes   []string `json:"grant_types,omitempty"` // Default: ["authorization_code", "refresh_token"]
}

type OIDCProviderConfig struct {
	// Provider Identity
	ProviderName string `json:"provider_name" validate:"required"` // github, google, custom-provider, etc.
	DisplayName  string `json:"display_name" validate:"required"`

	// OIDC Configuration
	ClientID     string   `json:"client_id" validate:"required"`
	ClientSecret string   `json:"client_secret" validate:"required"`
	AuthURL      string   `json:"auth_url" validate:"required"`
	TokenURL     string   `json:"token_url" validate:"required"`
	UserInfoURL  string   `json:"user_info_url" validate:"required"`
	Scopes       []string `json:"scopes" validate:"required,min=1"`

	// Optional Configuration
	IssuerURL        string                 `json:"issuer_url,omitempty"`
	JWKsURL          string                 `json:"jwks_url,omitempty"`
	AdditionalParams map[string]interface{} `json:"additional_params,omitempty"`
	IsActive         bool                   `json:"is_active"`
	SortOrder        int                    `json:"sort_order"`
}

// Update OIDC Configuration Request
type UpdateOIDCConfigRequest struct {
	TenantID     string   `json:"tenant_id" validate:"required"`
	OrgID        string   `json:"org_id" validate:"required"`
	ProviderName string   `json:"provider_name" validate:"required"`
	DisplayName  *string  `json:"display_name,omitempty"`
	ClientID     *string  `json:"client_id,omitempty"`
	ClientSecret *string  `json:"client_secret,omitempty"`
	AuthURL      *string  `json:"auth_url,omitempty"`
	TokenURL     *string  `json:"token_url,omitempty"`
	UserInfoURL  *string  `json:"user_info_url,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	IsActive     *bool    `json:"is_active,omitempty"`
	UpdatedBy    string   `json:"updated_by"`
}

// List/Get Requests
type GetTenantConfigRequest struct {
	TenantID string `json:"tenant_id" validate:"required"`
	OrgID    string `json:"org_id" validate:"required"`
}

type GetProviderConfigRequest struct {
	TenantID     string `json:"tenant_id" validate:"required"`
	OrgID        string `json:"org_id" validate:"required"`
	ProviderName string `json:"provider_name" validate:"required"`
}

// Delete Request
type DeleteOIDCConfigRequest struct {
	TenantID     string `json:"tenant_id" validate:"required"`
	OrgID        string `json:"org_id" validate:"required"`
	ProviderName string `json:"provider_name" validate:"required"`
}

// Test Request
type TestOIDCFlowRequest struct {
	TenantID     string `json:"tenant_id" validate:"required"`
	OrgID        string `json:"org_id" validate:"required"`
	ProviderName string `json:"provider_name,omitempty"`
}

// Hydra Client Structure
type HydraClient struct {
	ClientID      string                 `json:"client_id"`
	ClientSecret  string                 `json:"client_secret,omitempty"`
	GrantTypes    []string               `json:"grant_types"`
	RedirectURIs  []string               `json:"redirect_uris"`
	ResponseTypes []string               `json:"response_types"`
	TokenEndpoint string                 `json:"token_endpoint_auth_method"`
	Scope         string                 `json:"scope"`
	ClientName    string                 `json:"client_name"`
	Metadata      map[string]interface{} `json:"metadata"`
}

func NewAuthController(authService *service.AuthService) *AuthController {
	return &AuthController{
		authService: authService,
		hydraConfig: HydraConfig{
			AdminURL:  db.AppConfig.HydraAdminURL,
			PublicURL: db.AppConfig.HydraPublicURL,
		},
		tenantHydraClientRepo: repository.NewTenantHydraClientRepository(), // Add this
	}
}

// ===== MAIN CONFIGURATION ENDPOINT =====

func (ac *AuthController) CompleteOIDCConfiguration(c *gin.Context) {
	var req CompleteOIDCConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:     "Invalid request",
			Message:   err.Error(),
			Code:      http.StatusBadRequest,
			Timestamp: time.Now(),
		})
		return
	}

	// Step 1: Create main tenant OAuth client in Hydra
	tenantClientID := fmt.Sprintf("%s-main-client", req.TenantID)
	clientSecret := generateSecureSecret()

	// Set defaults for tenant client
	grantTypes := req.TenantClient.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}

	scopes := req.TenantClient.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email", "offline_access"}
	}

	tenantClient := HydraClient{
		ClientID:      tenantClientID,
		ClientSecret:  clientSecret,
		GrantTypes:    grantTypes,
		RedirectURIs:  req.TenantClient.RedirectURIs,
		ResponseTypes: []string{"code"},
		TokenEndpoint: "client_secret_post",
		Scope:         strings.Join(scopes, " "),
		ClientName:    req.TenantClient.ClientName,
		Metadata: map[string]interface{}{
			"type":        "tenant_main_client",
			"tenant_id":   req.TenantID,
			"org_id":      req.OrgID,
			"tenant_name": req.TenantName,
			"created_at":  time.Now().Format(time.RFC3339),
			"created_by":  req.CreatedBy,
		},
	}

	if err := ac.createHydraClient(tenantClient); err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:     "Failed to create tenant OAuth client",
			Message:   err.Error(),
			Code:      http.StatusInternalServerError,
			Timestamp: time.Now(),
		})
		return
	}

	// Store the main tenant client mapping in database
	tenantHydraClient := &dto.TenantHydraClient{
		OrgID:             req.OrgID,
		TenantID:          req.TenantID,
		TenantName:        req.TenantName,
		HydraClientID:     tenantClientID,
		HydraClientSecret: clientSecret,
		ClientName:        req.TenantClient.ClientName,
		RedirectURIs:      req.TenantClient.RedirectURIs,
		Scopes:            scopes,
		ClientType:        "main",
		IsActive:          true,
		CreatedBy:         req.CreatedBy,
	}

	if err := ac.tenantHydraClientRepo.Create(tenantHydraClient); err != nil {
		log.Printf("Warning: Failed to store tenant-client mapping: %v", err)
		// Don't fail the whole operation, just log the warning
	}

	// Step 2: Create OIDC provider configurations in Hydra
	var createdProviders []map[string]interface{}
	var failedProviders []map[string]interface{}

	for _, provider := range req.OIDCProviders {
		oidcClientID := fmt.Sprintf("%s-%s-oidc", req.TenantID, normalizeProviderName(provider.ProviderName))

		oidcClient := HydraClient{
			ClientID:     oidcClientID,
			ClientSecret: "not-used-for-oidc-config",
			GrantTypes:   []string{"client_credentials"},
			ClientName:   fmt.Sprintf("%s %s OIDC Config", req.TenantName, provider.DisplayName),
			Metadata: map[string]interface{}{
				"type":          "oidc_provider",
				"tenant_id":     req.TenantID,
				"org_id":        req.OrgID,
				"provider_name": provider.ProviderName,
				"display_name":  provider.DisplayName,
				"provider_config": map[string]interface{}{
					"client_id":         provider.ClientID,
					"client_secret":     provider.ClientSecret,
					"auth_url":          provider.AuthURL,
					"token_url":         provider.TokenURL,
					"user_info_url":     provider.UserInfoURL,
					"scopes":            provider.Scopes,
					"issuer_url":        provider.IssuerURL,
					"jwks_url":          provider.JWKsURL,
					"additional_params": provider.AdditionalParams,
				},
				"is_active":    provider.IsActive,
				"sort_order":   provider.SortOrder,
				"created_at":   time.Now().Format(time.RFC3339),
				"created_by":   req.CreatedBy,
				"callback_url": fmt.Sprintf("%s/callback/%s", db.AppConfig.IdentityProviderURL, normalizeProviderName(provider.ProviderName)),
			},
		}

		if err := ac.createHydraClient(oidcClient); err != nil {
			failedProviders = append(failedProviders, map[string]interface{}{
				"provider_name": provider.ProviderName,
				"error":         err.Error(),
			})
			continue
		}

		// Store the OIDC provider mapping in database
		providerHydraClient := &dto.TenantHydraClient{
			OrgID:             req.OrgID,
			TenantID:          req.TenantID,
			TenantName:        req.TenantName,
			HydraClientID:     oidcClientID,
			HydraClientSecret: "not-used-for-oidc-config",
			ClientName:        fmt.Sprintf("%s %s OIDC Config", req.TenantName, provider.DisplayName),
			ClientType:        "oidc_provider",
			ProviderName:      provider.ProviderName,
			IsActive:          provider.IsActive,
			CreatedBy:         req.CreatedBy,
		}

		if err := ac.tenantHydraClientRepo.Create(providerHydraClient); err != nil {
			log.Printf("Warning: Failed to store OIDC provider mapping for %s: %v", provider.ProviderName, err)
		}

		createdProviders = append(createdProviders, map[string]interface{}{
			"provider_name": provider.ProviderName,
			"display_name":  provider.DisplayName,
			"client_id":     oidcClientID,
			"callback_url":  fmt.Sprintf("%s/callback/%s", db.AppConfig.IdentityProviderURL, normalizeProviderName(provider.ProviderName)),
			"is_active":     provider.IsActive,
		})
	}

	// Step 3: Generate response
	response := map[string]interface{}{
		"success":     true,
		"tenant_id":   req.TenantID,
		"org_id":      req.OrgID,
		"tenant_name": req.TenantName,

		"tenant_client": map[string]interface{}{
			"client_id":     tenantClientID,
			"client_secret": clientSecret,
			"redirect_uris": req.TenantClient.RedirectURIs,
			"scopes":        scopes,
		},

		"oidc_providers": map[string]interface{}{
			"created":       createdProviders,
			"failed":        failedProviders,
			"total":         len(req.OIDCProviders),
			"success_count": len(createdProviders),
			"failed_count":  len(failedProviders),
		},

		"login_url": fmt.Sprintf("%s/oauth2/auth?client_id=%s&response_type=code&scope=%s&redirect_uri=",
			ac.hydraConfig.PublicURL, tenantClientID, strings.Join(scopes, "+")),

		"callback_urls": ac.generateCallbackURLs(req.OIDCProviders),

		"instructions": map[string]string{
			"setup":     "Use the callback URLs when configuring your OIDC providers",
			"login":     "Use the login_url with your redirect_uri to start OAuth flow",
			"providers": "Configure your OIDC providers with the provided callback URLs",
		},
	}

	statusCode := http.StatusCreated
	message := "OIDC configuration completed successfully"

	if len(failedProviders) > 0 {
		if len(createdProviders) == 0 {
			statusCode = http.StatusInternalServerError
			message = "Failed to create OIDC configuration"
		} else {
			statusCode = http.StatusPartialContent
			message = "OIDC configuration completed with some failures"
		}
	}

	c.JSON(statusCode, dto.MessageResponse{
		Message:   message,
		Success:   len(createdProviders) > 0,
		Data:      response,
		Timestamp: time.Now(),
	})
}

// ===== MANAGEMENT ENDPOINTS =====

func (ac *AuthController) UpdateOIDCProvider(c *gin.Context) {
	var req UpdateOIDCConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:     "Invalid request",
			Message:   err.Error(),
			Code:      http.StatusBadRequest,
			Timestamp: time.Now(),
		})
		return
	}

	// Get existing OIDC client
	oidcClientID := fmt.Sprintf("%s-%s-oidc", req.TenantID, normalizeProviderName(req.ProviderName))

	existingClient, err := ac.getHydraClient(oidcClientID)
	if err != nil {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{
			Error:     "OIDC provider not found",
			Message:   err.Error(),
			Code:      http.StatusNotFound,
			Timestamp: time.Now(),
		})
		return
	}

	// Update metadata
	metadata := existingClient.Metadata
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	if providerConfig, ok := metadata["provider_config"].(map[string]interface{}); ok {
		if req.ClientID != nil {
			providerConfig["client_id"] = *req.ClientID
		}
		if req.ClientSecret != nil {
			providerConfig["client_secret"] = *req.ClientSecret
		}
		if req.AuthURL != nil {
			providerConfig["auth_url"] = *req.AuthURL
		}
		if req.TokenURL != nil {
			providerConfig["token_url"] = *req.TokenURL
		}
		if req.UserInfoURL != nil {
			providerConfig["user_info_url"] = *req.UserInfoURL
		}
		if len(req.Scopes) > 0 {
			providerConfig["scopes"] = req.Scopes
		}
		metadata["provider_config"] = providerConfig
	}

	if req.DisplayName != nil {
		metadata["display_name"] = *req.DisplayName
	}
	if req.IsActive != nil {
		metadata["is_active"] = *req.IsActive
	}
	metadata["updated_at"] = time.Now().Format(time.RFC3339)
	metadata["updated_by"] = req.UpdatedBy

	updatedClient := HydraClient{
		ClientID:   oidcClientID,
		ClientName: existingClient.ClientName,
		GrantTypes: existingClient.GrantTypes,
		Metadata:   metadata,
	}

	if req.DisplayName != nil {
		updatedClient.ClientName = fmt.Sprintf("%s %s OIDC Config",
			metadata["tenant_name"], *req.DisplayName)
	}

	if err := ac.updateHydraClient(oidcClientID, updatedClient); err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:     "Failed to update OIDC provider",
			Message:   err.Error(),
			Code:      http.StatusInternalServerError,
			Timestamp: time.Now(),
		})
		return
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message: "OIDC provider updated successfully",
		Success: true,
		Data: map[string]interface{}{
			"provider_name": req.ProviderName,
			"client_id":     oidcClientID,
			"updated_at":    time.Now(),
		},
		Timestamp: time.Now(),
	})
}

func (ac *AuthController) GetTenantOIDCConfig(c *gin.Context) {
	var req GetTenantConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:     "Invalid request",
			Message:   err.Error(),
			Code:      http.StatusBadRequest,
			Timestamp: time.Now(),
		})
		return
	}

	// Get all Hydra clients for this tenant
	clients, err := ac.getAllHydraClients()
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:     "Failed to get Hydra clients",
			Message:   err.Error(),
			Code:      http.StatusInternalServerError,
			Timestamp: time.Now(),
		})
		return
	}

	var tenantClient map[string]interface{}
	var oidcProviders []map[string]interface{}

	for _, client := range clients {
		if metadata, ok := client.Metadata["tenant_id"].(string); ok && metadata == req.TenantID {
			if orgID, ok := client.Metadata["org_id"].(string); ok && orgID == req.OrgID {

				if clientType, ok := client.Metadata["type"].(string); ok {
					switch clientType {
					case "tenant_main_client":
						tenantClient = map[string]interface{}{
							"client_id":     client.ClientID,
							"client_name":   client.ClientName,
							"redirect_uris": client.RedirectURIs,
							"scopes":        strings.Split(client.Scope, " "),
							"created_at":    client.Metadata["created_at"],
						}
					case "oidc_provider":
						provider := map[string]interface{}{
							"provider_name": client.Metadata["provider_name"],
							"display_name":  client.Metadata["display_name"],
							"client_id":     client.ClientID,
							"is_active":     client.Metadata["is_active"],
							"sort_order":    client.Metadata["sort_order"],
							"callback_url":  client.Metadata["callback_url"],
							"created_at":    client.Metadata["created_at"],
						}

						if providerConfig, ok := client.Metadata["provider_config"].(map[string]interface{}); ok {
							provider["provider_config"] = providerConfig
						}

						oidcProviders = append(oidcProviders, provider)
					}
				}
			}
		}
	}

	if tenantClient == nil {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{
			Error:     "Tenant configuration not found",
			Message:   "No configuration found for the specified tenant",
			Code:      http.StatusNotFound,
			Timestamp: time.Now(),
		})
		return
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message: "Tenant OIDC configuration retrieved successfully",
		Success: true,
		Data: map[string]interface{}{
			"tenant_id":      req.TenantID,
			"org_id":         req.OrgID,
			"tenant_client":  tenantClient,
			"oidc_providers": oidcProviders,
			"provider_count": len(oidcProviders),
		},
		Timestamp: time.Now(),
	})
}

func (ac *AuthController) GetOIDCProvider(c *gin.Context) {
	var req GetProviderConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:     "Invalid request",
			Message:   err.Error(),
			Code:      http.StatusBadRequest,
			Timestamp: time.Now(),
		})
		return
	}

	oidcClientID := fmt.Sprintf("%s-%s-oidc", req.TenantID, normalizeProviderName(req.ProviderName))

	client, err := ac.getHydraClient(oidcClientID)
	if err != nil {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{
			Error:     "OIDC provider not found",
			Message:   err.Error(),
			Code:      http.StatusNotFound,
			Timestamp: time.Now(),
		})
		return
	}

	response := map[string]interface{}{
		"provider_name": client.Metadata["provider_name"],
		"display_name":  client.Metadata["display_name"],
		"client_id":     client.ClientID,
		"is_active":     client.Metadata["is_active"],
		"sort_order":    client.Metadata["sort_order"],
		"callback_url":  client.Metadata["callback_url"],
		"created_at":    client.Metadata["created_at"],
	}

	if providerConfig, ok := client.Metadata["provider_config"].(map[string]interface{}); ok {
		// Remove sensitive data from response
		sanitizedConfig := make(map[string]interface{})
		for k, v := range providerConfig {
			if k != "client_secret" {
				sanitizedConfig[k] = v
			} else {
				sanitizedConfig[k] = "***hidden***"
			}
		}
		response["provider_config"] = sanitizedConfig
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message:   "OIDC provider retrieved successfully",
		Success:   true,
		Data:      response,
		Timestamp: time.Now(),
	})
}

func (ac *AuthController) DeleteOIDCProvider(c *gin.Context) {
	var req DeleteOIDCConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:     "Invalid request",
			Message:   err.Error(),
			Code:      http.StatusBadRequest,
			Timestamp: time.Now(),
		})
		return
	}

	oidcClientID := fmt.Sprintf("%s-%s-oidc", req.TenantID, normalizeProviderName(req.ProviderName))

	if err := ac.deleteHydraClient(oidcClientID); err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:     "Failed to delete OIDC provider",
			Message:   err.Error(),
			Code:      http.StatusInternalServerError,
			Timestamp: time.Now(),
		})
		return
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message: "OIDC provider deleted successfully",
		Success: true,
		Data: map[string]interface{}{
			"provider_name": req.ProviderName,
			"deleted_at":    time.Now(),
		},
		Timestamp: time.Now(),
	})
}

// ===== TESTING ENDPOINTS =====

func (ac *AuthController) TestOIDCFlow(c *gin.Context) {
	var req TestOIDCFlowRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:     "Invalid request",
			Message:   err.Error(),
			Code:      http.StatusBadRequest,
			Timestamp: time.Now(),
		})
		return
	}

	// Get tenant main client
	tenantClientID := fmt.Sprintf("%s-main-client", req.TenantID)
	tenantClient, err := ac.getHydraClient(tenantClientID)
	if err != nil {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{
			Error:     "Tenant client not found",
			Message:   err.Error(),
			Code:      http.StatusNotFound,
			Timestamp: time.Now(),
		})
		return
	}

	response := map[string]interface{}{
		"tenant_id":        req.TenantID,
		"org_id":           req.OrgID,
		"tenant_client_id": tenantClientID,
		"login_url_template": fmt.Sprintf("%s/oauth2/auth?client_id=%s&response_type=code&scope=%s&redirect_uri={{redirect_uri}}&state={{state}}",
			ac.hydraConfig.PublicURL, tenantClientID, tenantClient.Scope),
	}

	if req.ProviderName != "" {
		callbackURL := fmt.Sprintf("%s/oauth2/callback/%s", ac.hydraConfig.PublicURL, normalizeProviderName(req.ProviderName))
		response["provider_callback_url"] = callbackURL

		// Get provider config if exists
		oidcClientID := fmt.Sprintf("%s-%s-oidc", req.TenantID, normalizeProviderName(req.ProviderName))
		if providerClient, err := ac.getHydraClient(oidcClientID); err == nil {
			response["provider_config"] = map[string]interface{}{
				"provider_name": providerClient.Metadata["provider_name"],
				"display_name":  providerClient.Metadata["display_name"],
				"is_active":     providerClient.Metadata["is_active"],
			}
		}
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message:   "OIDC flow test information retrieved successfully",
		Success:   true,
		Data:      response,
		Timestamp: time.Now(),
	})
}

// ===== HYDRA API OPERATIONS =====

func (ac *AuthController) createHydraClient(client HydraClient) error {
	jsonData, err := json.Marshal(client)
	if err != nil {
		return fmt.Errorf("failed to marshal client data: %w", err)
	}

	url := fmt.Sprintf("%s/admin/clients", ac.hydraConfig.AdminURL)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call Hydra API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("Hydra API returned status %d", resp.StatusCode)
	}

	return nil
}

func (ac *AuthController) getHydraClient(clientID string) (*HydraClient, error) {
	url := fmt.Sprintf("%s/admin/clients/%s", ac.hydraConfig.AdminURL, clientID)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client not found or API error: %d", resp.StatusCode)
	}

	var client HydraClient
	if err := json.NewDecoder(resp.Body).Decode(&client); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &client, nil
}

func (ac *AuthController) getAllHydraClients() ([]HydraClient, error) {
	url := fmt.Sprintf("%s/admin/clients", ac.hydraConfig.AdminURL)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get clients: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: %d", resp.StatusCode)
	}

	var clients []HydraClient
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return clients, nil
}

func (ac *AuthController) updateHydraClient(clientID string, client HydraClient) error {
	jsonData, err := json.Marshal(client)
	if err != nil {
		return fmt.Errorf("failed to marshal client data: %w", err)
	}

	url := fmt.Sprintf("%s/admin/clients/%s", ac.hydraConfig.AdminURL, clientID)

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call Hydra API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Hydra API returned status %d", resp.StatusCode)
	}

	return nil
}

func (ac *AuthController) deleteHydraClient(clientID string) error {
	url := fmt.Sprintf("%s/admin/clients/%s", ac.hydraConfig.AdminURL, clientID)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call Hydra API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Hydra API returned status %d", resp.StatusCode)
	}

	return nil
}

// ===== UTILITY FUNCTIONS =====

func (ac *AuthController) generateCallbackURLs(providers []OIDCProviderConfig) map[string]string {
	callbackURLs := make(map[string]string)

	for _, provider := range providers {
		normalizedName := normalizeProviderName(provider.ProviderName)
		callbackURLs[provider.ProviderName] = fmt.Sprintf("%s/oauth2/callback/%s",
			ac.hydraConfig.PublicURL, normalizedName)
	}

	return callbackURLs
}

func generateSecureSecret() string {
	return fmt.Sprintf("secret-%d-%s", time.Now().Unix(), uuid.New().String()[:8])
}

func normalizeProviderName(name string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, " ", "-"), "_", "-"))
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// ===== ADDITIONAL HELPER ENDPOINTS =====

func (ac *AuthController) GetProviderTemplates(c *gin.Context) {
	var req struct {
		TenantID string `json:"tenant_id" validate:"required"`
		OrgID    string `json:"org_id" validate:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:     "Invalid request",
			Message:   err.Error(),
			Code:      http.StatusBadRequest,
			Timestamp: time.Now(),
		})
		return
	}

	// Common provider templates that can be used as starting points
	templates := map[string]map[string]interface{}{
		"github": {
			"provider_name": "github",
			"display_name":  "GitHub",
			"auth_url":      "https://github.com/login/oauth/authorize",
			"token_url":     "https://github.com/login/oauth/access_token",
			"user_info_url": "https://api.github.com/user",
			"scopes":        []string{"user:email"},
			"description":   "GitHub OAuth integration",
		},
		"google": {
			"provider_name": "google",
			"display_name":  "Google",
			"auth_url":      "https://accounts.google.com/o/oauth2/v2/auth",
			"token_url":     "https://oauth2.googleapis.com/token",
			"user_info_url": "https://www.googleapis.com/oauth2/v2/userinfo",
			"scopes":        []string{"openid", "profile", "email"},
			"description":   "Google OAuth 2.0 integration",
		},
		"linkedin": {
			"provider_name": "linkedin",
			"display_name":  "LinkedIn",
			"auth_url":      "https://www.linkedin.com/oauth/v2/authorization",
			"token_url":     "https://www.linkedin.com/oauth/v2/accessToken",
			"user_info_url": "https://api.linkedin.com/v2/me",
			"scopes":        []string{"r_liteprofile", "r_emailaddress"},
			"description":   "LinkedIn OAuth 2.0 integration",
		},
		"microsoft": {
			"provider_name": "microsoft",
			"display_name":  "Microsoft",
			"auth_url":      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			"token_url":     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			"user_info_url": "https://graph.microsoft.com/v1.0/me",
			"scopes":        []string{"openid", "profile", "email"},
			"description":   "Microsoft Azure AD OAuth 2.0 integration",
		},
		"okta": {
			"provider_name": "okta",
			"display_name":  "Okta",
			"auth_url":      "https://{your-okta-domain}/oauth2/v1/authorize",
			"token_url":     "https://{your-okta-domain}/oauth2/v1/token",
			"user_info_url": "https://{your-okta-domain}/oauth2/v1/userinfo",
			"scopes":        []string{"openid", "profile", "email"},
			"description":   "Okta OAuth 2.0 integration (replace {your-okta-domain})",
		},
		"auth0": {
			"provider_name": "auth0",
			"display_name":  "Auth0",
			"auth_url":      "https://{your-auth0-domain}/authorize",
			"token_url":     "https://{your-auth0-domain}/oauth/token",
			"user_info_url": "https://{your-auth0-domain}/userinfo",
			"scopes":        []string{"openid", "profile", "email"},
			"description":   "Auth0 OAuth 2.0 integration (replace {your-auth0-domain})",
		},
		"custom": {
			"provider_name": "custom-provider",
			"display_name":  "Custom Provider",
			"auth_url":      "https://your-provider.com/oauth/authorize",
			"token_url":     "https://your-provider.com/oauth/token",
			"user_info_url": "https://your-provider.com/oauth/userinfo",
			"scopes":        []string{"openid", "profile", "email"},
			"description":   "Template for custom OAuth 2.0 provider",
		},
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message: "Provider templates retrieved successfully",
		Success: true,
		Data: map[string]interface{}{
			"templates":    templates,
			"count":        len(templates),
			"instructions": "Use these templates as starting points for configuring OIDC providers. Replace placeholder values with your actual provider details.",
		},
		Timestamp: time.Now(),
	})
}

func (ac *AuthController) ValidateOIDCConfig(c *gin.Context) {
	var req struct {
		TenantID     string `json:"tenant_id" validate:"required"`
		OrgID        string `json:"org_id" validate:"required"`
		ProviderName string `json:"provider_name" validate:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:     "Invalid request",
			Message:   err.Error(),
			Code:      http.StatusBadRequest,
			Timestamp: time.Now(),
		})
		return
	}

	oidcClientID := fmt.Sprintf("%s-%s-oidc", req.TenantID, normalizeProviderName(req.ProviderName))

	client, err := ac.getHydraClient(oidcClientID)
	if err != nil {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{
			Error:     "OIDC provider not found",
			Message:   err.Error(),
			Code:      http.StatusNotFound,
			Timestamp: time.Now(),
		})
		return
	}

	// Validate configuration
	errors := []string{}
	warnings := []string{}

	providerConfig, ok := client.Metadata["provider_config"].(map[string]interface{})
	if !ok {
		errors = append(errors, "Provider configuration not found in metadata")
	} else {
		// Check required fields
		if clientID, ok := providerConfig["client_id"].(string); !ok || clientID == "" {
			errors = append(errors, "Client ID is required")
		}
		if clientSecret, ok := providerConfig["client_secret"].(string); !ok || clientSecret == "" {
			errors = append(errors, "Client Secret is required")
		}
		if authURL, ok := providerConfig["auth_url"].(string); !ok || authURL == "" {
			errors = append(errors, "Auth URL is required")
		}
		if tokenURL, ok := providerConfig["token_url"].(string); !ok || tokenURL == "" {
			errors = append(errors, "Token URL is required")
		}
		if userInfoURL, ok := providerConfig["user_info_url"].(string); !ok || userInfoURL == "" {
			errors = append(errors, "User Info URL is required")
		}
		if scopes, ok := providerConfig["scopes"].([]interface{}); !ok || len(scopes) == 0 {
			errors = append(errors, "At least one scope is required")
		}

		// Check if provider is active
		if isActive, ok := client.Metadata["is_active"].(bool); !ok || !isActive {
			warnings = append(warnings, "Provider is not currently active")
		}
	}

	validationResult := map[string]interface{}{
		"provider_name": req.ProviderName,
		"client_id":     oidcClientID,
		"is_valid":      len(errors) == 0,
		"errors":        errors,
		"warnings":      warnings,
		"validated_at":  time.Now(),
	}

	status := http.StatusOK
	message := "Validation completed successfully"

	if len(errors) > 0 {
		message = "Validation failed with errors"
	} else if len(warnings) > 0 {
		message = "Validation passed with warnings"
	}

	c.JSON(status, dto.MessageResponse{
		Message:   message,
		Success:   len(errors) == 0,
		Data:      validationResult,
		Timestamp: time.Now(),
	})
}

func (ac *AuthController) GetTenantStats(c *gin.Context) {
	var req struct {
		TenantID string `json:"tenant_id" validate:"required"`
		OrgID    string `json:"org_id" validate:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:     "Invalid request",
			Message:   err.Error(),
			Code:      http.StatusBadRequest,
			Timestamp: time.Now(),
		})
		return
	}

	// Get all clients for this tenant
	clients, err := ac.getAllHydraClients()
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:     "Failed to get client information",
			Message:   err.Error(),
			Code:      http.StatusInternalServerError,
			Timestamp: time.Now(),
		})
		return
	}

	var tenantClientCount int
	var oidcProviderCount int
	var activeProviders int
	var inactiveProviders int
	var providersByType = make(map[string]int)

	for _, client := range clients {
		if tenantID, ok := client.Metadata["tenant_id"].(string); ok && tenantID == req.TenantID {
			if orgID, ok := client.Metadata["org_id"].(string); ok && orgID == req.OrgID {

				if clientType, ok := client.Metadata["type"].(string); ok {
					switch clientType {
					case "tenant_main_client":
						tenantClientCount++
					case "oidc_provider":
						oidcProviderCount++

						if isActive, ok := client.Metadata["is_active"].(bool); ok && isActive {
							activeProviders++
						} else {
							inactiveProviders++
						}

						if providerName, ok := client.Metadata["provider_name"].(string); ok {
							providersByType[providerName]++
						}
					}
				}
			}
		}
	}

	stats := map[string]interface{}{
		"tenant_id":          req.TenantID,
		"org_id":             req.OrgID,
		"tenant_clients":     tenantClientCount,
		"total_providers":    oidcProviderCount,
		"active_providers":   activeProviders,
		"inactive_providers": inactiveProviders,
		"providers_by_type":  providersByType,
		"last_updated":       time.Now(),
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message:   "Tenant statistics retrieved successfully",
		Success:   true,
		Data:      stats,
		Timestamp: time.Now(),
	})
}
func (ac *AuthController) DeleteCompleteTenantConfig(c *gin.Context) {
	var req struct {
		TenantID string `json:"tenant_id" validate:"required"`
		OrgID    string `json:"org_id" validate:"required"`
		Force    bool   `json:"force"` // Force delete even if errors
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:     "Invalid request",
			Message:   err.Error(),
			Code:      http.StatusBadRequest,
			Timestamp: time.Now(),
		})
		return
	}

	// Get all Hydra clients for this tenant
	clients, err := ac.getAllHydraClients()
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:     "Failed to get Hydra clients",
			Message:   err.Error(),
			Code:      http.StatusInternalServerError,
			Timestamp: time.Now(),
		})
		return
	}

	var deletedClients []string
	var failedDeletions []map[string]interface{}

	// Find and delete all clients for this tenant
	for _, client := range clients {
		if tenantID, ok := client.Metadata["tenant_id"].(string); ok && tenantID == req.TenantID {
			if orgID, ok := client.Metadata["org_id"].(string); ok && orgID == req.OrgID {

				err := ac.deleteHydraClient(client.ClientID)
				if err != nil {
					if !req.Force {
						c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
							Error:     "Failed to delete client",
							Message:   fmt.Sprintf("Failed to delete client %s: %v", client.ClientID, err),
							Code:      http.StatusInternalServerError,
							Timestamp: time.Now(),
						})
						return
					}
					failedDeletions = append(failedDeletions, map[string]interface{}{
						"client_id": client.ClientID,
						"error":     err.Error(),
					})
				} else {
					deletedClients = append(deletedClients, client.ClientID)
				}
			}
		}
	}

	if len(deletedClients) == 0 && len(failedDeletions) == 0 {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{
			Error:     "Tenant configuration not found",
			Message:   "No configuration found for the specified tenant",
			Code:      http.StatusNotFound,
			Timestamp: time.Now(),
		})
		return
	}

	response := map[string]interface{}{
		"success":          len(deletedClients) > 0,
		"tenant_id":        req.TenantID,
		"org_id":           req.OrgID,
		"deleted_clients":  deletedClients,
		"failed_deletions": failedDeletions,
		"deleted_count":    len(deletedClients),
		"failed_count":     len(failedDeletions),
	}

	statusCode := http.StatusOK
	message := "Tenant configuration deleted successfully"

	if len(failedDeletions) > 0 {
		if len(deletedClients) == 0 {
			statusCode = http.StatusInternalServerError
			message = "Failed to delete tenant configuration"
		} else {
			statusCode = http.StatusPartialContent
			message = "Tenant configuration partially deleted"
		}
	}

	c.JSON(statusCode, dto.MessageResponse{
		Message:   message,
		Success:   len(deletedClients) > 0,
		Data:      response,
		Timestamp: time.Now(),
	})
}

// List All Tenants
func (ac *AuthController) ListAllTenants(c *gin.Context) {
	// Get all Hydra clients
	clients, err := ac.getAllHydraClients()
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:     "Failed to get Hydra clients",
			Message:   err.Error(),
			Code:      http.StatusInternalServerError,
			Timestamp: time.Now(),
		})
		return
	}

	// Group by tenant
	tenants := make(map[string]map[string]interface{})

	for _, client := range clients {
		if tenantID, ok := client.Metadata["tenant_id"].(string); ok {
			if orgID, ok := client.Metadata["org_id"].(string); ok {
				tenantKey := fmt.Sprintf("%s:%s", tenantID, orgID)

				if _, exists := tenants[tenantKey]; !exists {
					tenants[tenantKey] = map[string]interface{}{
						"tenant_id":        tenantID,
						"org_id":           orgID,
						"tenant_name":      client.Metadata["tenant_name"],
						"main_client":      nil,
						"oidc_providers":   []map[string]interface{}{},
						"total_clients":    0,
						"active_providers": 0,
					}
				}

				tenant := tenants[tenantKey]
				tenant["total_clients"] = tenant["total_clients"].(int) + 1

				if clientType, ok := client.Metadata["type"].(string); ok {
					switch clientType {
					case "tenant_main_client":
						tenant["main_client"] = map[string]interface{}{
							"client_id":   client.ClientID,
							"client_name": client.ClientName,
							"created_at":  client.Metadata["created_at"],
						}
					case "oidc_provider":
						provider := map[string]interface{}{
							"provider_name": client.Metadata["provider_name"],
							"display_name":  client.Metadata["display_name"],
							"client_id":     client.ClientID,
							"is_active":     client.Metadata["is_active"],
							"sort_order":    client.Metadata["sort_order"],
						}

						providers := tenant["oidc_providers"].([]map[string]interface{})
						tenant["oidc_providers"] = append(providers, provider)

						if isActive, ok := client.Metadata["is_active"].(bool); ok && isActive {
							tenant["active_providers"] = tenant["active_providers"].(int) + 1
						}
					}
				}
			}
		}
	}

	// Convert map to slice
	var tenantList []map[string]interface{}
	for _, tenant := range tenants {
		tenantList = append(tenantList, tenant)
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message: "Tenants listed successfully",
		Success: true,
		Data: map[string]interface{}{
			"tenants": tenantList,
			"count":   len(tenantList),
		},
		Timestamp: time.Now(),
	})
}

// Check if Tenant Exists
func (ac *AuthController) CheckTenantExists(c *gin.Context) {
	var req struct {
		TenantID string `json:"tenant_id" validate:"required"`
		OrgID    string `json:"org_id" validate:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:     "Invalid request",
			Message:   err.Error(),
			Code:      http.StatusBadRequest,
			Timestamp: time.Now(),
		})
		return
	}

	// Check if main client exists
	mainClientID := fmt.Sprintf("%s-main-client", req.TenantID)

	client, err := ac.getHydraClient(mainClientID)
	exists := err == nil && client != nil

	var tenantInfo map[string]interface{}
	if exists {
		tenantInfo = map[string]interface{}{
			"tenant_id":   req.TenantID,
			"org_id":      req.OrgID,
			"tenant_name": client.Metadata["tenant_name"],
			"client_id":   client.ClientID,
			"client_name": client.ClientName,
			"created_at":  client.Metadata["created_at"],
		}
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message: "Tenant existence check completed",
		Success: true,
		Data: map[string]interface{}{
			"exists":      exists,
			"tenant_id":   req.TenantID,
			"org_id":      req.OrgID,
			"tenant_info": tenantInfo,
		},
		Timestamp: time.Now(),
	})
}

// OIDCProvider struct for internal use
type OIDCProvider struct {
	ProviderName string                 `json:"provider_name"`
	DisplayName  string                 `json:"display_name"`
	IsActive     bool                   `json:"is_active"`
	SortOrder    int                    `json:"sort_order"`
	CallbackURL  string                 `json:"callback_url"`
	Config       map[string]interface{} `json:"config"`
}

// Update Complete Tenant Configuration
func (ac *AuthController) UpdateCompleteTenantConfig(c *gin.Context) {
	var req struct {
		TenantID      string               `json:"tenant_id" validate:"required"`
		OrgID         string               `json:"org_id" validate:"required"`
		TenantName    *string              `json:"tenant_name,omitempty"`
		TenantClient  *TenantClientConfig  `json:"tenant_client,omitempty"`
		OIDCProviders []OIDCProviderConfig `json:"oidc_providers,omitempty"`
		UpdatedBy     string               `json:"updated_by"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:     "Invalid request",
			Message:   err.Error(),
			Code:      http.StatusBadRequest,
			Timestamp: time.Now(),
		})
		return
	}

	// Check if tenant exists
	mainClientID := fmt.Sprintf("%s-main-client", req.TenantID)
	existingMainClient, err := ac.getHydraClient(mainClientID)
	if err != nil {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{
			Error:     "Tenant not found",
			Message:   fmt.Sprintf("Tenant with ID %s does not exist", req.TenantID),
			Code:      http.StatusNotFound,
			Timestamp: time.Now(),
		})
		return
	}

	var updatedMainClient *HydraClient
	var updatedProviders []map[string]interface{}
	var failedProviders []map[string]interface{}

	// Update main tenant client if provided
	if req.TenantClient != nil {
		// Set defaults
		grantTypes := req.TenantClient.GrantTypes
		if len(grantTypes) == 0 {
			grantTypes = []string{"authorization_code", "refresh_token"}
		}

		scopes := req.TenantClient.Scopes
		if len(scopes) == 0 {
			scopes = []string{"openid", "profile", "email", "offline_access"}
		}

		// Update tenant name if provided
		tenantName := existingMainClient.Metadata["tenant_name"].(string)
		if req.TenantName != nil {
			tenantName = *req.TenantName
		}

		updatedMainClient = &HydraClient{
			ClientID:      mainClientID,
			ClientName:    req.TenantClient.ClientName,
			GrantTypes:    grantTypes,
			RedirectURIs:  req.TenantClient.RedirectURIs,
			ResponseTypes: []string{"code"},
			Scope:         strings.Join(scopes, " "),
			Metadata: map[string]interface{}{
				"type":        "tenant_main_client",
				"tenant_id":   req.TenantID,
				"org_id":      req.OrgID,
				"tenant_name": tenantName,
				"created_at":  existingMainClient.Metadata["created_at"],
				"updated_at":  time.Now().Format(time.RFC3339),
				"updated_by":  req.UpdatedBy,
			},
		}

		if err := ac.updateHydraClient(mainClientID, *updatedMainClient); err != nil {
			c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
				Error:     "Failed to update tenant client",
				Message:   err.Error(),
				Code:      http.StatusInternalServerError,
				Timestamp: time.Now(),
			})
			return
		}
	}

	// Update OIDC providers if provided
	if len(req.OIDCProviders) > 0 {
		// Get existing providers
		existingProviders, err := ac.getOIDCProvidersForTenant(req.TenantID)
		if err != nil {
			log.Printf("Warning: Failed to get existing providers: %v", err)
		}

		// Create map of existing providers for quick lookup
		existingProviderMap := make(map[string]bool)
		for _, provider := range existingProviders {
			existingProviderMap[provider.ProviderName] = true
		}

		for _, provider := range req.OIDCProviders {
			oidcClientID := fmt.Sprintf("%s-%s-oidc", req.TenantID, normalizeProviderName(provider.ProviderName))

			// Determine tenant name for client name
			tenantName := existingMainClient.Metadata["tenant_name"].(string)
			if req.TenantName != nil {
				tenantName = *req.TenantName
			}

			oidcClient := HydraClient{
				ClientID:   oidcClientID,
				ClientName: fmt.Sprintf("%s %s OIDC Config", tenantName, provider.DisplayName),
				GrantTypes: []string{"client_credentials"},
				Metadata: map[string]interface{}{
					"type":          "oidc_provider",
					"tenant_id":     req.TenantID,
					"org_id":        req.OrgID,
					"provider_name": provider.ProviderName,
					"display_name":  provider.DisplayName,
					"provider_config": map[string]interface{}{
						"client_id":         provider.ClientID,
						"client_secret":     provider.ClientSecret,
						"auth_url":          provider.AuthURL,
						"token_url":         provider.TokenURL,
						"user_info_url":     provider.UserInfoURL,
						"scopes":            provider.Scopes,
						"issuer_url":        provider.IssuerURL,
						"jwks_url":          provider.JWKsURL,
						"additional_params": provider.AdditionalParams,
					},
					"is_active":    provider.IsActive,
					"sort_order":   provider.SortOrder,
					"callback_url": fmt.Sprintf("%s/oauth2/callback/%s", ac.hydraConfig.PublicURL, normalizeProviderName(provider.ProviderName)),
					"updated_at":   time.Now().Format(time.RFC3339),
					"updated_by":   req.UpdatedBy,
				},
			}

			// Check if provider exists
			if existingProviderMap[provider.ProviderName] {
				// Update existing provider
				if err := ac.updateHydraClient(oidcClientID, oidcClient); err != nil {
					failedProviders = append(failedProviders, map[string]interface{}{
						"provider_name": provider.ProviderName,
						"action":        "update",
						"error":         err.Error(),
					})
					continue
				}
			} else {
				// Create new provider
				if err := ac.createHydraClient(oidcClient); err != nil {
					failedProviders = append(failedProviders, map[string]interface{}{
						"provider_name": provider.ProviderName,
						"action":        "create",
						"error":         err.Error(),
					})
					continue
				}
			}

			updatedProviders = append(updatedProviders, map[string]interface{}{
				"provider_name": provider.ProviderName,
				"display_name":  provider.DisplayName,
				"client_id":     oidcClientID,
				"callback_url":  fmt.Sprintf("%s/oauth2/callback/%s", ac.hydraConfig.PublicURL, normalizeProviderName(provider.ProviderName)),
				"is_active":     provider.IsActive,
				"action": map[string]interface{}{
					"type": func() string {
						if existingProviderMap[provider.ProviderName] {
							return "updated"
						}
						return "created"
					}(),
				},
			})
		}
	}

	// Prepare response
	response := map[string]interface{}{
		"success":    true,
		"tenant_id":  req.TenantID,
		"org_id":     req.OrgID,
		"updated_at": time.Now(),
		"updated_by": req.UpdatedBy,
	}

	if updatedMainClient != nil {
		response["tenant_client"] = map[string]interface{}{
			"client_id":     updatedMainClient.ClientID,
			"client_name":   updatedMainClient.ClientName,
			"redirect_uris": updatedMainClient.RedirectURIs,
			"scopes":        strings.Split(updatedMainClient.Scope, " "),
			"updated":       true,
		}
	}

	if len(req.OIDCProviders) > 0 {
		response["oidc_providers"] = map[string]interface{}{
			"updated":       updatedProviders,
			"failed":        failedProviders,
			"success_count": len(updatedProviders),
			"failed_count":  len(failedProviders),
		}
	}

	statusCode := http.StatusOK
	message := "Tenant configuration updated successfully"

	if len(failedProviders) > 0 {
		if len(updatedProviders) == 0 {
			statusCode = http.StatusInternalServerError
			message = "Failed to update tenant configuration"
		} else {
			statusCode = http.StatusPartialContent
			message = "Tenant configuration partially updated"
		}
	}

	c.JSON(statusCode, dto.MessageResponse{
		Message:   message,
		Success:   len(updatedProviders) > 0 || updatedMainClient != nil,
		Data:      response,
		Timestamp: time.Now(),
	})
}

// Helper function to get OIDC providers for tenant (if not already exists)
func (ac *AuthController) getOIDCProvidersForTenant(tenantID string) ([]OIDCProvider, error) {
	// Get all Hydra clients
	clients, err := ac.getAllHydraClients()
	if err != nil {
		return nil, err
	}

	var providers []OIDCProvider

	// Find OIDC provider configs for this tenant
	for _, client := range clients {
		if clientTenantID, ok := client.Metadata["tenant_id"].(string); ok && clientTenantID == tenantID {
			if clientType, ok := client.Metadata["type"].(string); ok && clientType == "oidc_provider" {

				providerName, _ := client.Metadata["provider_name"].(string)
				displayName, _ := client.Metadata["display_name"].(string)
				isActive, _ := client.Metadata["is_active"].(bool)
				sortOrder, _ := client.Metadata["sort_order"].(float64)
				callbackURL, _ := client.Metadata["callback_url"].(string)
				providerConfig, _ := client.Metadata["provider_config"].(map[string]interface{})

				if providerName != "" {
					provider := OIDCProvider{
						ProviderName: providerName,
						DisplayName:  displayName,
						IsActive:     isActive,
						SortOrder:    int(sortOrder),
						CallbackURL:  callbackURL,
						Config:       providerConfig,
					}
					providers = append(providers, provider)
				}
			}
		}
	}

	return providers, nil
}

// Correct Multi-Tenant Architecture
// Add these endpoints to your auth_controller.go

// Step 1: Create Base Hydra Client for Tenant
func (ac *AuthController) CreateBaseTenantClient(c *gin.Context) {
	var req struct {
		TenantID     string   `json:"tenant_id" validate:"required"`
		OrgID        string   `json:"org_id" validate:"required"`
		TenantName   string   `json:"tenant_name" validate:"required"`
		RedirectURIs []string `json:"redirect_uris" validate:"required"`
		Scopes       []string `json:"scopes,omitempty"`
		CreatedBy    string   `json:"created_by"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:     "Invalid request",
			Message:   err.Error(),
			Code:      http.StatusBadRequest,
			Timestamp: time.Now(),
		})
		return
	}

	// Check if tenant client already exists
	mainClientID := fmt.Sprintf("%s-main-client", req.TenantID)
	existingClient, _ := ac.getHydraClient(mainClientID)
	if existingClient != nil {
		c.JSON(http.StatusConflict, dto.ErrorResponse{
			Error:     "Tenant client already exists",
			Message:   fmt.Sprintf("Tenant with ID %s already has a Hydra client", req.TenantID),
			Code:      http.StatusConflict,
			Timestamp: time.Now(),
		})
		return
	}

	// Set default scopes if not provided
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email", "offline_access"}
	}

	// Generate client secret
	clientSecret := fmt.Sprintf("tenant-secret-%d-%s", time.Now().Unix(), generateRandomString(16))

	// Create main tenant client in Hydra
	tenantClient := HydraClient{
		ClientID:      mainClientID,
		ClientName:    fmt.Sprintf("%s Main OAuth Client", req.TenantName),
		ClientSecret:  clientSecret,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		RedirectURIs:  req.RedirectURIs,
		TokenEndpoint: "client_secret_post",
		ResponseTypes: []string{"code"},
		Scope:         strings.Join(scopes, " "),
		Metadata: map[string]interface{}{
			"type":        "tenant_main_client",
			"tenant_id":   req.TenantID,
			"org_id":      req.OrgID,
			"tenant_name": req.TenantName,
			"created_at":  time.Now().Format(time.RFC3339),
			"created_by":  req.CreatedBy,
		},
	}

	if err := ac.createHydraClient(tenantClient); err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:     "Failed to create tenant client",
			Message:   err.Error(),
			Code:      http.StatusInternalServerError,
			Timestamp: time.Now(),
		})
		return
	}

	// Return the client credentials - SAVE THESE!
	c.JSON(http.StatusCreated, dto.MessageResponse{
		Message: "Tenant base client created successfully",
		Success: true,
		Data: map[string]interface{}{
			"tenant_id":     req.TenantID,
			"org_id":        req.OrgID,
			"tenant_name":   req.TenantName,
			"client_id":     mainClientID,
			"client_secret": clientSecret, // IMPORTANT: Save this!
			"redirect_uris": req.RedirectURIs,
			"scopes":        scopes,
			"created_at":    time.Now(),
		},
		Timestamp: time.Now(),
	})
}

// Step 2: Add OIDC Provider to Existing Tenant
func (ac *AuthController) AddOIDCProviderToTenant(c *gin.Context) {
	var req struct {
		TenantID  string             `json:"tenant_id" validate:"required"`
		OrgID     string             `json:"org_id" validate:"required"`
		Provider  OIDCProviderConfig `json:"provider" validate:"required"`
		CreatedBy string             `json:"created_by"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:     "Invalid request",
			Message:   err.Error(),
			Code:      http.StatusBadRequest,
			Timestamp: time.Now(),
		})
		return
	}

	// Verify tenant client exists
	mainClientID := fmt.Sprintf("%s-main-client", req.TenantID)
	tenantClient, err := ac.getHydraClient(mainClientID)
	if err != nil {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{
			Error:     "Tenant not found",
			Message:   fmt.Sprintf("No base client found for tenant %s. Create base client first.", req.TenantID),
			Code:      http.StatusNotFound,
			Timestamp: time.Now(),
		})
		return
	}

	// Create OIDC provider config as Hydra client metadata
	oidcClientID := fmt.Sprintf("%s-%s-oidc", req.TenantID, normalizeProviderName(req.Provider.ProviderName))

	// Check if provider already exists
	existingProvider, _ := ac.getHydraClient(oidcClientID)
	if existingProvider != nil {
		c.JSON(http.StatusConflict, dto.ErrorResponse{
			Error:     "Provider already exists",
			Message:   fmt.Sprintf("Provider %s already exists for tenant %s", req.Provider.ProviderName, req.TenantID),
			Code:      http.StatusConflict,
			Timestamp: time.Now(),
		})
		return
	}

	tenantName := tenantClient.Metadata["tenant_name"].(string)

	oidcClient := HydraClient{
		ClientID:   oidcClientID,
		ClientName: fmt.Sprintf("%s %s OIDC Config", tenantName, req.Provider.DisplayName),
		GrantTypes: []string{"client_credentials"}, // Just for storing config
		Metadata: map[string]interface{}{
			"type":          "oidc_provider",
			"tenant_id":     req.TenantID,
			"org_id":        req.OrgID,
			"provider_name": req.Provider.ProviderName,
			"display_name":  req.Provider.DisplayName,
			"provider_config": map[string]interface{}{
				"client_id":         req.Provider.ClientID,
				"client_secret":     req.Provider.ClientSecret,
				"auth_url":          req.Provider.AuthURL,
				"token_url":         req.Provider.TokenURL,
				"user_info_url":     req.Provider.UserInfoURL,
				"scopes":            req.Provider.Scopes,
				"issuer_url":        req.Provider.IssuerURL,
				"jwks_url":          req.Provider.JWKsURL,
				"additional_params": req.Provider.AdditionalParams,
			},
			"is_active":    req.Provider.IsActive,
			"sort_order":   req.Provider.SortOrder,
			"callback_url": fmt.Sprintf("%s/callback/%s", getEnv("OAUTH_LOGIN_SERVICE_URL", "http://localhost:8080"), normalizeProviderName(req.Provider.ProviderName)),
			"created_at":   time.Now().Format(time.RFC3339),
			"created_by":   req.CreatedBy,
		},
	}

	if err := ac.createHydraClient(oidcClient); err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:     "Failed to add OIDC provider",
			Message:   err.Error(),
			Code:      http.StatusInternalServerError,
			Timestamp: time.Now(),
		})
		return
	}

	// Store the OIDC provider mapping in database
	providerHydraClient := &dto.TenantHydraClient{
		OrgID:             req.OrgID,
		TenantID:          req.TenantID,
		TenantName:        tenantName,
		HydraClientID:     oidcClientID,
		HydraClientSecret: "not-used-for-oidc-config",
		ClientName:        fmt.Sprintf("%s %s OIDC Config", tenantName, req.Provider.DisplayName),
		ClientType:        "oidc_provider",
		ProviderName:      req.Provider.ProviderName,
		IsActive:          req.Provider.IsActive,
		CreatedBy:         req.CreatedBy,
	}

	if err := ac.tenantHydraClientRepo.Create(providerHydraClient); err != nil {
		log.Printf("Warning: Failed to store OIDC provider mapping for %s: %v", req.Provider.ProviderName, err)
	}

	c.JSON(http.StatusCreated, dto.MessageResponse{
		Message: "OIDC provider added successfully",
		Success: true,
		Data: map[string]interface{}{
			"tenant_id":     req.TenantID,
			"org_id":        req.OrgID,
			"provider_name": req.Provider.ProviderName,
			"display_name":  req.Provider.DisplayName,
			"client_id":     oidcClientID,
			"callback_url":  fmt.Sprintf("%s/callback/%s", getEnv("OAUTH_LOGIN_SERVICE_URL", "http://localhost:8080"), normalizeProviderName(req.Provider.ProviderName)),
			"is_active":     req.Provider.IsActive,
			"created_at":    time.Now(),
		},
		Timestamp: time.Now(),
	})
}

// Step 3: Get Tenant's Dynamic Login Page Data
func (ac *AuthController) GetTenantLoginPageData(c *gin.Context) {
	var req struct {
		TenantID string `json:"tenant_id" validate:"required"`
		OrgID    string `json:"org_id" validate:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:     "Invalid request",
			Message:   err.Error(),
			Code:      http.StatusBadRequest,
			Timestamp: time.Now(),
		})
		return
	}

	// Get tenant client
	mainClientID := fmt.Sprintf("%s-main-client", req.TenantID)
	tenantClient, err := ac.getHydraClient(mainClientID)
	if err != nil {
		c.JSON(http.StatusNotFound, dto.ErrorResponse{
			Error:     "Tenant not found",
			Message:   fmt.Sprintf("No client found for tenant %s", req.TenantID),
			Code:      http.StatusNotFound,
			Timestamp: time.Now(),
		})
		return
	}

	// Get all OIDC providers for this tenant
	providers, err := ac.getOIDCProvidersForTenant(req.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:     "Failed to get providers",
			Message:   err.Error(),
			Code:      http.StatusInternalServerError,
			Timestamp: time.Now(),
		})
		return
	}

	// Filter active providers and sort
	var activeProviders []map[string]interface{}
	for _, provider := range providers {
		if provider.IsActive {
			activeProviders = append(activeProviders, map[string]interface{}{
				"provider_name": provider.ProviderName,
				"display_name":  provider.DisplayName,
				"sort_order":    provider.SortOrder,
			})
		}
	}

	// Sort by sort_order
	sort.Slice(activeProviders, func(i, j int) bool {
		return activeProviders[i]["sort_order"].(int) < activeProviders[j]["sort_order"].(int)
	})

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message: "Login page data retrieved successfully",
		Success: true,
		Data: map[string]interface{}{
			"tenant_id":      req.TenantID,
			"org_id":         req.OrgID,
			"tenant_name":    tenantClient.Metadata["tenant_name"],
			"client_name":    tenantClient.ClientName,
			"main_client_id": tenantClient.ClientID,
			"providers":      activeProviders,
			"provider_count": len(activeProviders),
		},
		Timestamp: time.Now(),
	})
}

// Helper function to generate random string
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
func (ac *AuthController) GetTenantHydraClients(c *gin.Context) {
	var req struct {
		TenantID string `json:"tenant_id" validate:"required"`
		OrgID    string `json:"org_id" validate:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:     "Invalid request",
			Message:   err.Error(),
			Code:      http.StatusBadRequest,
			Timestamp: time.Now(),
		})
		return
	}

	clients, err := ac.tenantHydraClientRepo.GetByTenantID(req.TenantID, req.OrgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:     "Failed to get tenant clients",
			Message:   err.Error(),
			Code:      http.StatusInternalServerError,
			Timestamp: time.Now(),
		})
		return
	}

	// Separate main client and provider clients
	var mainClient *dto.TenantHydraClientResponse
	var providerClients []dto.TenantHydraClientResponse

	for _, client := range clients {
		resp := dto.TenantHydraClientResponse{
			ID:                client.ID,
			OrgID:             client.OrgID,
			TenantID:          client.TenantID,
			TenantName:        client.TenantName,
			HydraClientID:     client.HydraClientID,
			HydraClientSecret: client.HydraClientSecret,
			ClientName:        client.ClientName,
			RedirectURIs:      client.RedirectURIs,
			Scopes:            client.Scopes,
			ClientType:        client.ClientType,
			ProviderName:      client.ProviderName,
			IsActive:          client.IsActive,
			CreatedAt:         client.CreatedAt,
			UpdatedAt:         client.UpdatedAt,
			CreatedBy:         client.CreatedBy,
		}

		if client.ClientType == "main" {
			mainClient = &resp
		} else {
			providerClients = append(providerClients, resp)
		}
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message: "Tenant Hydra clients retrieved successfully",
		Success: true,
		Data: map[string]interface{}{
			"main_client":      mainClient,
			"provider_clients": providerClients,
			"total_clients":    len(clients),
		},
		Timestamp: time.Now(),
	})
}

// SyncHydraClients syncs Hydra clients with database mappings
func (ac *AuthController) SyncHydraClients(c *gin.Context) {
	var req struct {
		TenantID string `json:"tenant_id,omitempty"`
		OrgID    string `json:"org_id,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:     "Invalid request",
			Message:   err.Error(),
			Code:      http.StatusBadRequest,
			Timestamp: time.Now(),
		})
		return
	}

	// Get all Hydra clients
	hydraClients, err := ac.getAllHydraClients()
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:     "Failed to get Hydra clients",
			Message:   err.Error(),
			Code:      http.StatusInternalServerError,
			Timestamp: time.Now(),
		})
		return
	}

	syncedCount := 0
	missingCount := 0

	for _, hClient := range hydraClients {
		// Check if client exists in database
		_, err := ac.tenantHydraClientRepo.GetByHydraClientID(hClient.ClientID)
		if err != nil {
			// Client not in database, log it
			log.Printf("Hydra client %s not found in database mappings", hClient.ClientID)
			missingCount++
		} else {
			syncedCount++
		}
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message: "Hydra clients sync completed",
		Success: true,
		Data: map[string]interface{}{
			"total_hydra_clients": len(hydraClients),
			"synced_clients":      syncedCount,
			"missing_mappings":    missingCount,
		},
		Timestamp: time.Now(),
	})
}

func (ac *AuthController) ListTenantHydraClients(c *gin.Context) {
	var req dto.GetTenantHydraClientsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:     "Invalid request",
			Message:   err.Error(),
			Code:      http.StatusBadRequest,
			Timestamp: time.Now(),
		})
		return
	}

	clients, err := ac.tenantHydraClientRepo.ListAll(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:     "Failed to list clients",
			Message:   err.Error(),
			Code:      http.StatusInternalServerError,
			Timestamp: time.Now(),
		})
		return
	}

	// Convert to response format
	var responses []dto.TenantHydraClientResponse
	for _, client := range clients {
		resp := dto.TenantHydraClientResponse{
			ID:            client.ID,
			OrgID:         client.OrgID,
			TenantID:      client.TenantID,
			TenantName:    client.TenantName,
			HydraClientID: client.HydraClientID,
			ClientName:    client.ClientName,
			RedirectURIs:  client.RedirectURIs,
			Scopes:        client.Scopes,
			ClientType:    client.ClientType,
			ProviderName:  client.ProviderName,
			IsActive:      client.IsActive,
			CreatedAt:     client.CreatedAt,
			UpdatedAt:     client.UpdatedAt,
			CreatedBy:     client.CreatedBy,
		}

		// Only include secret if specifically requested
		if req.TenantID != "" && req.OrgID != "" {
			resp.HydraClientSecret = client.HydraClientSecret
		}

		responses = append(responses, resp)
	}

	c.JSON(http.StatusOK, dto.MessageResponse{
		Message:   "Hydra clients retrieved successfully",
		Success:   true,
		Data:      responses,
		Timestamp: time.Now(),
	})
}
