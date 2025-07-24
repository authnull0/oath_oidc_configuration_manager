// src/models/dto/auth_models.go

// Updated DTOs for string-based IDs
package dto

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// ===== CUSTOM TYPES =====

// Custom JSONMap type for JSONB handling
type JSONMap map[string]interface{}

func (m JSONMap) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	ba, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return string(ba), nil
}

func (m *JSONMap) Scan(value interface{}) error {
	var ba []byte
	switch v := value.(type) {
	case []byte:
		ba = v
	case string:
		ba = []byte(v)
	case nil:
		return nil
	default:
		return fmt.Errorf("failed to unmarshal JSONB value: %v", value)
	}
	var t map[string]interface{}
	if err := json.Unmarshal(ba, &t); err != nil {
		return err
	}
	*m = JSONMap(t)
	return nil
}

func (m JSONMap) GormDataType() string {
	return "jsonb"
}

func (JSONMap) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	if db.Dialector.Name() == "postgres" {
		return "jsonb"
	}
	return "json"
}

// ===== MAIN ENTITY WITH STRING IDS =====

// OAuthOIDCConfiguration - Main configuration entity with string IDs
type OAuthOIDCConfiguration struct {
	ID          uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name        string     `json:"name" gorm:"not null;index"`
	OrgID       string     `json:"org_id" gorm:"not null;index"`    // Changed to string
	TenantID    string     `json:"tenant_id" gorm:"not null;index"` // Changed to string
	ConfigType  string     `json:"config_type" gorm:"not null"`
	ConfigFiles JSONMap    `json:"config_files" gorm:"type:jsonb"`
	IsActive    bool       `json:"is_active" gorm:"default:true"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"-" gorm:"index"`
	CreatedBy   string     `json:"created_by"`
	UpdatedBy   string     `json:"updated_by"`
}

func (OAuthOIDCConfiguration) TableName() string {
	return "oauth_oidc_configurations"
}

// Helper method to convert to response
func (c *OAuthOIDCConfiguration) ToResponse() *ConfigResponse {
	configFiles := make(map[string]interface{})
	for k, v := range c.ConfigFiles {
		configFiles[k] = v
	}

	return &ConfigResponse{
		ID:          c.ID,
		Name:        c.Name,
		OrgID:       c.OrgID,    // Now string
		TenantID:    c.TenantID, // Now string
		ConfigType:  c.ConfigType,
		ConfigFiles: configFiles,
		IsActive:    c.IsActive,
		CreatedAt:   c.CreatedAt,
		UpdatedAt:   c.UpdatedAt,
		CreatedBy:   c.CreatedBy,
		UpdatedBy:   c.UpdatedBy,
	}
}

// ===== CRUD REQUEST DTOs WITH STRING IDS =====

// CreateConfigRequest - Generic request for creating any configuration
type CreateConfigRequest struct {
	Name        string                 `json:"name" validate:"required"`
	OrgID       string                 `json:"org_id" validate:"required"`    // Changed to string
	TenantID    string                 `json:"tenant_id" validate:"required"` // Changed to string
	ConfigType  string                 `json:"config_type" validate:"required,oneof=local_auth oidc oauth_server webauthn_mfa saml2 entra_sync ad_sync"`
	ConfigFiles map[string]interface{} `json:"config_files" validate:"required"`
	IsActive    bool                   `json:"is_active"`
	CreatedBy   string                 `json:"created_by"`
}

// UpdateConfigRequest - Generic request for updating configurations
type UpdateConfigRequest struct {
	ID          uuid.UUID              `json:"id" validate:"required"`
	OrgID       string                 `json:"org_id" validate:"required"`    // Changed to string
	TenantID    string                 `json:"tenant_id" validate:"required"` // Changed to string
	Name        *string                `json:"name,omitempty"`
	ConfigFiles map[string]interface{} `json:"config_files,omitempty"`
	IsActive    *bool                  `json:"is_active,omitempty"`
	UpdatedBy   string                 `json:"updated_by"`
}

// GetConfigsRequest - Request for listing configurations with filters
type GetConfigsRequest struct {
	OrgID      string `json:"org_id" validate:"required"`    // Changed to string
	TenantID   string `json:"tenant_id" validate:"required"` // Changed to string
	Page       int    `json:"page"`
	Limit      int    `json:"limit"`
	ConfigType string `json:"config_type,omitempty"`
	ActiveOnly bool   `json:"active_only"`
}

// GetConfigByNameRequest - Request for getting configuration by name
type GetConfigByNameRequest struct {
	Name     string `json:"name" validate:"required"`
	OrgID    string `json:"org_id" validate:"required"`    // Changed to string
	TenantID string `json:"tenant_id" validate:"required"` // Changed to string
}

// GetConfigByIDRequest - Request for getting configuration by ID
type GetConfigByIDRequest struct {
	ID       uuid.UUID `json:"id" validate:"required"`
	OrgID    string    `json:"org_id" validate:"required"`    // Changed to string
	TenantID string    `json:"tenant_id" validate:"required"` // Changed to string
}

// DeleteConfigRequest - Request for deleting configuration
type DeleteConfigRequest struct {
	ID       uuid.UUID `json:"id" validate:"required"`
	OrgID    string    `json:"org_id" validate:"required"`    // Changed to string
	TenantID string    `json:"tenant_id" validate:"required"` // Changed to string
}

// ===== SPECIFIC CONFIGURATION REQUEST DTOs WITH STRING IDS =====

// ConfigureOIDCRequest - Request for configuring OIDC
type ConfigureOIDCRequest struct {
	Name       string     `json:"name" validate:"required"`
	OrgID      string     `json:"org_id" validate:"required"`    // Changed to string
	TenantID   string     `json:"tenant_id" validate:"required"` // Changed to string
	OIDCConfig OIDCConfig `json:"oidc_config" validate:"required"`
	IsActive   bool       `json:"is_active"`
	CreatedBy  string     `json:"created_by"`
}

// OIDC Configuration structs (unchanged)
type OIDCConfig struct {
	ClientID           string            `json:"client_id" validate:"required"`
	ClientSecret       string            `json:"client_secret" validate:"required"`
	Issuer             string            `json:"issuer,omitempty"`
	RedirectURL        string            `json:"redirect_url,omitempty"`
	PostLogoutURL      string            `json:"post_logout_url,omitempty"`
	Scopes             []string          `json:"scopes" validate:"required,min=1"`
	ProviderName       string            `json:"provider_name,omitempty"`
	ClaimMappings      map[string]string `json:"claim_mappings,omitempty"`
	EnablePKCE         bool              `json:"enable_pkce"`
	ResponseType       string            `json:"response_type,omitempty"`
	ResponseMode       string            `json:"response_mode,omitempty"`
	EnableNonce        bool              `json:"enable_nonce"`
	ClockSkew          int               `json:"clock_skew,omitempty"`
	EnableAutoUserSync bool              `json:"enable_auto_user_sync"`
	AuthURL            string            `json:"auth_url,omitempty"`
	TokenURL           string            `json:"token_url,omitempty"`
	UserInfoURL        string            `json:"user_info_url,omitempty"`
}

// ===== RESPONSE DTOs WITH STRING IDS =====

// ConfigResponse - Single configuration response
type ConfigResponse struct {
	ID          uuid.UUID              `json:"id"`
	Name        string                 `json:"name"`
	OrgID       string                 `json:"org_id"`    // Changed to string
	TenantID    string                 `json:"tenant_id"` // Changed to string
	ConfigType  string                 `json:"config_type"`
	ConfigFiles map[string]interface{} `json:"config_files"`
	IsActive    bool                   `json:"is_active"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	CreatedBy   string                 `json:"created_by"`
	UpdatedBy   string                 `json:"updated_by"`
}

// ConfigListResponse - List of configurations response
type ConfigListResponse struct {
	Configs    []*ConfigResponse `json:"configs"`
	Page       int               `json:"page"`
	Limit      int               `json:"limit"`
	Total      int64             `json:"total"`
	TotalPages int64             `json:"total_pages"`
}

// ===== ERROR AND SUCCESS RESPONSES =====

// ErrorResponse - Standard error response
type ErrorResponse struct {
	Error     string    `json:"error"`
	Message   string    `json:"message"`
	Code      int       `json:"code"`
	Timestamp time.Time `json:"timestamp"`
	RequestID string    `json:"request_id,omitempty"`
	Details   []string  `json:"details,omitempty"`
}

// MessageResponse - Standard success response
type MessageResponse struct {
	Message   string      `json:"message"`
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
	RequestID string      `json:"request_id,omitempty"`
}

// Custom JSONMap type for JSONB handling

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

// TenantHydraClient model - matches your tenant_hydra_clients table
// type TenantHydraClient struct {
// 	ID                uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
// 	OrgID             string    `json:"org_id" gorm:"not null"`
// 	TenantID          string    `json:"tenant_id" gorm:"not null"`
// 	HydraClientID     string    `json:"hydra_client_id" gorm:"not null;unique"`
// 	HydraClientSecret string    `json:"hydra_client_secret" gorm:"not null"`
// 	CreatedAt         time.Time `json:"created_at" gorm:"default:CURRENT_TIMESTAMP"`
// 	UpdatedAt         time.Time `json:"updated_at" gorm:"default:CURRENT_TIMESTAMP"`
// }

// func (TenantHydraClient) TableName() string {
// 	return "tenant_hydra_clients"
// }

// OIDC Configuration model for tenant databases
type OIDCConfiguration struct {
	ID          uuid.UUID              `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name        string                 `json:"name" gorm:"not null;index"`
	OrgID       string                 `json:"org_id" gorm:"not null;index"`    // Changed to string
	TenantID    string                 `json:"tenant_id" gorm:"not null;index"` // Changed to string
	ConfigType  string                 `json:"config_type" gorm:"not null"`
	ConfigFiles map[string]interface{} `json:"config_files" gorm:"type:jsonb"`
	IsActive    bool                   `json:"is_active" gorm:"default:true"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	DeletedAt   *time.Time             `json:"-" gorm:"index"`
	CreatedBy   string                 `json:"created_by"`
	UpdatedBy   string                 `json:"updated_by"`
}

func (OIDCConfiguration) TableName() string {
	return "oauth_oidc_configurations"
}

type GetTenantConfigsRequest struct {
	OrgID      uuid.UUID `json:"org_id" validate:"required"`
	TenantID   uuid.UUID `json:"tenant_id" validate:"required"`
	Page       int       `json:"page"`
	Limit      int       `json:"limit"`
	ActiveOnly bool      `json:"active_only"`
}

// GetConfigsByTypeRequest - Request for getting configurations by type
type GetConfigsByTypeRequest struct {
	OrgID      uuid.UUID `json:"org_id" validate:"required"`
	TenantID   uuid.UUID `json:"tenant_id" validate:"required"`
	ConfigType string    `json:"config_type" validate:"required"`
	ActiveOnly bool      `json:"active_only"`
}

// CheckTenantConfigRequest - Request for checking if tenant has specific config
type CheckTenantConfigRequest struct {
	OrgID      uuid.UUID `json:"org_id" validate:"required"`
	TenantID   uuid.UUID `json:"tenant_id" validate:"required"`
	ConfigType string    `json:"config_type" validate:"required"`
	ActiveOnly bool      `json:"active_only"`
}

// GetConfigStatsRequest - Request for getting configuration statistics
type GetConfigStatsRequest struct {
	OrgID    uuid.UUID `json:"org_id" validate:"required"`
	TenantID uuid.UUID `json:"tenant_id" validate:"required"`
}

// ActivateConfigRequest - Request for activating a configuration
type ActivateConfigRequest struct {
	ID        uuid.UUID `json:"id" validate:"required"`
	OrgID     uuid.UUID `json:"org_id" validate:"required"`
	TenantID  uuid.UUID `json:"tenant_id" validate:"required"`
	UpdatedBy string    `json:"updated_by"`
}

// BatchConfigUpdate - For batch update operations
type BatchConfigUpdate struct {
	ID         uuid.UUID              `json:"id" validate:"required"`
	UpdateData map[string]interface{} `json:"update_data" validate:"required"`
}

// ===== SPECIFIC CONFIGURATION REQUEST DTOs =====

// ConfigureLocalAuthRequest - Request for configuring local authentication
type ConfigureLocalAuthRequest struct {
	Name            string          `json:"name" validate:"required"`
	OrgID           uuid.UUID       `json:"org_id" validate:"required"`
	TenantID        uuid.UUID       `json:"tenant_id" validate:"required"`
	LocalAuthConfig LocalAuthConfig `json:"local_auth_config" validate:"required"`
	IsActive        bool            `json:"is_active"`
	CreatedBy       string          `json:"created_by"`
}

type ConfigureOAuthServerRequest struct {
	Name              string            `json:"name" validate:"required"`
	OrgID             uuid.UUID         `json:"org_id" validate:"required"`
	TenantID          uuid.UUID         `json:"tenant_id" validate:"required"`
	OAuthServerConfig OAuthServerConfig `json:"oauth_server_config" validate:"required"`
	IsActive          bool              `json:"is_active"`
	CreatedBy         string            `json:"created_by"`
}

// ConfigureWebAuthnMFARequest - Request for configuring WebAuthn MFA
type ConfigureWebAuthnMFARequest struct {
	Name              string            `json:"name" validate:"required"`
	OrgID             uuid.UUID         `json:"org_id" validate:"required"`
	TenantID          uuid.UUID         `json:"tenant_id" validate:"required"`
	WebAuthnMFAConfig WebAuthnMFAConfig `json:"webauthn_mfa_config" validate:"required"`
	IsActive          bool              `json:"is_active"`
	CreatedBy         string            `json:"created_by"`
}

// ConfigureSAML2Request - Request for configuring SAML2
type ConfigureSAML2Request struct {
	Name        string      `json:"name" validate:"required"`
	OrgID       uuid.UUID   `json:"org_id" validate:"required"`
	TenantID    uuid.UUID   `json:"tenant_id" validate:"required"`
	SAML2Config SAML2Config `json:"saml2_config" validate:"required"`
	IsActive    bool        `json:"is_active"`
	CreatedBy   string      `json:"created_by"`
}

// ConfigureEntraSyncRequest - Request for configuring Entra ID sync
type ConfigureEntraSyncRequest struct {
	Name            string          `json:"name" validate:"required"`
	OrgID           uuid.UUID       `json:"org_id" validate:"required"`
	TenantID        uuid.UUID       `json:"tenant_id" validate:"required"`
	EntraSyncConfig EntraSyncConfig `json:"entra_sync_config" validate:"required"`
	IsActive        bool            `json:"is_active"`
	CreatedBy       string          `json:"created_by"`
}

// ConfigureADSyncRequest - Request for configuring Active Directory sync
type ConfigureADSyncRequest struct {
	Name         string       `json:"name" validate:"required"`
	OrgID        uuid.UUID    `json:"org_id" validate:"required"`
	TenantID     uuid.UUID    `json:"tenant_id" validate:"required"`
	ADSyncConfig ADSyncConfig `json:"ad_sync_config" validate:"required"`
	IsActive     bool         `json:"is_active"`
	CreatedBy    string       `json:"created_by"`
}

// ===== CONFIGURATION STRUCTS (SEPARATE FOR CLARITY) =====

// LocalAuthConfig - Local authentication configuration
type LocalAuthConfig struct {
	EnableRegistration  bool           `json:"enable_registration"`
	RequireVerification bool           `json:"require_verification"`
	PasswordPolicy      PasswordPolicy `json:"password_policy" validate:"required"`
	SessionTimeout      int            `json:"session_timeout" validate:"required,min=5"` // minutes
	AllowPasswordReset  bool           `json:"allow_password_reset"`
	MaxLoginAttempts    int            `json:"max_login_attempts" validate:"min=3,max=10"`
	LockoutDuration     int            `json:"lockout_duration" validate:"min=5"` // minutes
	EnableRememberMe    bool           `json:"enable_remember_me"`
	RememberMeDuration  int            `json:"remember_me_duration" validate:"min=1440"` // minutes (24 hours minimum)
}

// PasswordPolicy - Password policy configuration
type PasswordPolicy struct {
	MinLength         int  `json:"min_length" validate:"required,min=6,max=128"`
	MaxLength         int  `json:"max_length" validate:"required,min=8,max=256"`
	RequireUpper      bool `json:"require_upper"`
	RequireLower      bool `json:"require_lower"`
	RequireNumbers    bool `json:"require_numbers"`
	RequireSymbols    bool `json:"require_symbols"`
	PreventReuse      bool `json:"prevent_reuse"`
	ReuseHistoryCount int  `json:"reuse_history_count" validate:"min=0,max=24"`
	MaxAge            int  `json:"max_age" validate:"min=0"` // days, 0 = no expiry
}

type OAuthServerConfig struct {
	ServerURL            string            `json:"server_url" validate:"required,url"`
	ClientID             string            `json:"client_id" validate:"required"`
	ClientSecret         string            `json:"client_secret" validate:"required"`
	GrantTypes           []string          `json:"grant_types" validate:"required,min=1"`
	TokenEndpoint        string            `json:"token_endpoint" validate:"required,url"`
	AuthEndpoint         string            `json:"auth_endpoint" validate:"required,url"`
	RevocationEndpoint   string            `json:"revocation_endpoint,omitempty"`
	IntrospectEndpoint   string            `json:"introspect_endpoint,omitempty"`
	UserinfoEndpoint     string            `json:"userinfo_endpoint,omitempty"`
	Scopes               []string          `json:"scopes" validate:"required,min=1"`
	RedirectURIs         []string          `json:"redirect_uris" validate:"required,min=1"`
	ClaimMappings        map[string]string `json:"claim_mappings,omitempty"`
	TokenLifetime        int               `json:"token_lifetime" validate:"min=300,max=86400"` // seconds
	RefreshTokenLifetime int               `json:"refresh_token_lifetime" validate:"min=3600"`  // seconds
	EnablePKCE           bool              `json:"enable_pkce"`
	RequireConsent       bool              `json:"require_consent"`
}

// WebAuthnMFAConfig - WebAuthn MFA configuration
type WebAuthnMFAConfig struct {
	RPDisplayName          string                 `json:"rp_display_name" validate:"required"`
	RPID                   string                 `json:"rp_id" validate:"required"`
	RPOrigin               string                 `json:"rp_origin" validate:"required,url"`
	RequireResident        bool                   `json:"require_resident"`
	UserVerification       string                 `json:"user_verification" validate:"required,oneof=required preferred discouraged"`
	Timeout                int                    `json:"timeout" validate:"required,min=30,max=300"` // seconds
	AttestationPreference  string                 `json:"attestation_preference" validate:"oneof=none indirect direct enterprise"`
	AuthenticatorSelection AuthenticatorSelection `json:"authenticator_selection"`
	AllowedCredentialTypes []string               `json:"allowed_credential_types"`
	EnableBackupEligible   bool                   `json:"enable_backup_eligible"`
	MaxCredentialsPerUser  int                    `json:"max_credentials_per_user" validate:"min=1,max=20"`
}

// AuthenticatorSelection - WebAuthn authenticator selection criteria
type AuthenticatorSelection struct {
	AuthenticatorAttachment string `json:"authenticator_attachment,omitempty" validate:"omitempty,oneof=platform cross-platform"`
	RequireResidentKey      bool   `json:"require_resident_key"`
	UserVerification        string `json:"user_verification" validate:"required,oneof=required preferred discouraged"`
}

// SAML2Config - SAML2 configuration
type SAML2Config struct {
	EntityID             string            `json:"entity_id" validate:"required"`
	SSOURL               string            `json:"sso_url" validate:"required,url"`
	SLOUrl               string            `json:"slo_url,omitempty"`
	Certificate          string            `json:"certificate" validate:"required"`
	PrivateKey           string            `json:"private_key,omitempty"`
	NameIDFormat         string            `json:"name_id_format" validate:"required"`
	SignRequests         bool              `json:"sign_requests"`
	WantAssertionsSigned bool              `json:"want_assertions_signed"`
	WantNameIDEncrypted  bool              `json:"want_name_id_encrypted"`
	SigningMethod        string            `json:"signing_method" validate:"oneof=rsa-sha1 rsa-sha256 rsa-sha512"`
	DigestMethod         string            `json:"digest_method" validate:"oneof=sha1 sha256 sha512"`
	AttributeMappings    map[string]string `json:"attribute_mappings,omitempty"`
	AllowedClockDrift    int               `json:"allowed_clock_drift" validate:"min=0,max=300"` // seconds
	SessionTimeout       int               `json:"session_timeout" validate:"min=300"`           // seconds
	EnableSingleLogout   bool              `json:"enable_single_logout"`
	ForceAuthn           bool              `json:"force_authn"`
	IsPassive            bool              `json:"is_passive"`
}

// EntraSyncConfig - Entra ID sync configuration
type EntraSyncConfig struct {
	TenantID          string            `json:"tenant_id" validate:"required"`
	ClientID          string            `json:"client_id" validate:"required"`
	ClientSecret      string            `json:"client_secret" validate:"required"`
	Authority         string            `json:"authority,omitempty"`
	GraphEndpoint     string            `json:"graph_endpoint,omitempty"`
	SyncInterval      int               `json:"sync_interval" validate:"required,min=15"` // minutes
	SyncGroups        []string          `json:"sync_groups,omitempty"`
	UserFilter        string            `json:"user_filter,omitempty"`
	GroupFilter       string            `json:"group_filter,omitempty"`
	AttributeMappings map[string]string `json:"attribute_mappings,omitempty"`
	EnableGroupSync   bool              `json:"enable_group_sync"`
	EnableUserSync    bool              `json:"enable_user_sync"`
	SyncDeletedUsers  bool              `json:"sync_deleted_users"`
	SyncDisabledUsers bool              `json:"sync_disabled_users"`
	BatchSize         int               `json:"batch_size" validate:"min=10,max=1000"`
	EnableDeltaSync   bool              `json:"enable_delta_sync"`
	MaxSyncErrors     int               `json:"max_sync_errors" validate:"min=1,max=100"`
}

// ADSyncConfig - Active Directory sync configuration
type ADSyncConfig struct {
	ServerAddress     string            `json:"server_address" validate:"required"`
	Port              int               `json:"port" validate:"required,min=1,max=65535"`
	Username          string            `json:"username" validate:"required"`
	Password          string            `json:"password" validate:"required"`
	BaseDN            string            `json:"base_dn" validate:"required"`
	UserFilter        string            `json:"user_filter,omitempty"`
	GroupFilter       string            `json:"group_filter,omitempty"`
	SyncInterval      int               `json:"sync_interval" validate:"required,min=15"` // minutes
	UseSSL            bool              `json:"use_ssl"`
	UseTLS            bool              `json:"use_tls"`
	SyncGroups        []string          `json:"sync_groups,omitempty"`
	AttributeMappings map[string]string `json:"attribute_mappings,omitempty"`
	EnableGroupSync   bool              `json:"enable_group_sync"`
	EnableUserSync    bool              `json:"enable_user_sync"`
	SyncDeletedUsers  bool              `json:"sync_deleted_users"`
	SyncDisabledUsers bool              `json:"sync_disabled_users"`
	BatchSize         int               `json:"batch_size" validate:"min=10,max=1000"`
	ConnectionTimeout int               `json:"connection_timeout" validate:"min=5,max=300"` // seconds
	SearchTimeout     int               `json:"search_timeout" validate:"min=5,max=300"`     // seconds
	MaxSyncErrors     int               `json:"max_sync_errors" validate:"min=1,max=100"`
	EnablePaging      bool              `json:"enable_paging"`
	PageSize          int               `json:"page_size" validate:"min=100,max=5000"`
}

type TenantConfigListResponse struct {
	Configs    []*ConfigResponse `json:"configs"`
	TenantID   uuid.UUID         `json:"tenant_id"`
	OrgID      uuid.UUID         `json:"org_id"`
	Page       int               `json:"page"`
	Limit      int               `json:"limit"`
	Total      int64             `json:"total"`
	TotalPages int64             `json:"total_pages"`
	ActiveOnly bool              `json:"active_only"`
}

// ConfigsByTypeResponse - Configurations by type response
type ConfigsByTypeResponse struct {
	Configs    []*ConfigResponse `json:"configs"`
	ConfigType string            `json:"config_type"`
	TenantID   uuid.UUID         `json:"tenant_id"`
	OrgID      uuid.UUID         `json:"org_id"`
	Count      int64             `json:"count"`
	ActiveOnly bool              `json:"active_only"`
}

// TenantConfigCheckResponse - Tenant configuration check response
type TenantConfigCheckResponse struct {
	HasConfig  bool      `json:"has_config"`
	Count      int64     `json:"count"`
	ConfigType string    `json:"config_type"`
	TenantID   uuid.UUID `json:"tenant_id"`
	OrgID      uuid.UUID `json:"org_id"`
	ActiveOnly bool      `json:"active_only"`
}

// ConfigStatsResponse - Configuration statistics response
type ConfigStatsResponse struct {
	TenantID uuid.UUID        `json:"tenant_id"`
	OrgID    uuid.UUID        `json:"org_id"`
	Total    int64            `json:"total"`
	Active   int64            `json:"active"`
	Inactive int64            `json:"inactive"`
	ByType   map[string]int64 `json:"by_type"`
}

// ConfigHealthResponse - Configuration health check response
type ConfigHealthResponse struct {
	ConfigID   uuid.UUID `json:"config_id"`
	ConfigName string    `json:"config_name"`
	ConfigType string    `json:"config_type"`
	IsHealthy  bool      `json:"is_healthy"`
	LastCheck  time.Time `json:"last_check"`
	ErrorMsg   string    `json:"error_msg,omitempty"`
}

// ConfigValidationResponse - Configuration validation response
type ConfigValidationResponse struct {
	IsValid  bool     `json:"is_valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// ConfigTestResponse - Configuration test response
type ConfigTestResponse struct {
	ConfigID   uuid.UUID `json:"config_id"`
	ConfigType string    `json:"config_type"`
	TestPassed bool      `json:"test_passed"`
	TestResult string    `json:"test_result"`
	ErrorMsg   string    `json:"error_msg,omitempty"`
	TestedAt   time.Time `json:"tested_at"`
}

// SyncStatusResponse - Sync status response for AD/Entra sync configurations
type SyncStatusResponse struct {
	ConfigID     uuid.UUID `json:"config_id"`
	ConfigName   string    `json:"config_name"`
	LastSync     time.Time `json:"last_sync"`
	NextSync     time.Time `json:"next_sync"`
	SyncStatus   string    `json:"sync_status"` // "running", "completed", "failed", "scheduled"
	UsersSync    int       `json:"users_synced"`
	GroupsSync   int       `json:"groups_synced"`
	ErrorsCount  int       `json:"errors_count"`
	LastErrorMsg string    `json:"last_error_msg,omitempty"`
	SyncDuration int       `json:"sync_duration"` // seconds
}

// ===== AUDIT AND LOGGING DTOs =====

// ConfigAuditLog - Configuration audit log entry
type ConfigAuditLog struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	ConfigID    uuid.UUID `json:"config_id" gorm:"type:uuid;not null;index"`
	Action      string    `json:"action" gorm:"not null"` // "created", "updated", "deleted", "activated", "deactivated"
	ChangedBy   string    `json:"changed_by" gorm:"not null"`
	ChangedAt   time.Time `json:"changed_at" gorm:"not null;default:now()"`
	OldValues   JSONMap   `json:"old_values,omitempty" gorm:"type:jsonb"`
	NewValues   JSONMap   `json:"new_values,omitempty" gorm:"type:jsonb"`
	IPAddress   string    `json:"ip_address,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	SessionID   string    `json:"session_id,omitempty"`
	Description string    `json:"description,omitempty"`
}

// ConfigAuditLogResponse - Configuration audit log response
type ConfigAuditLogResponse struct {
	ID          uuid.UUID              `json:"id"`
	ConfigID    uuid.UUID              `json:"config_id"`
	Action      string                 `json:"action"`
	ChangedBy   string                 `json:"changed_by"`
	ChangedAt   time.Time              `json:"changed_at"`
	OldValues   map[string]interface{} `json:"old_values,omitempty"`
	NewValues   map[string]interface{} `json:"new_values,omitempty"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	Description string                 `json:"description,omitempty"`
}

// ConfigAuditListResponse - Configuration audit log list response
type ConfigAuditListResponse struct {
	AuditLogs  []*ConfigAuditLogResponse `json:"audit_logs"`
	Page       int                       `json:"page"`
	Limit      int                       `json:"limit"`
	Total      int64                     `json:"total"`
	TotalPages int64                     `json:"total_pages"`
}

// ValidationErrorResponse - Validation error response
type ValidationErrorResponse struct {
	Error   string                  `json:"error"`
	Message string                  `json:"message"`
	Code    int                     `json:"code"`
	Errors  map[string][]string     `json:"validation_errors"`
	Details []ValidationErrorDetail `json:"details,omitempty"`
}

// ValidationErrorDetail - Detailed validation error
type ValidationErrorDetail struct {
	Field   string `json:"field"`
	Value   string `json:"value"`
	Message string `json:"message"`
	Tag     string `json:"tag"`
}

// ===== EXISTING MODELS FOR COMPATIBILITY =====

// TokenVerifyResponse - Token verification response (from your existing code)
type TokenVerifyResponse struct {
	Valid  bool      `json:"valid"`
	UserID uuid.UUID `json:"user_id"`
	Error  string    `json:"error,omitempty"`
}

// TokenVerifyRequest - Token verification request (from your existing code)
type TokenVerifyRequest struct {
	Token string `json:"token"`
}

// User - User entity (from your existing code)
type User struct {
	ID           uuid.UUID  `json:"id"`
	TenantID     uuid.UUID  `json:"tenant_id"`
	TenantDB     string     `json:"tenant_db"`
	Username     string     `json:"username"`
	Email        string     `json:"email"`
	FullName     string     `json:"full_name,omitempty"`
	PasswordHash string     `json:"password_hash,omitempty"` // Optional if you're not always storing
	Source       string     `json:"source,omitempty"`        // "manual", "ad", "entra_id"
	Status       string     `json:"status,omitempty"`        // "active", "inactive", "suspended"
	LastLogin    *time.Time `json:"last_login,omitempty"`    // pointer to allow NULL
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`

	DefaultClient *Client `json:"-" gorm:"-"`
}

// Client - Client entity (from your existing code)
type Client struct {
	ID        uuid.UUID  `json:"id" gorm:"primaryKey"`
	ClientID  uuid.UUID  `json:"client_id" gorm:"uniqueIndex;not null"`
	TenantID  uuid.UUID  `json:"tenant_id" gorm:"not null"`
	ProjectID uuid.UUID  `gorm:"not null;uniqueIndex"`
	Name      string     `json:"name"`
	Active    bool       `json:"active" gorm:"default:true"`
	Scopes    []Scope    `json:"scopes" gorm:"many2many:client_scopes;"`
	Roles     []Role     `json:"roles" gorm:"many2many:client_roles;"`
	Groups    []Group    `json:"groups" gorm:"many2many:client_groups;"`
	Resources []Resource `json:"resources" gorm:"many2many:client_resources;"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// Scope - Scope entity (from your existing code)
type Scope struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Name        string    `json:"name" gorm:"uniqueIndex;not null"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// Role - Role entity (from your existing code)
type Role struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Name        string    `json:"name" gorm:"uniqueIndex;not null"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// Group - Group entity (from your existing code)
type Group struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Name        string    `json:"name" gorm:"uniqueIndex;not null"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// Resource - Resource entity (from your existing code)
type Resource struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Name        string    `json:"name" gorm:"uniqueIndex;not null"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// ===== UTILITY DTOs =====

// HealthCheckResponse - Service health check response
type HealthCheckResponse struct {
	Status    string            `json:"status"`
	Service   string            `json:"service"`
	Version   string            `json:"version"`
	Timestamp time.Time         `json:"timestamp"`
	Checks    map[string]string `json:"checks,omitempty"`
}

// PaginationMeta - Pagination metadata for responses
type PaginationMeta struct {
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	Total      int64 `json:"total"`
	TotalPages int64 `json:"total_pages"`
	HasNext    bool  `json:"has_next"`
	HasPrev    bool  `json:"has_prev"`
}

// FilterCriteria - Generic filter criteria for queries
type FilterCriteria struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // "eq", "ne", "gt", "lt", "gte", "lte", "like", "in"
	Value    interface{} `json:"value"`
}

// SortCriteria - Generic sort criteria for queries
type SortCriteria struct {
	Field string `json:"field"`
	Order string `json:"order"` // "asc", "desc"
}

// AdvancedQueryRequest - Advanced query request with filters and sorting
type AdvancedQueryRequest struct {
	OrgID    uuid.UUID        `json:"org_id" validate:"required"`
	TenantID uuid.UUID        `json:"tenant_id" validate:"required"`
	Filters  []FilterCriteria `json:"filters,omitempty"`
	Sort     []SortCriteria   `json:"sort,omitempty"`
	Page     int              `json:"page"`
	Limit    int              `json:"limit"`
}

// BulkOperationRequest - Request for bulk operations
type BulkOperationRequest struct {
	OrgID     uuid.UUID   `json:"org_id" validate:"required"`
	TenantID  uuid.UUID   `json:"tenant_id" validate:"required"`
	Operation string      `json:"operation" validate:"required,oneof=activate deactivate delete"`
	ConfigIDs []uuid.UUID `json:"config_ids" validate:"required,min=1"`
	UpdatedBy string      `json:"updated_by"`
}

// BulkOperationResponse - Response for bulk operations
type BulkOperationResponse struct {
	Operation      string            `json:"operation"`
	TotalRequested int               `json:"total_requested"`
	Successful     int               `json:"successful"`
	Failed         int               `json:"failed"`
	Errors         map[string]string `json:"errors,omitempty"` // config_id -> error_message
	ProcessedAt    time.Time         `json:"processed_at"`
}

// ConfigImportRequest - Request for importing configurations
type ConfigImportRequest struct {
	OrgID          uuid.UUID          `json:"org_id" validate:"required"`
	TenantID       uuid.UUID          `json:"tenant_id" validate:"required"`
	Configurations []ConfigImportItem `json:"configurations" validate:"required,min=1"`
	OverwriteMode  string             `json:"overwrite_mode" validate:"oneof=skip overwrite merge"` // How to handle existing configs
	ValidateOnly   bool               `json:"validate_only"`                                        // Only validate, don't import
	CreatedBy      string             `json:"created_by"`
}

// ConfigImportItem - Individual configuration item for import
type ConfigImportItem struct {
	Name        string                 `json:"name" validate:"required"`
	ConfigType  string                 `json:"config_type" validate:"required"`
	ConfigFiles map[string]interface{} `json:"config_files" validate:"required"`
	IsActive    bool                   `json:"is_active"`
}

// ConfigImportResponse - Response for configuration import
type ConfigImportResponse struct {
	TotalConfigs    int                  `json:"total_configs"`
	ImportedConfigs int                  `json:"imported_configs"`
	SkippedConfigs  int                  `json:"skipped_configs"`
	FailedConfigs   int                  `json:"failed_configs"`
	ValidationOnly  bool                 `json:"validation_only"`
	Results         []ConfigImportResult `json:"results"`
	Summary         map[string]int       `json:"summary"` // config_type -> count
	ProcessedAt     time.Time            `json:"processed_at"`
}

// ConfigImportResult - Result for individual configuration import
type ConfigImportResult struct {
	Name       string    `json:"name"`
	ConfigType string    `json:"config_type"`
	Status     string    `json:"status"` // "imported", "skipped", "failed", "validated"
	ConfigID   uuid.UUID `json:"config_id,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// ConfigExportRequest - Request for exporting configurations
type ConfigExportRequest struct {
	OrgID       uuid.UUID   `json:"org_id" validate:"required"`
	TenantID    uuid.UUID   `json:"tenant_id" validate:"required"`
	ConfigTypes []string    `json:"config_types,omitempty"` // If empty, export all types
	ConfigIDs   []uuid.UUID `json:"config_ids,omitempty"`   // If specified, export only these configs
	ActiveOnly  bool        `json:"active_only"`
	Format      string      `json:"format" validate:"oneof=json yaml"` // Export format
}

// ConfigExportResponse - Response for configuration export
type ConfigExportResponse struct {
	Configurations []ConfigExportItem `json:"configurations"`
	ExportedAt     time.Time          `json:"exported_at"`
	TenantID       uuid.UUID          `json:"tenant_id"`
	OrgID          uuid.UUID          `json:"org_id"`
	TotalConfigs   int                `json:"total_configs"`
	Format         string             `json:"format"`
}

// ConfigExportItem - Individual configuration item for export
type ConfigExportItem struct {
	Name        string                 `json:"name"`
	ConfigType  string                 `json:"config_type"`
	ConfigFiles map[string]interface{} `json:"config_files"`
	IsActive    bool                   `json:"is_active"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	CreatedBy   string                 `json:"created_by"`
	UpdatedBy   string                 `json:"updated_by"`
}

// ===== WEBHOOK AND NOTIFICATION DTOs =====

// WebhookConfigRequest - Request for configuring webhooks
type WebhookConfigRequest struct {
	OrgID     uuid.UUID `json:"org_id" validate:"required"`
	TenantID  uuid.UUID `json:"tenant_id" validate:"required"`
	URL       string    `json:"url" validate:"required,url"`
	Events    []string  `json:"events" validate:"required,min=1"` // config.created, config.updated, etc.
	Secret    string    `json:"secret,omitempty"`
	IsActive  bool      `json:"is_active"`
	CreatedBy string    `json:"created_by"`
}

// WebhookEvent - Webhook event payload
type WebhookEvent struct {
	ID         uuid.UUID   `json:"id"`
	Event      string      `json:"event"`
	TenantID   uuid.UUID   `json:"tenant_id"`
	OrgID      uuid.UUID   `json:"org_id"`
	ConfigID   uuid.UUID   `json:"config_id"`
	ConfigType string      `json:"config_type"`
	Timestamp  time.Time   `json:"timestamp"`
	Data       interface{} `json:"data"`
	Signature  string      `json:"signature,omitempty"`
}

// NotificationPreferences - User notification preferences
type NotificationPreferences struct {
	OrgID           uuid.UUID `json:"org_id" validate:"required"`
	TenantID        uuid.UUID `json:"tenant_id" validate:"required"`
	UserID          uuid.UUID `json:"user_id" validate:"required"`
	EmailEnabled    bool      `json:"email_enabled"`
	SlackEnabled    bool      `json:"slack_enabled"`
	WebhookEnabled  bool      `json:"webhook_enabled"`
	Events          []string  `json:"events"` // Which events to notify about
	SlackWebhookURL string    `json:"slack_webhook_url,omitempty"`
}

// ===== ANALYTICS AND REPORTING DTOs =====

// ConfigUsageStats - Configuration usage statistics
type ConfigUsageStats struct {
	ConfigID        uuid.UUID `json:"config_id"`
	ConfigName      string    `json:"config_name"`
	ConfigType      string    `json:"config_type"`
	AuthAttempts    int64     `json:"auth_attempts"`
	SuccessfulAuths int64     `json:"successful_auths"`
	FailedAuths     int64     `json:"failed_auths"`
	LastUsed        time.Time `json:"last_used"`
	SuccessRate     float64   `json:"success_rate"`
}

// TenantUsageReport - Comprehensive tenant usage report
type TenantUsageReport struct {
	TenantID      uuid.UUID          `json:"tenant_id"`
	OrgID         uuid.UUID          `json:"org_id"`
	ReportPeriod  string             `json:"report_period"` // "daily", "weekly", "monthly"
	StartDate     time.Time          `json:"start_date"`
	EndDate       time.Time          `json:"end_date"`
	TotalConfigs  int                `json:"total_configs"`
	ActiveConfigs int                `json:"active_configs"`
	ConfigsByType map[string]int     `json:"configs_by_type"`
	UsageStats    []ConfigUsageStats `json:"usage_stats"`
	GeneratedAt   time.Time          `json:"generated_at"`
}

// SecurityAuditRequest - Request for security audit
type SecurityAuditRequest struct {
	OrgID     uuid.UUID `json:"org_id" validate:"required"`
	TenantID  uuid.UUID `json:"tenant_id" validate:"required"`
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
	Severity  string    `json:"severity,omitempty" validate:"omitempty,oneof=low medium high critical"`
}

// SecurityAuditResponse - Security audit response
type SecurityAuditResponse struct {
	TenantID    uuid.UUID            `json:"tenant_id"`
	OrgID       uuid.UUID            `json:"org_id"`
	AuditPeriod string               `json:"audit_period"`
	Issues      []SecurityIssue      `json:"issues"`
	Summary     SecurityAuditSummary `json:"summary"`
	GeneratedAt time.Time            `json:"generated_at"`
}

// SecurityIssue - Individual security issue
type SecurityIssue struct {
	ID             uuid.UUID `json:"id"`
	ConfigID       uuid.UUID `json:"config_id"`
	ConfigName     string    `json:"config_name"`
	ConfigType     string    `json:"config_type"`
	Severity       string    `json:"severity"`
	IssueType      string    `json:"issue_type"`
	Description    string    `json:"description"`
	Recommendation string    `json:"recommendation"`
	DetectedAt     time.Time `json:"detected_at"`
}

// SecurityAuditSummary - Summary of security audit
type SecurityAuditSummary struct {
	TotalIssues    int            `json:"total_issues"`
	BySeverity     map[string]int `json:"by_severity"`
	ByConfigType   map[string]int `json:"by_config_type"`
	ResolvedIssues int            `json:"resolved_issues"`
	OpenIssues     int            `json:"open_issues"`
}

// ===== SYSTEM CONFIGURATION DTOs =====

// SystemSettings - System-wide settings
type SystemSettings struct {
	ID                    uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	OrgID                 uuid.UUID `json:"org_id" gorm:"type:uuid;not null;index"`
	TenantID              uuid.UUID `json:"tenant_id" gorm:"type:uuid;not null;index"`
	MaxConfigsPerTenant   int       `json:"max_configs_per_tenant"`
	DefaultSessionTimeout int       `json:"default_session_timeout"`
	EnableAuditLogging    bool      `json:"enable_audit_logging"`
	EnableWebhooks        bool      `json:"enable_webhooks"`
	EnableNotifications   bool      `json:"enable_notifications"`
	RetentionPeriodDays   int       `json:"retention_period_days"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
	UpdatedBy             string    `json:"updated_by"`
}
