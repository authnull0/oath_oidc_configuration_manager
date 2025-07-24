package dto

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// TenantHydraClient model for tracking Hydra clients
type TenantHydraClient struct {
	ID                uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	OrgID             string         `json:"org_id" gorm:"not null;index"`
	TenantID          string         `json:"tenant_id" gorm:"not null;index"`
	TenantName        string         `json:"tenant_name" gorm:"not null"`
	HydraClientID     string         `json:"hydra_client_id" gorm:"not null;unique"`
	HydraClientSecret string         `json:"hydra_client_secret" gorm:"not null"`
	ClientName        string         `json:"client_name" gorm:"not null"`
	RedirectURIs      pq.StringArray `json:"redirect_uris" gorm:"type:jsonb;default:'[]'"`
	Scopes            pq.StringArray `json:"scopes" gorm:"type:text[];default:'{openid,profile,email}'"`
	ClientType        string         `json:"client_type" gorm:"not null"` // 'main' or 'oidc_provider'
	ProviderName      string         `json:"provider_name,omitempty"`
	IsActive          bool           `json:"is_active" gorm:"default:true"`
	CreatedAt         time.Time      `json:"created_at" gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt         time.Time      `json:"updated_at" gorm:"default:CURRENT_TIMESTAMP"`
	CreatedBy         string         `json:"created_by" gorm:"default:'system'"`
}

func (TenantHydraClient) TableName() string {
	return "tenant_hydra_clients"
}

// CreateTenantHydraClientRequest for API
type CreateTenantHydraClientRequest struct {
	OrgID             string   `json:"org_id" validate:"required"`
	TenantID          string   `json:"tenant_id" validate:"required"`
	TenantName        string   `json:"tenant_name" validate:"required"`
	HydraClientID     string   `json:"hydra_client_id" validate:"required"`
	HydraClientSecret string   `json:"hydra_client_secret" validate:"required"`
	ClientName        string   `json:"client_name" validate:"required"`
	RedirectURIs      []string `json:"redirect_uris" validate:"required"`
	Scopes            []string `json:"scopes"`
	ClientType        string   `json:"client_type" validate:"required,oneof=main oidc_provider"`
	ProviderName      string   `json:"provider_name,omitempty"`
	CreatedBy         string   `json:"created_by"`
}

// TenantHydraClientResponse for API responses
type TenantHydraClientResponse struct {
	ID                uuid.UUID `json:"id"`
	OrgID             string    `json:"org_id"`
	TenantID          string    `json:"tenant_id"`
	TenantName        string    `json:"tenant_name"`
	HydraClientID     string    `json:"hydra_client_id"`
	HydraClientSecret string    `json:"hydra_client_secret,omitempty"` // Omit in list views
	ClientName        string    `json:"client_name"`
	RedirectURIs      []string  `json:"redirect_uris"`
	Scopes            []string  `json:"scopes"`
	ClientType        string    `json:"client_type"`
	ProviderName      string    `json:"provider_name,omitempty"`
	IsActive          bool      `json:"is_active"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	CreatedBy         string    `json:"created_by"`
}

// GetTenantHydraClientsRequest for listing
type GetTenantHydraClientsRequest struct {
	OrgID      string `json:"org_id,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
	ClientType string `json:"client_type,omitempty"`
	IsActive   *bool  `json:"is_active,omitempty"`
}
