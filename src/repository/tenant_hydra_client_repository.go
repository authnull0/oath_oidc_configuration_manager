package repository

import (
	"fmt"
	"oath_oidc_configuration_manager/src/db"
	"oath_oidc_configuration_manager/src/dto"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type TenantHydraClientRepository struct {
	masterDB *gorm.DB
}

func NewTenantHydraClientRepository() *TenantHydraClientRepository {
	return &TenantHydraClientRepository{
		masterDB: db.DB,
	}
}

// Create saves a new tenant-hydra client mapping
func (r *TenantHydraClientRepository) Create(client *dto.TenantHydraClient) error {
	if err := r.masterDB.Create(client).Error; err != nil {
		return fmt.Errorf("failed to create tenant hydra client mapping: %w", err)
	}
	return nil
}

// GetByTenantID retrieves all Hydra clients for a tenant
func (r *TenantHydraClientRepository) GetByTenantID(tenantID, orgID string) ([]*dto.TenantHydraClient, error) {
	var clients []*dto.TenantHydraClient

	query := r.masterDB.Where("tenant_id = ? AND org_id = ?", tenantID, orgID)

	if err := query.Find(&clients).Error; err != nil {
		return nil, fmt.Errorf("failed to get tenant hydra clients: %w", err)
	}

	return clients, nil
}

// GetByHydraClientID retrieves mapping by Hydra client ID
func (r *TenantHydraClientRepository) GetByHydraClientID(hydraClientID string) (*dto.TenantHydraClient, error) {
	var client dto.TenantHydraClient

	if err := r.masterDB.Where("hydra_client_id = ?", hydraClientID).First(&client).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("client not found")
		}
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	return &client, nil
}

// GetMainClient retrieves the main OAuth client for a tenant
func (r *TenantHydraClientRepository) GetMainClient(tenantID, orgID string) (*dto.TenantHydraClient, error) {
	var client dto.TenantHydraClient

	if err := r.masterDB.Where("tenant_id = ? AND org_id = ? AND client_type = ?",
		tenantID, orgID, "main").First(&client).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("main client not found for tenant")
		}
		return nil, fmt.Errorf("failed to get main client: %w", err)
	}

	return &client, nil
}

// GetProviderClients retrieves all OIDC provider clients for a tenant
func (r *TenantHydraClientRepository) GetProviderClients(tenantID, orgID string) ([]*dto.TenantHydraClient, error) {
	var clients []*dto.TenantHydraClient

	query := r.masterDB.Where("tenant_id = ? AND org_id = ? AND client_type = ?",
		tenantID, orgID, "oidc_provider")

	if err := query.Find(&clients).Error; err != nil {
		return nil, fmt.Errorf("failed to get provider clients: %w", err)
	}

	return clients, nil
}

// Update updates a client mapping
func (r *TenantHydraClientRepository) Update(id uuid.UUID, updates map[string]interface{}) error {
	if err := r.masterDB.Model(&dto.TenantHydraClient{}).
		Where("id = ?", id).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to update client mapping: %w", err)
	}
	return nil
}

// Delete soft deletes a client mapping
func (r *TenantHydraClientRepository) Delete(id uuid.UUID) error {
	if err := r.masterDB.Where("id = ?", id).Delete(&dto.TenantHydraClient{}).Error; err != nil {
		return fmt.Errorf("failed to delete client mapping: %w", err)
	}
	return nil
}

// DeleteByHydraClientID deletes by Hydra client ID
func (r *TenantHydraClientRepository) DeleteByHydraClientID(hydraClientID string) error {
	if err := r.masterDB.Where("hydra_client_id = ?", hydraClientID).
		Delete(&dto.TenantHydraClient{}).Error; err != nil {
		return fmt.Errorf("failed to delete client mapping: %w", err)
	}
	return nil
}

// ListAll lists all tenant hydra clients with optional filters
func (r *TenantHydraClientRepository) ListAll(req *dto.GetTenantHydraClientsRequest) ([]*dto.TenantHydraClient, error) {
	var clients []*dto.TenantHydraClient

	query := r.masterDB.Model(&dto.TenantHydraClient{})

	if req.OrgID != "" {
		query = query.Where("org_id = ?", req.OrgID)
	}

	if req.TenantID != "" {
		query = query.Where("tenant_id = ?", req.TenantID)
	}

	if req.ClientType != "" {
		query = query.Where("client_type = ?", req.ClientType)
	}

	if req.IsActive != nil {
		query = query.Where("is_active = ?", *req.IsActive)
	}

	if err := query.Order("created_at DESC").Find(&clients).Error; err != nil {
		return nil, fmt.Errorf("failed to list clients: %w", err)
	}

	return clients, nil
}
