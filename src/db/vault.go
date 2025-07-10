package db

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/vault/api"
)

var VaultClient *api.Client

func InitVault(cfg *Config) error {
	config := api.DefaultConfig()

	vaultAddr := cfg.VaultAddr
	if vaultAddr != "" {
		config.Address = vaultAddr
	} else {
		// Default to localhost for development
		config.Address = "http://localhost:8200"
	}

	var err error
	VaultClient, err = api.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %w", err)
	}

	// Set token if provided
	vaultToken := cfg.VaultToken
	if vaultToken != "" {
		VaultClient.SetToken(vaultToken)
		log.Printf("Vault token set: %s", maskToken(vaultToken))
	} else {
		log.Println("Warning: No Vault token provided")
	}

	// Test the connection to ensure Vault is actually running
	if err := testVaultConnection(cfg); err != nil {
		return fmt.Errorf("failed to connect to Vault: %w", err)
	}

	log.Println("Vault client initialized and connected successfully")
	return nil
}

// testVaultConnection verifies that Vault is running and accessible
func testVaultConnection(cfg *Config) error {
	if VaultClient == nil {
		return fmt.Errorf("vault client is nil")
	}

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Printf("Testing connection to Vault at: %s", VaultClient.Address())

	// Try to get Vault health status
	resp, err := VaultClient.Sys().HealthWithContext(ctx)
	if err != nil {
		return fmt.Errorf("vault health check failed: %w", err)
	}

	if resp == nil {
		return fmt.Errorf("vault health response is nil")
	}

	log.Printf("Vault health status: initialized=%t, sealed=%t", resp.Initialized, resp.Sealed)

	// Check if Vault is sealed
	if resp.Sealed {
		return fmt.Errorf("vault is sealed")
	}

	// Additional check: try to authenticate if token is provided
	if cfg.VaultToken != "" {
		// Try to lookup self to verify token is valid
		tokenInfo, err := VaultClient.Auth().Token().LookupSelfWithContext(ctx)
		if err != nil {
			return fmt.Errorf("vault token validation failed: %w", err)
		}

		if tokenInfo != nil && tokenInfo.Data != nil {
			if policies, ok := tokenInfo.Data["policies"].([]interface{}); ok {
				log.Printf("Token validated successfully. Policies: %v", policies)
			}
		}
	}

	return nil
}

// maskToken returns a masked version of the token for logging
func maskToken(token string) string {
	if len(token) <= 8 {
		return "***"
	}
	return token[:4] + "..." + token[len(token)-4:]
}

// GetSecretData extracts data from KV v2 secret response
func GetSecretData(secret *api.Secret) (map[string]interface{}, error) {
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("secret is nil or empty")
	}

	// For KV v2, the actual data is nested under "data" key
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("secret data is not in expected KV v2 format")
	}

	return data, nil
}

// HealthCheck performs a quick health check on the Vault connection
func HealthCheck() error {
	if VaultClient == nil {
		return fmt.Errorf("vault client not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := VaultClient.Sys().HealthWithContext(ctx)
	if err != nil {
		return fmt.Errorf("vault health check failed: %w", err)
	}

	if resp.Sealed {
		return fmt.Errorf("vault is sealed")
	}

	return nil
}

// SaveSecretToVault saves a secret to Vault under the specified tenant and project
func SaveSecretToVault(tenantID, projectID, clientID uuid.UUID) (string, error) {
	if VaultClient == nil {
		return "", fmt.Errorf("vault client not initialized")
	}

	// Debug: Check if we can access Vault (same as read function)
	tokenInfo, err := VaultClient.Auth().Token().LookupSelf()
	if err != nil {
		fmt.Printf("Token lookup failed: %v\n", err)
		return "", fmt.Errorf("failed to lookup token: %w", err)
	}
	fmt.Printf("Using token with policies: %v\n", tokenInfo.Data["policies"])

	secretID := uuid.New().String()

	// Use EXACTLY the same path format as your working read function
	secretPath := fmt.Sprintf("kv/data/secret/%s/%s/%s", tenantID.String(), projectID.String(), clientID.String())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// For KV v2 Logical API, data must be wrapped under "data" key
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"secret_id": secretID,
		},
	}

	// Use Logical API (same as read function) instead of KVv2 API
	_, err = VaultClient.Logical().WriteWithContext(ctx, secretPath, requestData)
	if err != nil {
		fmt.Printf("Error writing secret to Vault at path %s: %v\n", secretPath, err)
		return "", fmt.Errorf("failed to write secret to Vault at path %s: %w", secretPath, err)
	}

	log.Printf("Successfully saved secret %s to Vault", secretID)
	return secretID, nil
}
