package db

import (
	"fmt"
	"log"
	"os"
)

type Config struct {
	Port                string
	DBName              string
	DBUser              string
	DBPassword          string
	DBHost              string
	DBPort              string
	DBSchema            string
	DatabaseURL         string
	JWTDefSecret        string
	JWTSdkSecret        string
	AuthManagerURL      string
	VaultAddr           string
	VaultToken          string
	HydraAdminURL       string
	HydraPublicURL      string
	IdentityProviderURL string
}

var AppConfig *Config

func LoadConfig() *Config {
	// Return existing config if already loaded
	if AppConfig != nil {
		return AppConfig
	}

	// Load individual database variables
	dbName := getEnv("DB_NAME", "authsec")
	dbUser := getEnv("DB_USER", "authsec")
	dbPassword := getEnv("DB_PASSWORD", "authsec")
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbSchema := getEnv("DB_SCHEMA", "public")

	// Construct DatabaseURL
	databaseURL := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable search_path=%s",
		dbHost, dbUser, dbPassword, dbName, dbPort, dbSchema,
	)

	err := os.Setenv("DATABASE_URL", databaseURL)
	if err != nil {
		fmt.Println("Error setting env var:", err)
	}

	// Load other configuration variables
	port := getEnv("PORT", "7468")
	jwtSdkSecret := getEnv("JWT_SDK_SECRET", "authsecai")
	jwtDefSecret := getEnv("JWT_DEF_SECRET", "authsecai")
	authManagerURL := getEnv("AUTH_MANAGER_URL", "http://localhost:7469")

	vaultAddr := getEnv("VAULT_ADDR", "http://localhost:8200")
	vaultToken := getEnv("VAULT_TOKEN", "")
	hydraAdminURL := getEnv("HYDRA_ADMIN_URL", "http://localhost:4445")
	hydraPublicURL := getEnv("HYDRA_PUBLIC_URL", "http://localhost:4444")
	identityProviderURL := getEnv("IDENTITY_PROVIDER_URL", "http://localhost:7469")

	// Validate critical variables
	if dbName == "" || dbUser == "" || dbHost == "" || dbPort == "" {
		log.Fatal("DB_NAME, DB_USER, DB_HOST, and DB_PORT are required")
	}
	if jwtDefSecret == "authsecai" {
		log.Println("Warning: Using default JWT_DEF_SECRET, which is insecure")
	}
	if jwtSdkSecret == "authsecai" {
		log.Println("Warning: Using default JWT_SDK_SECRET, which is insecure")
	}
	if port == "" {
		log.Fatal("PORT is required")
	}

	AppConfig = &Config{
		Port:                port,
		DBName:              dbName,
		DBUser:              dbUser,
		DBPassword:          dbPassword,
		DBHost:              dbHost,
		DBPort:              dbPort,
		DBSchema:            dbSchema,
		DatabaseURL:         databaseURL,
		JWTDefSecret:        jwtDefSecret,
		JWTSdkSecret:        jwtSdkSecret,
		AuthManagerURL:      authManagerURL,
		VaultAddr:           vaultAddr,
		VaultToken:          vaultToken,
		HydraAdminURL:       hydraAdminURL,
		HydraPublicURL:      hydraPublicURL,
		IdentityProviderURL: identityProviderURL,
	}

	return AppConfig
}

// ADD THIS: New getter function
func GetConfig() *Config {
	if AppConfig == nil {
		log.Fatal("Configuration not loaded. Call LoadConfig() first.")
	}
	return AppConfig
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		log.Printf("Loaded %s: %s", key, value)
		return value
	}
	log.Printf("Using fallback for %s: %s", key, fallback)
	return fallback
}
