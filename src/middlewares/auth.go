package middlewares

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"oath_oidc_configuration_manager/src/db"
	"oath_oidc_configuration_manager/src/dto"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header"})
			c.Abort()
			return
		}

		// Prepare request to internal auth service
		token := parts[1]
		requestBody, err := json.Marshal(dto.TokenVerifyRequest{Token: token})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare token verification request"})
			c.Abort()
			return
		}

		// Make HTTP request to internal auth service
		authManagerURL := db.AppConfig.AuthManagerURL + "/authmgr/verifyToken"
		resp, err := http.Post(authManagerURL, "application/json", bytes.NewBuffer(requestBody))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to contact auth service"})
			c.Abort()
			return
		}
		defer resp.Body.Close()

		// Parse response
		var verifyResponse dto.TokenVerifyResponse
		if err := json.NewDecoder(resp.Body).Decode(&verifyResponse); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse auth service response"})
			c.Abort()
			return
		}

		// Check if token is valid
		if !verifyResponse.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": verifyResponse.Error})
			c.Abort()
			return
		}

		// Set user_id in context
		c.Set("user_id", verifyResponse.UserID)
		c.Next()
	}
}
