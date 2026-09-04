package middleware

import (
	"net/http"
	"strings"

	"forensix-backend/internal/models"
	"forensix-backend/internal/service"

	"github.com/gin-gonic/gin"
)

var authService = service.NewAuthService()

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		user, err := authService.ValidateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		c.Set("user", user)
		c.Set("token", token)
		c.Next()
	}
}

func RoleMiddleware(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		u, ok := user.(*models.User)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user"})
			c.Abort()
			return
		}

		allowed := false
		for _, r := range allowedRoles {
			if r == u.Role {
				allowed = true
				break
			}
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}
