package main

import (
	"log"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"forensix-backend/config"
	"forensix-backend/internal/handlers"
	"forensix-backend/internal/middleware"
	"forensix-backend/internal/repository"
)

func getMigrationsDir() string {
	if _, err := os.Stat("migrations"); err == nil {
		return "migrations"
	}
	if _, err := os.Stat("../migrations"); err == nil {
		return "../migrations"
	}
	return "migrations"
}

func main() {
	config.LoadConfig()

	if err := repository.InitDB(); err != nil {
		log.Fatal("Failed to connect to database: ", err)
	}

	if err := repository.RunMigrations(repository.DB, getMigrationsDir()); err != nil {
		log.Fatal("Failed to run migrations: ", err)
	}

	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000", "http://127.0.0.1:3000", "http://[::1]:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	h := handlers.NewHandler()

	// Public routes
	public := r.Group("/api/auth")
	{
		public.POST("/register", h.Register)
		public.POST("/login", h.Login)
		public.POST("/request-password-reset", h.RequestPasswordReset)
		public.POST("/reset-password", h.ResetPassword)
	}

	// Protected routes
	api := r.Group("/api")
	api.Use(middleware.AuthMiddleware())
	{
		api.POST("/logout", h.Logout)
		api.GET("/me", h.GetCurrentUser)
		api.PUT("/change-password", h.ChangePassword)
		api.PUT("/profile", h.UpdateMyProfile)

		// Users
		users := api.Group("/users")
		users.Use(middleware.RoleMiddleware("Administrator"))
		{
			users.GET("", h.ListUsers)
			users.GET("/:id", h.GetUser)
			users.PUT("/:id", h.UpdateUser)
			users.POST("/:id/reset-password", h.AdminResetPassword)
		}

		// Audit Logs
		auditLogs := api.Group("/audit-logs")
		auditLogs.Use(middleware.RoleMiddleware("Administrator"))
		{
			auditLogs.GET("", h.SearchAuditLogs)
			auditLogs.GET("/report", h.GenerateAuditLogReport)
		}

		// Cases
		cases := api.Group("/cases")
		{
		cases.GET("", h.ListCases)
		cases.GET("/my", h.ListMyCases)
		cases.GET("/search", h.SearchCases)
			cases.GET("/:id", h.GetCase)
			cases.GET("/:id/timeline", h.GetTimeline)
			cases.GET("/:id/report", h.GenerateCaseReport)
			cases.GET("/:id/notes", h.ListCaseNotes)
			cases.POST("/:id/notes", h.AddCaseNote)
			cases.GET("/:id/fci", h.GetFCI)
			cases.POST("", h.CreateCase)
			cases.PUT("/:id", h.UpdateCase)

		// Evidence
		evidence := cases.Group("/:id/evidence")
		evidence.Use(middleware.RoleMiddleware("Administrator", "EvidenceOfficer", "Investigator"))
		{
			evidence.GET("", h.ListEvidenceByCase)
			evidence.POST("/upload", h.UploadEvidence)
		}
		}

		// Evidence
		evidence := api.Group("/evidence")
		evidence.Use(middleware.RoleMiddleware("Administrator", "EvidenceOfficer", "Investigator"))
		{
			evidence.GET("/:id", h.GetEvidence)
			evidence.GET("/:id/download", h.DownloadEvidence)
			evidence.GET("/:id/custody", h.GetChainOfCustody)
			evidence.GET("/:id/custody/report", h.GenerateChainOfCustodyReport)
			evidence.GET("/:id/integrity/report", h.GenerateEvidenceIntegrityReport)
			evidence.POST("/:id/verify", h.VerifyEvidenceIntegrity)
		}

		evidence.GET("/search", h.SearchEvidence)

		// Notifications
		notifications := api.Group("/notifications")
		{
			notifications.GET("", h.GetNotifications)
			notifications.PUT("/:id/read", h.MarkNotificationRead)
		}

		// Dashboard
		api.GET("/dashboard/stats", h.GetDashboardStats)
		api.GET("/dashboard/role-stats", h.GetRoleDashboardStats)
	}

	log.Printf("Server starting on :%s", config.AppConfig.Port)
	if err := r.Run(":" + config.AppConfig.Port); err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}
