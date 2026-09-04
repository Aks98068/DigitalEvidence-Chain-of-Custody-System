package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"forensix-backend/config"
	"forensix-backend/internal/models"
	"forensix-backend/internal/service"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	authService         *service.AuthService
	userService         *service.UserService
	caseService         *service.CaseService
	evidenceService     *service.EvidenceService
	notificationService *service.NotificationService
	dashboardService    *service.DashboardService
}

func NewHandler() *Handler {
	return &Handler{
		authService:         service.NewAuthService(),
		userService:         service.NewUserService(),
		caseService:         service.NewCaseService(),
		evidenceService:     service.NewEvidenceService(),
		notificationService: service.NewNotificationService(),
		dashboardService:    service.NewDashboardService(),
	}
}

func sanitizeUser(user *models.User) map[string]interface{} {
	if user == nil {
		return nil
	}
	return map[string]interface{}{
		"id":          user.ID,
		"username":    user.Username,
		"email":       user.Email,
		"role":        user.Role,
		"first_name":  user.FirstName,
		"last_name":   user.LastName,
		"phone":       user.Phone,
		"is_active":   user.IsActive,
		"created_at":  user.CreatedAt,
		"updated_at":  user.UpdatedAt,
	}
}

func (h *Handler) Register(c *gin.Context) {
	var req struct {
		Username  string  `json:"username" binding:"required"`
		Email     string  `json:"email" binding:"required,email"`
		Password  string  `json:"password" binding:"required"`
		Role      string  `json:"role" binding:"required"`
		FirstName *string `json:"first_name"`
		LastName  *string `json:"last_name"`
		Phone     *string `json:"phone"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, token, err := h.authService.Register(req.Username, req.Email, req.Password, req.Role, req.FirstName, req.LastName, req.Phone)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"user": sanitizeUser(user), "token": token})
}

func (h *Handler) Login(c *gin.Context) {
	var req struct {
		UsernameOrEmail string `json:"username_or_email" binding:"required"`
		Password        string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ip := c.ClientIP()
	ua := c.GetHeader("User-Agent")
	user, token, err := h.authService.Login(req.UsernameOrEmail, req.Password, &ip, &ua)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": sanitizeUser(user), "token": token})
}

func (h *Handler) Logout(c *gin.Context) {
	token, _ := c.Get("token")
	_ = h.authService.Logout(token.(string))
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func (h *Handler) GetCurrentUser(c *gin.Context) {
	user, _ := c.Get("user")
	c.JSON(http.StatusOK, sanitizeUser(user.(*models.User)))
}

func (h *Handler) ChangePassword(c *gin.Context) {
	user, _ := c.Get("user")
	u := user.(*models.User)
	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.authService.ChangePassword(u.ID, req.OldPassword, req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

func (h *Handler) ListUsers(c *gin.Context) {
	users, err := h.userService.ListUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, users)
}

func (h *Handler) GetUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	user, err := h.userService.GetUser(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	c.JSON(http.StatusOK, user)
}

func (h *Handler) UpdateUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	currentUser, _ := c.Get("user")
	user, err := h.userService.UpdateUser(id, updates, currentUser.(*models.User).ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, user)
}

func (h *Handler) AdminResetPassword(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req struct {
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	currentUser, _ := c.Get("user")
	if err := h.userService.ResetPassword(id, req.NewPassword, currentUser.(*models.User).ID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

func (h *Handler) CreateCase(c *gin.Context) {
	user, _ := c.Get("user")
	u := user.(*models.User)
	var req struct {
		Title        string  `json:"title" binding:"required"`
		Description  string  `json:"description"`
		IncidentType string  `json:"incident_type"`
		Priority     string  `json:"priority"`
		AssignedTo   int     `json:"assigned_to"`
		Notes        *string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	caseObj, err := h.caseService.CreateCase(req.Title, req.Description, req.IncidentType, req.Priority, req.AssignedTo, u.ID, req.Notes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, caseObj)
}

func (h *Handler) GetCase(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	user, _ := c.Get("user")
	u := user.(*models.User)
	allowed, err := h.caseService.CanAccessCase(u.ID, id)
	if err != nil || !allowed {
		caseObj, _ := h.caseService.GetCase(id)
		if caseObj == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Case not found"})
			return
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}
	caseObj, err := h.caseService.GetCase(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Case not found"})
		return
	}
	c.JSON(http.StatusOK, caseObj)
}

func (h *Handler) GetTimeline(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	user, _ := c.Get("user")
	u := user.(*models.User)
	allowed, _ := h.caseService.CanAccessCase(u.ID, id)
	if !allowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}
	timeline, err := h.caseService.GetTimeline(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, timeline)
}

func (h *Handler) ListCaseNotes(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	user, _ := c.Get("user")
	u := user.(*models.User)
	allowed, _ := h.caseService.CanAccessCase(u.ID, id)
	if !allowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}
	notes, err := h.caseService.ListCaseNotes(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, notes)
}

func (h *Handler) AddCaseNote(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	user, _ := c.Get("user")
	u := user.(*models.User)
	allowed, _ := h.caseService.CanAccessCase(u.ID, id)
	if !allowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}
	var req struct {
		Note string `json:"note" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	note, err := h.caseService.AddCaseNote(id, u.ID, req.Note)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_ = h.caseService.AddTimelineEvent(id, "NOTE_ADDED", "Note added to case", &models.JSONMap{"user_id": u.ID})
	c.JSON(http.StatusCreated, note)
}

func (h *Handler) UpdateCase(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	currentUser, _ := c.Get("user")
	u := currentUser.(*models.User)
	allowed, err := h.caseService.CanAccessCase(u.ID, id)
	if err != nil || !allowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}
	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	caseObj, err := h.caseService.UpdateCase(id, updates, u.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, caseObj)
}

func (h *Handler) ListCases(c *gin.Context) {
	includeArchived, _ := strconv.ParseBool(c.Query("include_archived"))
	search := c.Query("search")
	user, _ := c.Get("user")
	u := user.(*models.User)
	var cases []*models.InvestigationCase
	var err error
	if search != "" {
		cases, err = h.caseService.SearchCases(search)
	} else if u.Role == "Administrator" || u.Role == "EvidenceOfficer" {
		cases, err = h.caseService.ListCases(includeArchived)
	} else {
		cases, err = h.caseService.ListCasesByUser(u.ID)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, cases)
}

func (h *Handler) ListMyCases(c *gin.Context) {
	user, _ := c.Get("user")
	u := user.(*models.User)
	cases, err := h.caseService.ListCasesByUser(u.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, cases)
}

func (h *Handler) SearchCases(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "search query is required"})
		return
	}
	cases, err := h.caseService.SearchCases(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, cases)
}

func (h *Handler) UploadEvidence(c *gin.Context) {
	caseID, _ := strconv.Atoi(c.Param("caseId"))
	category := c.PostForm("category")
	if category == "" {
		category = "Document"
	}

	uploadDir := config.AppConfig.UploadDir
	_ = os.MkdirAll(uploadDir, 0755)

	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "multipart form required"})
		return
	}
	files := form.File["files"]
	if len(files) == 0 {
		files = append(files, c.Request.MultipartForm.File["file"]...)
	}
	if len(files) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no files uploaded"})
		return
	}

	user, _ := c.Get("user")
	u := user.(*models.User)

	var results []*models.Evidence
	for _, file := range files {
		safeFileName := filepath.Base(file.Filename)
		filePath := filepath.Join(uploadDir, safeFileName)
		dst, err := os.Create(filePath)
		if err != nil {
			continue
		}

		src, err := file.Open()
		if err != nil {
			dst.Close()
			continue
		}

		_, err = io.Copy(dst, src)
		src.Close()
		dst.Close()

		if err != nil {
			os.Remove(filePath)
			continue
		}

		hasher := sha256.New()
		if fileData, openErr := os.Open(filePath); openErr == nil {
			_, _ = io.Copy(hasher, fileData)
			fileData.Close()
		}
		sha256Hash := hex.EncodeToString(hasher.Sum(nil))

		metadata := make(models.JSONMap)
		if stat, statErr := os.Stat(filePath); statErr == nil {
			metadata["file_size_bytes"] = stat.Size()
			metadata["file_mode"] = stat.Mode().String()
		}
		metadata["file_extension"] = filepath.Ext(file.Filename)
		metadata["file_name"] = file.Filename
		metadata["content_type"] = file.Header.Get("Content-Type")

		evidence, err := h.evidenceService.UploadEvidence(caseID, file.Filename, filePath, category, file.Size, file.Header.Get("Content-Type"), sha256Hash, u.ID, &metadata)
		if err != nil {
			os.Remove(filePath)
			continue
		}
		results = append(results, evidence)
	}

	if len(results) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no valid files were uploaded"})
		return
	}

	c.JSON(http.StatusCreated, results)
}

func (h *Handler) GetEvidence(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	evidence, err := h.evidenceService.GetEvidence(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Evidence not found"})
		return
	}
	user, _ := c.Get("user")
	u := user.(*models.User)
	allowed, _ := h.caseService.CanAccessCase(u.ID, evidence.CaseID)
	if !allowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}
	c.JSON(http.StatusOK, evidence)
}

func (h *Handler) DownloadEvidence(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	evidence, err := h.evidenceService.GetEvidence(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Evidence not found"})
		return
	}
	user, _ := c.Get("user")
	u := user.(*models.User)
	allowed, _ := h.caseService.CanAccessCase(u.ID, evidence.CaseID)
	if !allowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}
	_ = h.evidenceService.RecordCustodyAction(evidence.ID, u.ID, "Access", nil, nil)
	c.FileAttachment(evidence.FilePath, evidence.FileName)
}

func (h *Handler) ListEvidenceByCase(c *gin.Context) {
	caseID, _ := strconv.Atoi(c.Param("caseId"))
	user, _ := c.Get("user")
	u := user.(*models.User)
	allowed, _ := h.caseService.CanAccessCase(u.ID, caseID)
	if !allowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}
	evidence, err := h.evidenceService.ListEvidenceByCase(caseID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, evidence)
}

func (h *Handler) GetChainOfCustody(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	evidence, err := h.evidenceService.GetEvidence(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Evidence not found"})
		return
	}
	user, _ := c.Get("user")
	u := user.(*models.User)
	allowed, _ := h.caseService.CanAccessCase(u.ID, evidence.CaseID)
	if !allowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}
	records, err := h.evidenceService.GetChainOfCustody(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, records)
}

func (h *Handler) VerifyEvidenceIntegrity(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	valid, err := h.evidenceService.VerifyIntegrity(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	user, _ := c.Get("user")
	u := user.(*models.User)
	ev, _ := h.evidenceService.GetEvidence(id)
	if ev == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Evidence not found"})
		return
	}
	allowed, _ := h.caseService.CanAccessCase(u.ID, ev.CaseID)
	if !allowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}
	_ = h.evidenceService.RecordCustodyAction(id, u.ID, "Verify", nil, nil)
	if !valid {
		c, _ := h.caseService.GetCase(ev.CaseID)
		if c != nil && c.AssignedTo != nil {
			_ = h.notificationService.CreateNotification(*c.AssignedTo, "Evidence Integrity Verification Failed", "Integrity verification failed for evidence "+ev.EvidenceID)
		}
	}
	c.JSON(http.StatusOK, gin.H{"valid": valid})
}

func (h *Handler) GenerateCaseReport(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	filePath, err := h.caseService.GenerateCaseReportPDF(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Header("Content-Disposition", "attachment; filename=case_report.pdf")
	c.File(filePath)
}

func (h *Handler) GenerateEvidenceIntegrityReport(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	filePath, err := h.evidenceService.GenerateEvidenceIntegrityReportPDF(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Header("Content-Disposition", "attachment; filename=evidence_integrity_report.pdf")
	c.File(filePath)
}

func (h *Handler) GenerateChainOfCustodyReport(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	filePath, err := h.evidenceService.GenerateChainOfCustodyReportPDF(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Header("Content-Disposition", "attachment; filename=chain_of_custody_report.pdf")
	c.File(filePath)
}

func (h *Handler) GetNotifications(c *gin.Context) {
	user, _ := c.Get("user")
	u := user.(*models.User)
	notifications, err := h.notificationService.GetUserNotifications(u.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, notifications)
}

func (h *Handler) MarkNotificationRead(c *gin.Context) {
	user, _ := c.Get("user")
	u := user.(*models.User)
	id, _ := strconv.Atoi(c.Param("id"))
	_ = h.notificationService.MarkAsRead(id, u.ID)
	c.JSON(http.StatusOK, gin.H{"message": "Marked as read"})
}

func (h *Handler) GetDashboardStats(c *gin.Context) {
	stats, err := h.dashboardService.GetStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, stats)
}

func (h *Handler) GetRoleDashboardStats(c *gin.Context) {
	user, _ := c.Get("user")
	u := user.(*models.User)
	stats, err := h.dashboardService.GetRoleDashboardStats(u.ID, u.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, stats)
}

func (h *Handler) GenerateAuditLogReport(c *gin.Context) {
	searchTerm := c.Query("search")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	filePath, err := h.userService.GenerateAuditLogReportPDF(searchTerm, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Header("Content-Disposition", "attachment; filename=audit_log_report.pdf")
	c.File(filePath)
}

func (h *Handler) SearchAuditLogs(c *gin.Context) {
	searchTerm := c.Query("search")
	limitStr := c.Query("limit")
	offsetStr := c.Query("offset")
	limit := 20
	offset := 0
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil {
			offset = o
		}
	}
	logs, err := h.userService.SearchAuditLogs(searchTerm, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, logs)
}

func (h *Handler) RequestPasswordReset(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = h.authService.RequestPasswordReset(req.Email)
	c.JSON(http.StatusOK, gin.H{"message": "If the email exists, a reset link has been sent"})
}

func (h *Handler) ResetPassword(c *gin.Context) {
	var req struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.authService.ResetPassword(req.Token, req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

func (h *Handler) UpdateMyProfile(c *gin.Context) {
	user, _ := c.Get("user")
	u := user.(*models.User)
	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updated, err := h.userService.UpdateUser(u.ID, updates, u.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, updated)
}

func (h *Handler) SearchEvidence(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "search query is required"})
		return
	}
	evidence, err := h.evidenceService.SearchEvidence(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, evidence)
}

func (h *Handler) GetFCI(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	fci, err := h.caseService.ComputeFCI(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, fci)
}
