package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"forensix-backend/internal/models"
	"forensix-backend/internal/repository"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type CaseService struct {
	caseRepo         *repository.CaseRepository
	caseNoteRepo     *repository.CaseNoteRepository
	evidenceRepo     *repository.EvidenceRepository
	custodyRepo      *repository.ChainOfCustodyRepository
	auditRepo        *repository.AuditLogRepository
	notificationRepo *repository.NotificationRepository
	timelineRepo     *repository.InvestigationTimelineRepository
	userRepo         *repository.UserRepository
}

func NewCaseService() *CaseService {
	return &CaseService{
		caseRepo:         repository.NewCaseRepository(),
		caseNoteRepo:     repository.NewCaseNoteRepository(),
		evidenceRepo:     repository.NewEvidenceRepository(),
		custodyRepo:      repository.NewChainOfCustodyRepository(),
		auditRepo:        repository.NewAuditLogRepository(),
		notificationRepo: repository.NewNotificationRepository(),
		timelineRepo:     repository.NewInvestigationTimelineRepository(),
		userRepo:         repository.NewUserRepository(),
	}
}

func (s *CaseService) CreateCase(title, description, incidentType, priority string, assignedTo, createdBy int, notes *string) (*models.InvestigationCase, error) {
	if title == "" {
		return nil, errors.New("title is required")
	}
	if priority == "" {
		priority = "Medium"
	}
	c := &models.InvestigationCase{
		Title:        title,
		Description:  strPtr(description),
		IncidentType: strPtr(incidentType),
		Priority:     priority,
		Status:       "Open",
		AssignedTo:   intPtr(assignedTo),
		CreatedBy:    createdBy,
		Notes:        notes,
	}
	caseObj, err := s.caseRepo.Create(c)
	if err != nil {
		return nil, err
	}
	// Add timeline event
	_ = s.timelineRepo.Create(&models.InvestigationTimeline{
		CaseID:      caseObj.ID,
		EventType:   "CASE_CREATED",
		Description: "Case created: " + caseObj.Title,
		Metadata:    &models.JSONMap{"user_id": createdBy},
	})
	if assignedTo != 0 {
		_ = s.notificationRepo.Create(&models.Notification{
			UserID:  assignedTo,
			Title:   "New Case Assigned",
			Message: "You have been assigned to case " + caseObj.CaseID,
		})
	}
	_ = s.auditRepo.Create(&models.AuditLog{
		UserID:  &createdBy,
		Action:  "CASE_CREATE",
		Module:  strPtr("CASES"),
		Details: &models.JSONMap{"case_id": caseObj.CaseID},
	})
	return caseObj, nil
}

func (s *CaseService) GetTimeline(caseID int) ([]*models.InvestigationTimeline, error) {
	return s.timelineRepo.FindByCaseID(caseID)
}

func (s *CaseService) AddTimelineEvent(caseID int, eventType, description string, metadata *models.JSONMap) error {
	return s.timelineRepo.Create(&models.InvestigationTimeline{
		CaseID:      caseID,
		EventType:   eventType,
		Description: description,
		Metadata:    metadata,
	})
}

func (s *CaseService) GenerateCaseReport(caseID int) (map[string]interface{}, error) {
	caseObj, err := s.caseRepo.FindByID(caseID)
	if err != nil {
		return nil, err
	}

	evidenceList, err := s.evidenceRepo.FindByCaseID(caseID)
	if err != nil {
		evidenceList = []*models.Evidence{}
	}

	timeline, err := s.timelineRepo.FindByCaseID(caseID)
	if err != nil {
		timeline = []*models.InvestigationTimeline{}
	}

	return map[string]interface{}{
		"case":     caseObj,
		"evidence": evidenceList,
		"timeline": timeline,
	}, nil
}

func (s *EvidenceService) GenerateEvidenceIntegrityReport(evidenceID int) (map[string]interface{}, error) {
	evidence, err := s.evidenceRepo.FindByID(evidenceID)
	if err != nil {
		return nil, err
	}

	isValid, _ := s.VerifyIntegrity(evidenceID)
	custodyRecords, _ := s.GetChainOfCustody(evidenceID)

	return map[string]interface{}{
		"evidence":         evidence,
		"integrity_valid":  isValid,
		"chain_of_custody": custodyRecords,
	}, nil
}

func (s *EvidenceService) GenerateChainOfCustodyReport(evidenceID int) ([]*models.ChainOfCustody, error) {
	return s.GetChainOfCustody(evidenceID)
}

func (s *CaseService) UpdateCase(caseID int, updates map[string]interface{}, updatedBy int) (*models.InvestigationCase, error) {
	c, err := s.caseRepo.FindByID(caseID)
	if err != nil {
		return nil, err
	}

	if title, ok := updates["title"].(string); ok {
		c.Title = title
	}
	if desc, ok := updates["description"].(string); ok {
		c.Description = strPtr(desc)
	}
	if incidentType, ok := updates["incident_type"].(string); ok {
		c.IncidentType = strPtr(incidentType)
	}
	if priority, ok := updates["priority"].(string); ok {
		c.Priority = priority
	}
	if status, ok := updates["status"].(string); ok {
		oldStatus := c.Status
		c.Status = status
		if oldStatus != status {
			if c.AssignedTo != nil {
				_ = s.notificationRepo.Create(&models.Notification{
					UserID:  *c.AssignedTo,
					Title:   "Case Status Updated",
					Message: "Case " + c.CaseID + " status changed from " + oldStatus + " to " + status,
				})
			}
		}
	}
	if assignedTo, ok := updates["assigned_to"].(int); ok && assignedTo != 0 {
		oldAssigned := c.AssignedTo
		c.AssignedTo = &assignedTo
		if oldAssigned == nil || *oldAssigned != assignedTo {
			_ = s.notificationRepo.Create(&models.Notification{
				UserID:  assignedTo,
				Title:   "Case Assigned",
				Message: "You have been assigned to case " + c.CaseID,
			})
		}
	}
	if notes, ok := updates["notes"].(string); ok {
		c.Notes = strPtr(notes)
	}
	if isArchived, ok := updates["is_archived"].(bool); ok {
		c.IsArchived = isArchived
	}

	if err := s.caseRepo.Update(c); err != nil {
		return nil, err
	}

	_ = s.auditRepo.Create(&models.AuditLog{
		UserID:  &updatedBy,
		Action:  "CASE_UPDATE",
		Module:  strPtr("CASES"),
		Details: &models.JSONMap{"case_id": c.CaseID},
	})

	return c, nil
}

func (s *CaseService) GetCase(caseID int) (*models.InvestigationCase, error) {
	return s.caseRepo.FindByID(caseID)
}

func (s *CaseService) ListCases(includeArchived bool) ([]*models.InvestigationCase, error) {
	return s.caseRepo.ListAll(includeArchived)
}

func (s *CaseService) ListCasesByUser(userID int) ([]*models.InvestigationCase, error) {
	return s.caseRepo.ListByAssignedUser(userID)
}

func (s *CaseService) SearchCases(query string) ([]*models.InvestigationCase, error) {
	return s.caseRepo.Search(query)
}

func (s *CaseService) AddCaseNote(caseID, userID int, note string) (*models.CaseNote, error) {
	n := &models.CaseNote{CaseID: caseID, UserID: userID, Note: note}
	if err := s.caseNoteRepo.Create(n); err != nil {
		return nil, err
	}
	return n, nil
}

func (s *CaseService) ListCaseNotes(caseID int) ([]*models.CaseNote, error) {
	return s.caseNoteRepo.FindByCaseID(caseID)
}

func (s *CaseService) DeleteCaseNote(noteID, userID int) error {
	return s.caseNoteRepo.Delete(noteID, userID)
}

type EvidenceService struct {
	evidenceRepo     *repository.EvidenceRepository
	custodyRepo      *repository.ChainOfCustodyRepository
	auditRepo        *repository.AuditLogRepository
	notificationRepo *repository.NotificationRepository
	caseRepo         *repository.CaseRepository
	timelineRepo     *repository.InvestigationTimelineRepository
}

func NewEvidenceService() *EvidenceService {
	return &EvidenceService{
		evidenceRepo:     repository.NewEvidenceRepository(),
		custodyRepo:      repository.NewChainOfCustodyRepository(),
		auditRepo:        repository.NewAuditLogRepository(),
		notificationRepo: repository.NewNotificationRepository(),
		caseRepo:         repository.NewCaseRepository(),
		timelineRepo:     repository.NewInvestigationTimelineRepository(),
	}
}

func (s *EvidenceService) UploadEvidence(caseID int, fileName, filePath, category string, fileSize int64, fileType string, sha256 string, uploadedBy int, metadata *models.JSONMap) (*models.Evidence, error) {
	existing, _ := s.evidenceRepo.FindBySHA256(sha256)
	if existing != nil {
		return nil, errors.New("evidence with this hash already exists")
	}

	evidenceID := uuid.NewString()
	e := &models.Evidence{
		EvidenceID: evidenceID,
		CaseID:     caseID,
		FileName:   fileName,
		FilePath:   filePath,
		FileSize:   &fileSize,
		FileType:   &fileType,
		Category:   category,
		SHA256Hash: sha256,
		Metadata:   metadata,
		UploadedBy: uploadedBy,
	}

	evidence, err := s.evidenceRepo.Create(e)
	if err != nil {
		return nil, err
	}

	// Add timeline event
	_ = s.timelineRepo.Create(&models.InvestigationTimeline{
		CaseID:      caseID,
		EventType:   "EVIDENCE_UPLOADED",
		Description: "Evidence uploaded: " + fileName,
		Metadata:    &models.JSONMap{"evidence_id": evidence.EvidenceID, "user_id": uploadedBy},
	})

	c, _ := s.caseRepo.FindByID(caseID)
	if c != nil && c.AssignedTo != nil {
		_ = s.notificationRepo.Create(&models.Notification{
			UserID:  *c.AssignedTo,
			Title:   "New Evidence Uploaded",
			Message: "New evidence uploaded to case " + c.CaseID,
		})
	}

	_ = s.custodyRepo.Create(&models.ChainOfCustody{
		EvidenceID: evidence.ID,
		UserID:     uploadedBy,
		Action:     "Upload",
		Notes:      strPtr("Initial upload"),
	})

	_ = s.auditRepo.Create(&models.AuditLog{
		UserID:  &uploadedBy,
		Action:  "EVIDENCE_UPLOAD",
		Module:  strPtr("EVIDENCE"),
		Details: &models.JSONMap{"evidence_id": evidence.EvidenceID, "case_id": caseID},
	})

	return evidence, nil
}

func (s *EvidenceService) GetEvidence(id int) (*models.Evidence, error) {
	return s.evidenceRepo.FindByID(id)
}

func (s *EvidenceService) ListEvidenceByCase(caseID int) ([]*models.Evidence, error) {
	return s.evidenceRepo.FindByCaseID(caseID)
}

func (s *EvidenceService) SearchEvidence(query string) ([]*models.Evidence, error) {
	searchPattern := "%" + query + "%"
	return s.evidenceRepo.Search(searchPattern)
}

func (s *EvidenceService) RecordCustodyAction(evidenceID, userID int, action string, transferredTo *int, notes *string) error {
	return s.custodyRepo.Create(&models.ChainOfCustody{
		EvidenceID:    evidenceID,
		UserID:        userID,
		Action:        action,
		TransferredTo: transferredTo,
		Notes:         notes,
	})
}

func (s *EvidenceService) GetChainOfCustody(evidenceID int) ([]*models.ChainOfCustody, error) {
	return s.custodyRepo.FindByEvidenceID(evidenceID)
}

func (s *EvidenceService) VerifyIntegrity(evidenceID int) (bool, error) {
	evidence, err := s.evidenceRepo.FindByID(evidenceID)
	if err != nil {
		return false, err
	}

	file, err := os.Open(evidence.FilePath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return false, err
	}
	currentHash := hex.EncodeToString(h.Sum(nil))
	return currentHash == evidence.SHA256Hash, nil
}

type UserService struct {
	userRepo  *repository.UserRepository
	auditRepo *repository.AuditLogRepository
}

func NewUserService() *UserService {
	return &UserService{
		userRepo:  repository.NewUserRepository(),
		auditRepo: repository.NewAuditLogRepository(),
	}
}

func (s *UserService) GetUser(id int) (*models.User, error) {
	return s.userRepo.FindByID(id)
}

func (s *UserService) ListUsers() ([]*models.User, error) {
	return s.userRepo.ListAll()
}

func (s *UserService) UpdateUser(id int, updates map[string]interface{}, updatedBy int) (*models.User, error) {
	user, err := s.userRepo.FindByID(id)
	if err != nil {
		return nil, err
	}

	if email, ok := updates["email"].(string); ok {
		user.Email = email
	}
	if role, ok := updates["role"].(string); ok && isValidRole(role) {
		user.Role = role
	}
	if firstName, ok := updates["first_name"].(string); ok {
		user.FirstName = strPtr(firstName)
	}
	if lastName, ok := updates["last_name"].(string); ok {
		user.LastName = strPtr(lastName)
	}
	if phone, ok := updates["phone"].(string); ok {
		user.Phone = strPtr(phone)
	}
	if isActive, ok := updates["is_active"].(bool); ok {
		user.IsActive = isActive
	}

	if err := s.userRepo.Update(user); err != nil {
		return nil, err
	}

	_ = s.auditRepo.Create(&models.AuditLog{
		UserID:  &updatedBy,
		Action:  "USER_UPDATE",
		Module:  strPtr("USERS"),
		Details: &models.JSONMap{"user_id": id},
	})

	return user, nil
}

func (s *UserService) SearchAuditLogs(searchTerm string, limit, offset int) ([]*models.AuditLog, error) {
	if searchTerm == "" {
		return s.auditRepo.List(limit, offset)
	}
	return s.auditRepo.Search(searchTerm, limit, offset)
}

func (s *UserService) ResetPassword(id int, newPassword string, updatedBy int) error {
	if !isStrongPassword(newPassword) {
		return errors.New("password must be at least 8 characters, include uppercase, lowercase, number and special character")
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	_ = s.userRepo.UpdatePassword(id, string(hash))

	_ = s.auditRepo.Create(&models.AuditLog{
		UserID:  &updatedBy,
		Action:  "PASSWORD_RESET",
		Module:  strPtr("USERS"),
		Details: &models.JSONMap{"user_id": id},
	})
	return nil
}

type NotificationService struct {
	repo *repository.NotificationRepository
}

func NewNotificationService() *NotificationService {
	return &NotificationService{repo: repository.NewNotificationRepository()}
}

func (s *NotificationService) GetUserNotifications(userID int) ([]*models.Notification, error) {
	return s.repo.FindByUserID(userID)
}

func (s *NotificationService) MarkAsRead(id, userID int) error {
	return s.repo.MarkAsRead(id, userID)
}

func (s *NotificationService) CreateNotification(userID int, title, message string) error {
	return s.repo.Create(&models.Notification{UserID: userID, Title: title, Message: message})
}

type DashboardService struct {
	caseRepo     *repository.CaseRepository
	evidenceRepo *repository.EvidenceRepository
	userRepo     *repository.UserRepository
	auditRepo    *repository.AuditLogRepository
}

func NewDashboardService() *DashboardService {
	return &DashboardService{
		caseRepo:     repository.NewCaseRepository(),
		evidenceRepo: repository.NewEvidenceRepository(),
		userRepo:     repository.NewUserRepository(),
		auditRepo:    repository.NewAuditLogRepository(),
	}
}

func (s *DashboardService) GetStats() (map[string]interface{}, error) {
	cases, _ := s.caseRepo.ListAll(false)
	totalCases := len(cases)

	openCases := 0
	inProgress := 0
	closed := 0
	criticalCases := 0
	highCases := 0
	for _, c := range cases {
		switch c.Status {
		case "Open":
			openCases++
		case "In Progress":
			inProgress++
		case "Closed":
			closed++
		}
		switch c.Priority {
		case "Critical":
			criticalCases++
		case "High":
			highCases++
		}
	}

	evidence, _ := s.evidenceRepo.ListAll()
	totalEvidence := len(evidence)

	users, _ := s.userRepo.ListAll()
	investigators := 0
	admins := 0
	evidenceOfficers := 0
	viewers := 0
	for _, u := range users {
		switch u.Role {
		case "Investigator":
			investigators++
		case "Administrator":
			admins++
		case "EvidenceOfficer":
			evidenceOfficers++
		case "Viewer":
			viewers++
		}
	}

	evidenceByCategory := map[string]int{}
	for _, e := range evidence {
		evidenceByCategory[e.Category]++
	}

	recentActivities, _ := s.auditRepo.List(5, 0)

	return map[string]interface{}{
		"total_cases":          totalCases,
		"open_cases":           openCases,
		"in_progress_cases":    inProgress,
		"closed_cases":         closed,
		"critical_cases":       criticalCases,
		"high_cases":           highCases,
		"total_users":          len(users),
		"investigators":        investigators,
		"admins":               admins,
		"evidence_officers":    evidenceOfficers,
		"viewers":              viewers,
		"total_evidence":       totalEvidence,
		"evidence_by_category": evidenceByCategory,
		"recent_activities":    recentActivities,
	}, nil
}

func (s *DashboardService) GetRoleDashboardStats(userID int, role string) (map[string]interface{}, error) {
	var cases []*models.InvestigationCase
	var err error

	switch role {
	case "Administrator", "EvidenceOfficer":
		cases, err = s.caseRepo.ListAll(false)
	default:
		cases, err = s.caseRepo.ListByAssignedUser(userID)
	}
	if err != nil {
		return nil, err
	}

	totalCases := len(cases)
	openCases := 0
	inProgress := 0
	closed := 0
	criticalCases := 0
	highCases := 0
	for _, c := range cases {
		switch c.Status {
		case "Open":
			openCases++
		case "In Progress":
			inProgress++
		case "Closed":
			closed++
		}
		switch c.Priority {
		case "Critical":
			criticalCases++
		case "High":
			highCases++
		}
	}

	evidenceCount := 0
	if role == "Administrator" || role == "EvidenceOfficer" {
		allEvidence, _ := s.evidenceRepo.ListAll()
		evidenceCount = len(allEvidence)
	} else {
		for _, c := range cases {
			caseEvidence, _ := s.evidenceRepo.FindByCaseID(c.ID)
			evidenceCount += len(caseEvidence)
		}
	}

	result := map[string]interface{}{
		"total_cases":       totalCases,
		"open_cases":        openCases,
		"in_progress_cases": inProgress,
		"closed_cases":      closed,
		"critical_cases":    criticalCases,
		"high_cases":        highCases,
		"total_evidence":    evidenceCount,
		"role":              role,
	}

	if role == "Administrator" {
		users, _ := s.userRepo.ListAll()
		investigators := 0
		admins := 0
		evidenceOfficers := 0
		viewers := 0
		for _, u := range users {
			switch u.Role {
			case "Investigator":
				investigators++
			case "Administrator":
				admins++
			case "EvidenceOfficer":
				evidenceOfficers++
			case "Viewer":
				viewers++
			}
		}
		result["total_users"] = len(users)
		result["investigators"] = investigators
		result["admins"] = admins
		result["evidence_officers"] = evidenceOfficers
		result["viewers"] = viewers

		allEvidence, _ := s.evidenceRepo.ListAll()
		evidenceByCategory := map[string]int{}
		for _, e := range allEvidence {
			evidenceByCategory[e.Category]++
		}
		result["evidence_by_category"] = evidenceByCategory

		recentActivities, _ := s.auditRepo.List(5, 0)
		result["recent_activities"] = recentActivities
	}

	return result, nil
}

func (s *CaseService) ComputeFCI(caseID int) (map[string]interface{}, error) {
	c, err := s.caseRepo.FindByID(caseID)
	if err != nil {
		return nil, err
	}

	evidenceRecs, _ := s.evidenceRepo.FindByCaseID(caseID)
	evidenceCount := len(evidenceRecs)
	integralEvidence := 0
	for _, e := range evidenceRecs {
		f, err := os.Open(e.FilePath)
		if err == nil {
			h := sha256.New()
			_, _ = io.Copy(h, f)
			f.Close()
			if hex.EncodeToString(h.Sum(nil)) == e.SHA256Hash {
				integralEvidence++
			}
		}
	}

	custodyRecords, _ := s.custodyRepo.ListByEvidenceIDs(caseID)
	totalCustody := len(custodyRecords)
	expectedCustody := evidenceCount * 2
	custodyCompleteness := 0.0
	if expectedCustody > 0 {
		custodyCompleteness = float64(totalCustody) / float64(expectedCustody)
	}
	if custodyCompleteness > 1.0 {
		custodyCompleteness = 1.0
	}

	timelines, _ := s.timelineRepo.FindByCaseID(caseID)
	documentationScore := 0.0
	if evidenceCount > 0 {
		documentationScore = float64(len(timelines)) / (float64(evidenceCount) + 2.0)
	}
	if documentationScore > 1.0 {
		documentationScore = 1.0
	}

	progressScore := 0.0
	switch c.Status {
	case "Open":
		progressScore = 0.2
	case "Assigned":
		progressScore = 0.4
	case "In Progress":
		progressScore = 0.6
	case "Under Review":
		progressScore = 0.8
	case "Closed":
		progressScore = 1.0
	}

	integrityScore := 0.0
	if evidenceCount > 0 {
		integrityScore = float64(integralEvidence) / float64(evidenceCount)
	}

	fci := (integrityScore*0.3 + custodyCompleteness*0.3 + documentationScore*0.2 + progressScore*0.2)
	if fci > 1.0 {
		fci = 1.0
	}
	fciPercent := fci * 100

	return map[string]interface{}{
		"case_id":              c.CaseID,
		"forensic_confidence":  fciPercent,
		"integrity_score":      integrityScore * 100,
		"custody_score":        custodyCompleteness * 100,
		"documentation_score":  documentationScore * 100,
		"progress_score":       progressScore * 100,
		"evidence_count":       evidenceCount,
		"integral_evidence":    integralEvidence,
		"custody_records":      totalCustody,
	}, nil
}

func (s *CaseService) CanAccessCase(userID int, caseID int) (bool, error) {
	c, err := s.caseRepo.FindByID(caseID)
	if err != nil {
		return false, err
	}
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return false, err
	}
	if user.Role == "Administrator" || user.Role == "EvidenceOfficer" {
		return true, nil
	}
	return c.AssignedTo != nil && *c.AssignedTo == userID, nil
}

func intPtr(i int) *int {
	if i == 0 {
		return nil
	}
	return &i
}
