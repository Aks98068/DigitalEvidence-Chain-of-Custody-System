package repository

import (
	"database/sql"
	"time"

	"forensix-backend/internal/models"
)

type UserRepository struct {
	DB *sql.DB
}

func NewUserRepository() *UserRepository {
	return &UserRepository{DB: DB}
}

func (r *UserRepository) Create(user *models.User) (*models.User, error) {
	query := `
	INSERT INTO users (username, email, password_hash, role, first_name, last_name, phone)
	VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	result, err := r.DB.Exec(
		query,
		user.Username, user.Email, user.PasswordHash, user.Role,
		user.FirstName, user.LastName, user.Phone,
	)
	if err != nil {
		return nil, err
	}
	id, _ := result.LastInsertId()
	user.ID = int(id)
	return user, nil
}

func (r *UserRepository) FindByID(id int) (*models.User, error) {
	var user models.User
	query := `SELECT id, username, email, password_hash, role, first_name, last_name, phone, is_active, failed_login_attempts, account_locked_until, last_login_at, created_at, updated_at FROM users WHERE id = ?`
	err := r.DB.QueryRow(query, id).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Role,
		&user.FirstName, &user.LastName, &user.Phone, &user.IsActive,
		&user.FailedLoginAttempts, &user.AccountLockedUntil, &user.LastLoginAt,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) FindByEmail(email string) (*models.User, error) {
	var user models.User
	query := `SELECT id, username, email, password_hash, role, first_name, last_name, phone, is_active, failed_login_attempts, account_locked_until, last_login_at, created_at, updated_at FROM users WHERE email = ?`
	err := r.DB.QueryRow(query, email).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Role,
		&user.FirstName, &user.LastName, &user.Phone, &user.IsActive,
		&user.FailedLoginAttempts, &user.AccountLockedUntil, &user.LastLoginAt,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) FindByUsername(username string) (*models.User, error) {
	var user models.User
	query := `SELECT id, username, email, password_hash, role, first_name, last_name, phone, is_active, failed_login_attempts, account_locked_until, last_login_at, created_at, updated_at FROM users WHERE username = ?`
	err := r.DB.QueryRow(query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Role,
		&user.FirstName, &user.LastName, &user.Phone, &user.IsActive,
		&user.FailedLoginAttempts, &user.AccountLockedUntil, &user.LastLoginAt,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) Update(user *models.User) error {
	query := `
	UPDATE users 
	SET email = ?, role = ?, first_name = ?, last_name = ?, phone = ?, is_active = ?, failed_login_attempts = ?, account_locked_until = ?, last_login_at = ?
	WHERE id = ?
	`
	_, err := r.DB.Exec(query, user.Email, user.Role, user.FirstName, user.LastName, user.Phone, user.IsActive, user.FailedLoginAttempts, user.AccountLockedUntil, user.LastLoginAt, user.ID)
	return err
}

func (r *UserRepository) UpdatePassword(userID int, passwordHash string) error {
	query := `UPDATE users SET password_hash = ? WHERE id = ?`
	_, err := r.DB.Exec(query, passwordHash, userID)
	return err
}

func (r *UserRepository) ListAll() ([]*models.User, error) {
	query := `SELECT id, username, email, role, first_name, last_name, phone, is_active, created_at, updated_at FROM users`
	rows, err := r.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		var u models.User
		err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.FirstName, &u.LastName, &u.Phone, &u.IsActive, &u.CreatedAt, &u.UpdatedAt)
		if err != nil {
			return nil, err
		}
		users = append(users, &u)
	}
	return users, nil
}

func (r *UserRepository) ListByRole(role string) ([]*models.User, error) {
	query := `SELECT id, username, email, role, first_name, last_name, phone, is_active, created_at, updated_at FROM users WHERE role = ?`
	rows, err := r.DB.Query(query, role)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		var u models.User
		err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.FirstName, &u.LastName, &u.Phone, &u.IsActive, &u.CreatedAt, &u.UpdatedAt)
		if err != nil {
			return nil, err
		}
		users = append(users, &u)
	}
	return users, nil
}

func (r *UserRepository) CreatePasswordResetToken(userID int, token string, expiresAt time.Time) error {
	query := `INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)`
	_, err := r.DB.Exec(query, userID, token, expiresAt)
	return err
}

func (r *UserRepository) FindPasswordResetToken(token string) (*models.PasswordResetToken, error) {
	var t models.PasswordResetToken
	query := `SELECT id, user_id, token, expires_at, created_at FROM password_reset_tokens WHERE token = ? AND expires_at > NOW()`
	err := r.DB.QueryRow(query, token).Scan(&t.ID, &t.UserID, &t.Token, &t.ExpiresAt, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *UserRepository) DeletePasswordResetToken(token string) error {
	query := `DELETE FROM password_reset_tokens WHERE token = ?`
	_, err := r.DB.Exec(query, token)
	return err
}

type SessionRepository struct {
	DB *sql.DB
}

func NewSessionRepository() *SessionRepository {
	return &SessionRepository{DB: DB}
}

func (r *SessionRepository) Create(session *models.Session) (*models.Session, error) {
	query := `INSERT INTO sessions (user_id, token, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, ?)`
	result, err := r.DB.Exec(query, session.UserID, session.Token, session.IPAddress, session.UserAgent, session.ExpiresAt)
	if err != nil {
		return nil, err
	}
	id, _ := result.LastInsertId()
	session.ID = int(id)
	return session, nil
}

func (r *SessionRepository) FindByToken(token string) (*models.Session, error) {
	var session models.Session
	query := `SELECT id, user_id, token, ip_address, user_agent, expires_at, created_at FROM sessions WHERE token = ? AND expires_at > NOW()`
	err := r.DB.QueryRow(query, token).Scan(&session.ID, &session.UserID, &session.Token, &session.IPAddress, &session.UserAgent, &session.ExpiresAt, &session.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (r *SessionRepository) Delete(token string) error {
	query := `DELETE FROM sessions WHERE token = ?`
	_, err := r.DB.Exec(query, token)
	return err
}

func (r *SessionRepository) DeleteExpired() error {
	query := `DELETE FROM sessions WHERE expires_at <= NOW()`
	_, err := r.DB.Exec(query)
	return err
}

type AuditLogRepository struct {
	DB *sql.DB
}

func NewAuditLogRepository() *AuditLogRepository {
	return &AuditLogRepository{DB: DB}
}

func (r *AuditLogRepository) Create(log *models.AuditLog) error {
	query := `INSERT INTO audit_logs (user_id, action, module, details, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)`
	_, err := r.DB.Exec(query, log.UserID, log.Action, log.Module, log.Details, log.IPAddress, log.UserAgent)
	return err
}

func (r *AuditLogRepository) List(limit, offset int) ([]*models.AuditLog, error) {
	query := `SELECT id, user_id, action, module, details, ip_address, user_agent, created_at FROM audit_logs ORDER BY created_at DESC LIMIT ? OFFSET ?`
	rows, err := r.DB.Query(query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*models.AuditLog
	for rows.Next() {
		var l models.AuditLog
		err := rows.Scan(&l.ID, &l.UserID, &l.Action, &l.Module, &l.Details, &l.IPAddress, &l.UserAgent, &l.CreatedAt)
		if err != nil {
			return nil, err
		}
		logs = append(logs, &l)
	}
	return logs, nil
}

func (r *AuditLogRepository) Search(searchTerm string, limit, offset int) ([]*models.AuditLog, error) {
	query := `
	SELECT id, user_id, action, module, details, ip_address, user_agent, created_at 
	FROM audit_logs 
	WHERE action LIKE ? OR module LIKE ? 
	ORDER BY created_at DESC 
	LIMIT ? OFFSET ?`
	searchPattern := "%" + searchTerm + "%"
	rows, err := r.DB.Query(query, searchPattern, searchPattern, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*models.AuditLog
	for rows.Next() {
		var l models.AuditLog
		err := rows.Scan(&l.ID, &l.UserID, &l.Action, &l.Module, &l.Details, &l.IPAddress, &l.UserAgent, &l.CreatedAt)
		if err != nil {
			return nil, err
		}
		logs = append(logs, &l)
	}
	return logs, nil
}

type CaseRepository struct {
	DB *sql.DB
}

func NewCaseRepository() *CaseRepository {
	return &CaseRepository{DB: DB}
}

func (r *CaseRepository) Create(c *models.InvestigationCase) (*models.InvestigationCase, error) {
	query := `INSERT INTO investigation_cases (title, description, incident_type, priority, status, assigned_to, created_by, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	result, err := r.DB.Exec(
		query,
		c.Title, c.Description, c.IncidentType, c.Priority, c.Status, c.AssignedTo, c.CreatedBy, c.Notes,
	)
	if err != nil {
		return nil, err
	}
	id, _ := result.LastInsertId()
	return r.FindByID(int(id))
}

func (r *CaseRepository) FindByID(id int) (*models.InvestigationCase, error) {
	var c models.InvestigationCase
	query := `SELECT id, case_id, title, description, incident_type, priority, status, assigned_to, created_by, notes, is_archived, created_at, updated_at FROM investigation_cases WHERE id = ?`
	err := r.DB.QueryRow(query, id).Scan(
		&c.ID, &c.CaseID, &c.Title, &c.Description, &c.IncidentType, &c.Priority,
		&c.Status, &c.AssignedTo, &c.CreatedBy, &c.Notes, &c.IsArchived, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *CaseRepository) FindByCaseID(caseID string) (*models.InvestigationCase, error) {
	var c models.InvestigationCase
	query := `SELECT id, case_id, title, description, incident_type, priority, status, assigned_to, created_by, notes, is_archived, created_at, updated_at FROM investigation_cases WHERE case_id = ?`
	err := r.DB.QueryRow(query, caseID).Scan(
		&c.ID, &c.CaseID, &c.Title, &c.Description, &c.IncidentType, &c.Priority,
		&c.Status, &c.AssignedTo, &c.CreatedBy, &c.Notes, &c.IsArchived, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *CaseRepository) Update(c *models.InvestigationCase) error {
	query := `
	UPDATE investigation_cases 
	SET title = ?, description = ?, incident_type = ?, priority = ?, status = ?, assigned_to = ?, notes = ?, is_archived = ?
	WHERE id = ?
	`
	_, err := r.DB.Exec(query, c.Title, c.Description, c.IncidentType, c.Priority, c.Status, c.AssignedTo, c.Notes, c.IsArchived, c.ID)
	return err
}

func (r *CaseRepository) ListAll(includeArchived bool) ([]*models.InvestigationCase, error) {
	query := `SELECT id, case_id, title, description, incident_type, priority, status, assigned_to, created_by, notes, is_archived, created_at, updated_at FROM investigation_cases`
	if !includeArchived {
		query += ` WHERE is_archived = FALSE`
	}
	query += ` ORDER BY created_at DESC`
	rows, err := r.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cases []*models.InvestigationCase
	for rows.Next() {
		var c models.InvestigationCase
		if err := rows.Scan(&c.ID, &c.CaseID, &c.Title, &c.Description, &c.IncidentType, &c.Priority, &c.Status, &c.AssignedTo, &c.CreatedBy, &c.Notes, &c.IsArchived, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		cases = append(cases, &c)
	}
	return cases, nil
}

func (r *CaseRepository) ListByAssignedUser(userID int) ([]*models.InvestigationCase, error) {
	query := `SELECT id, case_id, title, description, incident_type, priority, status, assigned_to, created_by, notes, is_archived, created_at, updated_at FROM investigation_cases WHERE assigned_to = ? AND is_archived = FALSE ORDER BY created_at DESC`
	rows, err := r.DB.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cases []*models.InvestigationCase
	for rows.Next() {
		var c models.InvestigationCase
		if err := rows.Scan(&c.ID, &c.CaseID, &c.Title, &c.Description, &c.IncidentType, &c.Priority, &c.Status, &c.AssignedTo, &c.CreatedBy, &c.Notes, &c.IsArchived, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		cases = append(cases, &c)
	}
	return cases, nil
}

func (r *CaseRepository) Search(query string) ([]*models.InvestigationCase, error) {
	searchPattern := "%" + query + "%"
	rows, err := r.DB.Query(
		`SELECT id, case_id, title, description, incident_type, priority, status, assigned_to, created_by, notes, is_archived, created_at, updated_at FROM investigation_cases WHERE case_id LIKE ? OR title LIKE ? OR description LIKE ? ORDER BY created_at DESC`,
		searchPattern, searchPattern, searchPattern,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cases []*models.InvestigationCase
	for rows.Next() {
		var c models.InvestigationCase
		if err := rows.Scan(&c.ID, &c.CaseID, &c.Title, &c.Description, &c.IncidentType, &c.Priority, &c.Status, &c.AssignedTo, &c.CreatedBy, &c.Notes, &c.IsArchived, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		cases = append(cases, &c)
	}
	return cases, nil
}

type EvidenceRepository struct {
	DB *sql.DB
}

func NewEvidenceRepository() *EvidenceRepository {
	return &EvidenceRepository{DB: DB}
}

func (r *EvidenceRepository) Create(e *models.Evidence) (*models.Evidence, error) {
	query := `INSERT INTO evidence (evidence_id, case_id, file_name, file_path, file_size, file_type, category, sha256_hash, metadata, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := r.DB.Exec(
		query,
		e.EvidenceID, e.CaseID, e.FileName, e.FilePath, e.FileSize, e.FileType, e.Category, e.SHA256Hash, e.Metadata, e.UploadedBy,
	)
	if err != nil {
		return nil, err
	}
	return r.FindByEvidenceID(e.EvidenceID)
}

func (r *EvidenceRepository) FindByID(id int) (*models.Evidence, error) {
	var e models.Evidence
	query := `SELECT id, evidence_id, case_id, file_name, file_path, file_size, file_type, category, sha256_hash, metadata, version, uploaded_by, created_at, updated_at FROM evidence WHERE id = ?`
	err := r.DB.QueryRow(query, id).Scan(
		&e.ID, &e.EvidenceID, &e.CaseID, &e.FileName, &e.FilePath, &e.FileSize,
		&e.FileType, &e.Category, &e.SHA256Hash, &e.Metadata, &e.Version,
		&e.UploadedBy, &e.CreatedAt, &e.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (r *EvidenceRepository) FindByEvidenceID(evidenceID string) (*models.Evidence, error) {
	var e models.Evidence
	query := `SELECT id, evidence_id, case_id, file_name, file_path, file_size, file_type, category, sha256_hash, metadata, version, uploaded_by, created_at, updated_at FROM evidence WHERE evidence_id = ?`
	err := r.DB.QueryRow(query, evidenceID).Scan(
		&e.ID, &e.EvidenceID, &e.CaseID, &e.FileName, &e.FilePath, &e.FileSize,
		&e.FileType, &e.Category, &e.SHA256Hash, &e.Metadata, &e.Version,
		&e.UploadedBy, &e.CreatedAt, &e.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (r *EvidenceRepository) FindBySHA256(sha256 string) (*models.Evidence, error) {
	var e models.Evidence
	query := `SELECT id, evidence_id, case_id, file_name, file_path, file_size, file_type, category, sha256_hash, metadata, version, uploaded_by, created_at, updated_at FROM evidence WHERE sha256_hash = ?`
	err := r.DB.QueryRow(query, sha256).Scan(
		&e.ID, &e.EvidenceID, &e.CaseID, &e.FileName, &e.FilePath, &e.FileSize,
		&e.FileType, &e.Category, &e.SHA256Hash, &e.Metadata, &e.Version,
		&e.UploadedBy, &e.CreatedAt, &e.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (r *EvidenceRepository) FindByCaseID(caseID int) ([]*models.Evidence, error) {
	query := `SELECT id, evidence_id, case_id, file_name, file_path, file_size, file_type, category, sha256_hash, metadata, version, uploaded_by, created_at, updated_at FROM evidence WHERE case_id = ? ORDER BY created_at DESC`
	rows, err := r.DB.Query(query, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var evidences []*models.Evidence
	for rows.Next() {
		var e models.Evidence
		if err := rows.Scan(&e.ID, &e.EvidenceID, &e.CaseID, &e.FileName, &e.FilePath, &e.FileSize, &e.FileType, &e.Category, &e.SHA256Hash, &e.Metadata, &e.Version, &e.UploadedBy, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		evidences = append(evidences, &e)
	}
	return evidences, nil
}

func (r *EvidenceRepository) ListAll() ([]*models.Evidence, error) {
	query := `SELECT id, evidence_id, case_id, file_name, file_path, file_size, file_type, category, sha256_hash, metadata, version, uploaded_by, created_at, updated_at FROM evidence ORDER BY created_at DESC`
	rows, err := r.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var evidences []*models.Evidence
	for rows.Next() {
		var e models.Evidence
		if err := rows.Scan(&e.ID, &e.EvidenceID, &e.CaseID, &e.FileName, &e.FilePath, &e.FileSize, &e.FileType, &e.Category, &e.SHA256Hash, &e.Metadata, &e.Version, &e.UploadedBy, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		evidences = append(evidences, &e)
	}
	return evidences, nil
}

func (r *EvidenceRepository) Search(searchPattern string) ([]*models.Evidence, error) {
	query := `SELECT id, evidence_id, case_id, file_name, file_path, file_size, file_type, category, sha256_hash, metadata, version, uploaded_by, created_at, updated_at FROM evidence WHERE file_name LIKE ? OR evidence_id LIKE ? OR category LIKE ? ORDER BY created_at DESC`
	rows, err := r.DB.Query(query, searchPattern, searchPattern, searchPattern)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var evidences []*models.Evidence
	for rows.Next() {
		var e models.Evidence
		if err := rows.Scan(&e.ID, &e.EvidenceID, &e.CaseID, &e.FileName, &e.FilePath, &e.FileSize, &e.FileType, &e.Category, &e.SHA256Hash, &e.Metadata, &e.Version, &e.UploadedBy, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		evidences = append(evidences, &e)
	}
	return evidences, nil
}

type ChainOfCustodyRepository struct {
	DB *sql.DB
}

func NewChainOfCustodyRepository() *ChainOfCustodyRepository {
	return &ChainOfCustodyRepository{DB: DB}
}

func (r *ChainOfCustodyRepository) Create(c *models.ChainOfCustody) error {
	query := `INSERT INTO chain_of_custody (evidence_id, user_id, action, transferred_to, notes) VALUES (?, ?, ?, ?, ?)`
	_, err := r.DB.Exec(query, c.EvidenceID, c.UserID, c.Action, c.TransferredTo, c.Notes)
	return err
}

func (r *ChainOfCustodyRepository) FindByEvidenceID(evidenceID int) ([]*models.ChainOfCustody, error) {
	query := `SELECT id, evidence_id, user_id, action, transferred_to, notes, created_at FROM chain_of_custody WHERE evidence_id = ? ORDER BY created_at ASC`
	rows, err := r.DB.Query(query, evidenceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []*models.ChainOfCustody
	for rows.Next() {
		var c models.ChainOfCustody
		if err := rows.Scan(&c.ID, &c.EvidenceID, &c.UserID, &c.Action, &c.TransferredTo, &c.Notes, &c.CreatedAt); err != nil {
			return nil, err
		}
		records = append(records, &c)
	}
	return records, nil
}

func (r *ChainOfCustodyRepository) ListByEvidenceIDs(caseID int) ([]*models.ChainOfCustody, error) {
	query := `SELECT c.id, c.evidence_id, c.user_id, c.action, c.transferred_to, c.notes, c.created_at FROM chain_of_custody c JOIN evidence e ON c.evidence_id = e.id WHERE e.case_id = ? ORDER BY c.created_at ASC`
	rows, err := r.DB.Query(query, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []*models.ChainOfCustody
	for rows.Next() {
		var c models.ChainOfCustody
		if err := rows.Scan(&c.ID, &c.EvidenceID, &c.UserID, &c.Action, &c.TransferredTo, &c.Notes, &c.CreatedAt); err != nil {
			return nil, err
		}
		records = append(records, &c)
	}
	return records, nil
}

type NotificationRepository struct {
	DB *sql.DB
}

func NewNotificationRepository() *NotificationRepository {
	return &NotificationRepository{DB: DB}
}

func (r *NotificationRepository) Create(n *models.Notification) error {
	query := `INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)`
	_, err := r.DB.Exec(query, n.UserID, n.Title, n.Message)
	return err
}

func (r *NotificationRepository) FindByUserID(userID int) ([]*models.Notification, error) {
	query := `SELECT id, user_id, title, message, is_read, created_at FROM notifications WHERE user_id = ? ORDER BY created_at DESC`
	rows, err := r.DB.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var notifications []*models.Notification
	for rows.Next() {
		var n models.Notification
		if err := rows.Scan(&n.ID, &n.UserID, &n.Title, &n.Message, &n.IsRead, &n.CreatedAt); err != nil {
			return nil, err
		}
		notifications = append(notifications, &n)
	}
	return notifications, nil
}

func (r *NotificationRepository) MarkAsRead(id int, userID int) error {
	query := `UPDATE notifications SET is_read = TRUE WHERE id = ? AND user_id = ?`
	_, err := r.DB.Exec(query, id, userID)
	return err
}

type InvestigationTimelineRepository struct {
	DB *sql.DB
}

func NewInvestigationTimelineRepository() *InvestigationTimelineRepository {
	return &InvestigationTimelineRepository{DB: DB}
}

func (r *InvestigationTimelineRepository) Create(t *models.InvestigationTimeline) error {
	query := `INSERT INTO investigation_timelines (case_id, event_type, description, metadata) VALUES (?, ?, ?, ?)`
	_, err := r.DB.Exec(query, t.CaseID, t.EventType, t.Description, t.Metadata)
	return err
}

func (r *InvestigationTimelineRepository) FindByCaseID(caseID int) ([]*models.InvestigationTimeline, error) {
	query := `SELECT id, case_id, event_type, description, metadata, created_at FROM investigation_timelines WHERE case_id = ? ORDER BY created_at ASC`
	rows, err := r.DB.Query(query, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var timelines []*models.InvestigationTimeline
	for rows.Next() {
		var t models.InvestigationTimeline
		if err := rows.Scan(&t.ID, &t.CaseID, &t.EventType, &t.Description, &t.Metadata, &t.CreatedAt); err != nil {
			return nil, err
		}
		timelines = append(timelines, &t)
	}
	return timelines, nil
}

type CaseNoteRepository struct {
	DB *sql.DB
}

func NewCaseNoteRepository() *CaseNoteRepository {
	return &CaseNoteRepository{DB: DB}
}

func (r *CaseNoteRepository) Create(note *models.CaseNote) error {
	query := `INSERT INTO case_notes (case_id, user_id, note) VALUES (?, ?, ?)`
	_, err := r.DB.Exec(query, note.CaseID, note.UserID, note.Note)
	return err
}

func (r *CaseNoteRepository) FindByCaseID(caseID int) ([]*models.CaseNote, error) {
	query := `SELECT id, case_id, user_id, note, created_at FROM case_notes WHERE case_id = ? ORDER BY created_at ASC`
	rows, err := r.DB.Query(query, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var notes []*models.CaseNote
	for rows.Next() {
		var n models.CaseNote
		if err := rows.Scan(&n.ID, &n.CaseID, &n.UserID, &n.Note, &n.CreatedAt); err != nil {
			return nil, err
		}
		notes = append(notes, &n)
	}
	return notes, nil
}

func (r *CaseNoteRepository) Delete(id int, userID int) error {
	query := `DELETE FROM case_notes WHERE id = ? AND user_id = ?`
	_, err := r.DB.Exec(query, id, userID)
	return err
}
