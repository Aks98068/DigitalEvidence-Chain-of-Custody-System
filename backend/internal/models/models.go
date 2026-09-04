
package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"
)

type User struct {
	ID                  int        `json:"id" db:"id"`
	Username            string     `json:"username" db:"username"`
	Email               string     `json:"email" db:"email"`
	PasswordHash        string     `json:"-" db:"password_hash"`
	Role                string     `json:"role" db:"role"`
	FirstName           *string    `json:"first_name,omitempty" db:"first_name"`
	LastName            *string    `json:"last_name,omitempty" db:"last_name"`
	Phone               *string    `json:"phone,omitempty" db:"phone"`
	IsActive            bool       `json:"is_active" db:"is_active"`
	FailedLoginAttempts int        `json:"-" db:"failed_login_attempts"`
	AccountLockedUntil  *time.Time `json:"-" db:"account_locked_until"`
	LastLoginAt         *time.Time `json:"last_login_at,omitempty" db:"last_login_at"`
	CreatedAt           time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at" db:"updated_at"`
}

type InvestigationCase struct {
	ID           int        `json:"id" db:"id"`
	CaseID       string     `json:"case_id" db:"case_id"`
	Title        string     `json:"title" db:"title"`
	Description  *string    `json:"description,omitempty" db:"description"`
	IncidentType *string    `json:"incident_type,omitempty" db:"incident_type"`
	Priority     string     `json:"priority" db:"priority"`
	Status       string     `json:"status" db:"status"`
	AssignedTo   *int       `json:"assigned_to,omitempty" db:"assigned_to"`
	CreatedBy    int        `json:"created_by" db:"created_by"`
	Notes        *string    `json:"notes,omitempty" db:"notes"`
	IsArchived   bool       `json:"is_archived" db:"is_archived"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at" db:"updated_at"`
}

type Evidence struct {
	ID          int         `json:"id" db:"id"`
	EvidenceID  string      `json:"evidence_id" db:"evidence_id"`
	CaseID      int         `json:"case_id" db:"case_id"`
	FileName    string      `json:"file_name" db:"file_name"`
	FilePath    string      `json:"-" db:"file_path"`
	FileSize    *int64      `json:"file_size,omitempty" db:"file_size"`
	FileType    *string     `json:"file_type,omitempty" db:"file_type"`
	Category    string      `json:"category" db:"category"`
	SHA256Hash  string      `json:"sha256_hash" db:"sha256_hash"`
	Metadata    *JSONMap    `json:"metadata,omitempty" db:"metadata"`
	Version     int         `json:"version" db:"version"`
	UploadedBy  int         `json:"uploaded_by" db:"uploaded_by"`
	CreatedAt   time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at" db:"updated_at"`
}

type ChainOfCustody struct {
	ID            int        `json:"id" db:"id"`
	EvidenceID    int        `json:"evidence_id" db:"evidence_id"`
	UserID        int        `json:"user_id" db:"user_id"`
	Action        string     `json:"action" db:"action"`
	TransferredTo *int       `json:"transferred_to,omitempty" db:"transferred_to"`
	Notes         *string    `json:"notes,omitempty" db:"notes"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
}

type AuditLog struct {
	ID        int         `json:"id" db:"id"`
	UserID    *int        `json:"user_id,omitempty" db:"user_id"`
	Action    string      `json:"action" db:"action"`
	Module    *string     `json:"module,omitempty" db:"module"`
	Details   *JSONMap    `json:"details,omitempty" db:"details"`
	IPAddress *string     `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent *string     `json:"user_agent,omitempty" db:"user_agent"`
	CreatedAt time.Time   `json:"created_at" db:"created_at"`
}

type Session struct {
	ID         int        `json:"id" db:"id"`
	UserID     int        `json:"user_id" db:"user_id"`
	Token      string     `json:"-" db:"token"`
	IPAddress  *string    `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent  *string    `json:"user_agent,omitempty" db:"user_agent"`
	ExpiresAt  time.Time  `json:"expires_at" db:"expires_at"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
}

type Notification struct {
	ID        int        `json:"id" db:"id"`
	UserID    int        `json:"user_id" db:"user_id"`
	Title     string     `json:"title" db:"title"`
	Message   string     `json:"message" db:"message"`
	IsRead    bool       `json:"is_read" db:"is_read"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
}

type InvestigationTimeline struct {
	ID          int         `json:"id" db:"id"`
	CaseID      int         `json:"case_id" db:"case_id"`
	EventType   string      `json:"event_type" db:"event_type"`
	Description string      `json:"description" db:"description"`
	Metadata    *JSONMap    `json:"metadata,omitempty" db:"metadata"`
	CreatedAt   time.Time   `json:"created_at" db:"created_at"`
}

type CaseNote struct {
	ID        int       `json:"id" db:"id"`
	CaseID    int       `json:"case_id" db:"case_id"`
	UserID    int       `json:"user_id" db:"user_id"`
	Note      string    `json:"note" db:"note"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type PasswordResetToken struct {
	ID        int       `json:"id" db:"id"`
	UserID    int       `json:"user_id" db:"user_id"`
	Token     string    `json:"token" db:"token"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type JSONMap map[string]interface{}

func (j *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*j = make(JSONMap)
		return nil
	}
	if bytes, ok := value.([]byte); ok {
		return json.Unmarshal(bytes, j)
	}
	return nil
}

func (j JSONMap) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

