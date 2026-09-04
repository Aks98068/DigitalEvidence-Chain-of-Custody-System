package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"time"

	"forensix-backend/config"
	"forensix-backend/internal/models"
	"forensix-backend/internal/repository"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	userRepo       *repository.UserRepository
	sessionRepo    *repository.SessionRepository
	auditRepo      *repository.AuditLogRepository
	notificationRepo *repository.NotificationRepository
}

func NewAuthService() *AuthService {
	return &AuthService{
		userRepo:         repository.NewUserRepository(),
		sessionRepo:      repository.NewSessionRepository(),
		auditRepo:        repository.NewAuditLogRepository(),
		notificationRepo: repository.NewNotificationRepository(),
	}
}

func (s *AuthService) Register(username, email, password, role string, firstName, lastName, phone *string) (*models.User, string, error) {
	if !isStrongPassword(password) {
		return nil, "", errors.New("password must be at least 8 characters, include uppercase, lowercase, number and special character")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", err
	}

	finalRole := "Viewer"
	if role != "" && role != "Administrator" {
		finalRole = role
	}

	user := &models.User{
		Username:     username,
		Email:        email,
		PasswordHash: string(hash),
		Role:         finalRole,
		FirstName:    firstName,
		LastName:     lastName,
		Phone:        phone,
		IsActive:     true,
	}

	createdUser, err := s.userRepo.Create(user)
	if err != nil {
		return nil, "", err
	}

	token, err := s.createSession(createdUser.ID, nil, nil)
	if err != nil {
		return nil, "", err
	}

	_ = s.auditRepo.Create(&models.AuditLog{
		UserID: &createdUser.ID,
		Action: "USER_REGISTER",
		Module: strPtr("AUTH"),
	})

	return createdUser, token, nil
}

func (s *AuthService) Login(usernameOrEmail, password string, ipAddress, userAgent *string) (*models.User, string, error) {
	user, err := s.userRepo.FindByEmail(usernameOrEmail)
	if err != nil {
		user, err = s.userRepo.FindByUsername(usernameOrEmail)
		if err != nil {
			_ = s.auditRepo.Create(&models.AuditLog{
				Action:  "LOGIN_FAILED",
				Module:  strPtr("AUTH"),
				Details: &models.JSONMap{"username": usernameOrEmail},
			})
			_ = s.notificationRepo.Create(&models.Notification{
				UserID:  1,
				Title:   "Suspicious Login Attempt",
				Message: "Failed login attempt for " + usernameOrEmail,
			})
			return nil, "", errors.New("invalid credentials")
		}
	}

	if !user.IsActive {
		_ = s.auditRepo.Create(&models.AuditLog{
			Action:  "LOGIN_FAILED",
			Module:  strPtr("AUTH"),
			Details: &models.JSONMap{"username": user.Username, "reason": "inactive account"},
		})
		return nil, "", errors.New("account is inactive")
	}

	if user.AccountLockedUntil != nil && time.Now().Before(*user.AccountLockedUntil) {
		_ = s.notificationRepo.Create(&models.Notification{
			UserID:  1,
			Title:   "Suspicious Login Attempt",
			Message: "Login attempt on locked account for " + user.Username,
		})
		return nil, "", errors.New("account is temporarily locked")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		user.FailedLoginAttempts++
		if user.FailedLoginAttempts >= 5 {
			lockTime := time.Now().Add(15 * time.Minute)
			user.AccountLockedUntil = &lockTime
		}
		_ = s.userRepo.Update(user)

		_ = s.auditRepo.Create(&models.AuditLog{
			Action:  "LOGIN_FAILED",
			Module:  strPtr("AUTH"),
			Details: &models.JSONMap{"username": user.Username, "attempts": user.FailedLoginAttempts},
		})
		return nil, "", errors.New("invalid credentials")
	}

	user.FailedLoginAttempts = 0
	user.AccountLockedUntil = nil
	now := time.Now()
	user.LastLoginAt = &now
	_ = s.userRepo.Update(user)

	token, err := s.createSession(user.ID, ipAddress, userAgent)
	if err != nil {
		return nil, "", err
	}

	_ = s.auditRepo.Create(&models.AuditLog{
		UserID:    &user.ID,
		Action:    "LOGIN_SUCCESS",
		Module:    strPtr("AUTH"),
		IPAddress: ipAddress,
		UserAgent: userAgent,
	})

	return user, token, nil
}

func (s *AuthService) Logout(token string) error {
	_ = s.auditRepo.Create(&models.AuditLog{
		Action: "LOGOUT",
		Module: strPtr("AUTH"),
	})
	return s.sessionRepo.Delete(token)
}

func (s *AuthService) ValidateToken(token string) (*models.User, error) {
	session, err := s.sessionRepo.FindByToken(token)
	if err != nil {
		return nil, err
	}
	return s.userRepo.FindByID(session.UserID)
}

func (s *AuthService) createSession(userID int, ipAddress, userAgent *string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(config.AppConfig.SessionTTL).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(config.AppConfig.JWTSecret))
	if err != nil {
		return "", err
	}

	session := &models.Session{
		UserID:    userID,
		Token:     signedToken,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		ExpiresAt: time.Now().Add(config.AppConfig.SessionTTL),
	}
	_, err = s.sessionRepo.Create(session)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func (s *AuthService) ChangePassword(userID int, oldPassword, newPassword string) error {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword))
	if err != nil {
		return errors.New("current password is incorrect")
	}

	if !isStrongPassword(newPassword) {
		return errors.New("password must be at least 8 characters, include uppercase, lowercase, number and special character")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return s.userRepo.UpdatePassword(userID, string(hash))
}

func (s *AuthService) RequestPasswordReset(email string) (string, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return "", errors.New("user not found")
	}

	token := uuid.NewString()
	expiresAt := time.Now().Add(1 * time.Hour)
	if err := s.userRepo.CreatePasswordResetToken(user.ID, token, expiresAt); err != nil {
		return "", err
	}

	// In a real system, you would send an email here
	// For now, just return the token
	return token, nil
}

func (s *AuthService) ResetPassword(token, newPassword string) error {
	resetToken, err := s.userRepo.FindPasswordResetToken(token)
	if err != nil {
		return errors.New("invalid or expired token")
	}

	if !isStrongPassword(newPassword) {
		return errors.New("password must be at least 8 characters, include uppercase, lowercase, number and special character")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	if err := s.userRepo.UpdatePassword(resetToken.UserID, string(hash)); err != nil {
		return err
	}

	_ = s.userRepo.DeletePasswordResetToken(token)

	return nil
}

func ComputeSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func isStrongPassword(p string) bool {
	if len(p) < 8 {
		return false
	}
	hasUpper := false
	hasLower := false
	hasNumber := false
	hasSpecial := false
	for _, c := range p {
		switch {
		case 'A' <= c && c <= 'Z':
			hasUpper = true
		case 'a' <= c && c <= 'z':
			hasLower = true
		case '0' <= c && c <= '9':
			hasNumber = true
		default:
			hasSpecial = true
		}
	}
	return hasUpper && hasLower && hasNumber && hasSpecial
}

func isValidRole(r string) bool {
	valid := map[string]bool{
		"Administrator":   true,
		"Investigator":    true,
		"EvidenceOfficer": true,
		"Viewer":          true,
	}
	return valid[r]
}

func strPtr(s string) *string {
	return &s
}
