package repository

import (
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "github.com/go-sql-driver/mysql"
)

var migrateOnce sync.Once

func RunMigrations(db *sql.DB, migrationsDir string) error {
	var err error
	migrateOnce.Do(func() {
		err = runMigrations(db, migrationsDir)
	})
	return err
}

func runMigrations(db *sql.DB, migrationsDir string) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(255) PRIMARY KEY, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	files, err := os.ReadDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	var applied int
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".sql") {
			continue
		}

		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = ?", file.Name()).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to check migration %s: %w", file.Name(), err)
		}
		if count > 0 {
			continue
		}

		content, err := os.ReadFile(filepath.Join(migrationsDir, file.Name()))
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", file.Name(), err)
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction for %s: %w", file.Name(), err)
		}

		statements := splitSQL(string(content))
		for _, stmt := range statements {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if _, err := tx.Exec(stmt); err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to execute migration %s: %w\nSQL: %s\nError: %w", file.Name(), err, stmt, err)
			}
		}

		if _, err := tx.Exec("INSERT INTO schema_migrations (version) VALUES (?)", file.Name()); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to record migration %s: %w", file.Name(), err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit migration %s: %w", file.Name(), err)
		}
		applied++
	}

	fmt.Printf("Migrations applied: %d\n", applied)
	return nil
}

func splitSQL(content string) []string {
	var statements []string
	var current strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		current.WriteString(line)
		current.WriteString("\n")
		if strings.HasSuffix(strings.TrimSpace(line), ";") {
			statements = append(statements, current.String())
			current.Reset()
		}
	}
	if strings.TrimSpace(current.String()) != "" {
		statements = append(statements, current.String())
	}
	return statements
}
