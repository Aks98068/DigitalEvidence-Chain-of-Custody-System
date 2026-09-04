-- Create schema_migrations table
CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(255) PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('Administrator', 'Investigator', 'EvidenceOfficer', 'Viewer') NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    phone VARCHAR(20),
    is_active BOOLEAN DEFAULT TRUE,
    failed_login_attempts INT DEFAULT 0,
    account_locked_until DATETIME,
    last_login_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Investigation cases table
CREATE TABLE IF NOT EXISTS investigation_cases (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id VARCHAR(20) NOT NULL UNIQUE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    incident_type VARCHAR(100),
    priority ENUM('Critical', 'High', 'Medium', 'Low') DEFAULT 'Medium',
    status ENUM('Open', 'Assigned', 'In Progress', 'Under Review', 'Closed') DEFAULT 'Open',
    assigned_to INT,
    created_by INT NOT NULL,
    notes TEXT,
    is_archived BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_case_id (case_id),
    INDEX idx_status (status),
    INDEX idx_assigned_to (assigned_to)
);

-- Case notes table
CREATE TABLE IF NOT EXISTS case_notes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id INT NOT NULL,
    user_id INT NOT NULL,
    note TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES investigation_cases(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Evidence table
CREATE TABLE IF NOT EXISTS evidence (
    id INT AUTO_INCREMENT PRIMARY KEY,
    evidence_id VARCHAR(36) NOT NULL UNIQUE,
    case_id INT NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    file_size BIGINT,
    file_type VARCHAR(100),
    category ENUM('Document', 'Image', 'Video', 'Audio', 'Memory Dump', 'Network Capture', 'Executable', 'Mobile Data') NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    metadata JSON,
    version INT DEFAULT 1,
    uploaded_by INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES investigation_cases(id) ON DELETE CASCADE,
    FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_evidence_id (evidence_id),
    INDEX idx_sha256 (sha256_hash),
    INDEX idx_case_id (case_id)
);

-- Chain of custody table
CREATE TABLE IF NOT EXISTS chain_of_custody (
    id INT AUTO_INCREMENT PRIMARY KEY,
    evidence_id INT NOT NULL,
    user_id INT NOT NULL,
    action ENUM('Upload', 'Access', 'Transfer', 'Verify') NOT NULL,
    transferred_to INT,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (transferred_to) REFERENCES users(id) ON DELETE SET NULL
);

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(100) NOT NULL,
    module VARCHAR(100),
    details JSON,
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_created_at (created_at),
    INDEX idx_user_id (user_id)
);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(500) NOT NULL UNIQUE,
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    expires_at DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Notifications table
CREATE TABLE IF NOT EXISTS notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Investigation timelines table
CREATE TABLE IF NOT EXISTS investigation_timelines (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id INT NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES investigation_cases(id) ON DELETE CASCADE
);
