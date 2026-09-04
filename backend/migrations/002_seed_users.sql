
INSERT INTO users (username, email, password_hash, role, first_name, last_name, is_active) VALUES 
('admin', 'admin@forensix.local', '$2a$10$bCoUYQCwzYrBnAKfAB3UHOTt9/nZwlYkxuTkq2cUSxnExGJkbjiAi', 'Administrator', 'System', 'Administrator', TRUE),
('investigator1', 'investigator1@forensix.local', '$2a$10$bCoUYQCwzYrBnAKfAB3UHOTt9/nZwlYkxuTkq2cUSxnExGJkbjiAi', 'Investigator', 'John', 'Doe', TRUE),
('officer1', 'officer1@forensix.local', '$2a$10$bCoUYQCwzYrBnAKfAB3UHOTt9/nZwlYkxuTkq2cUSxnExGJkbjiAi', 'EvidenceOfficer', 'Jane', 'Smith', TRUE),
('viewer1', 'viewer1@forensix.local', '$2a$10$bCoUYQCwzYrBnAKfAB3UHOTt9/nZwlYkxuTkq2cUSxnExGJkbjiAi', 'Viewer', 'Bob', 'Jones', TRUE)
ON DUPLICATE KEY UPDATE 
  password_hash = VALUES(password_hash),
  role = VALUES(role),
  first_name = VALUES(first_name),
  last_name = VALUES(last_name),
  is_active = VALUES(is_active);
