-- Run once when upgrading an existing MariaDB/MySQL installation.
ALTER TABLE whitelist MODIFY ip_address VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL;
ALTER TABLE audit_log MODIFY ip_address VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL;
ALTER TABLE sessions MODIFY ip_address VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NOT NULL;
ALTER TABLE users MODIFY username VARCHAR(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;
ALTER TABLE zones MODIFY domain_name VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL;
ALTER TABLE sessions MODIFY created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE sessions MODIFY expires_at DATETIME NOT NULL;
CREATE INDEX idx_sessions_expiry ON sessions(expires_at);
