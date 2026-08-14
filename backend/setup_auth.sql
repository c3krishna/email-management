-- ============================================================
-- Email Management Dashboard — Auth Tables
-- Run on DB server: mysql -h 10.180.0.84 -u root -p worktual_email_campaign < setup_auth.sql
-- ============================================================

USE worktual_email_campaign;

-- ---- Users table ----
CREATE TABLE IF NOT EXISTS `email_mgmt_users` (
  `id`              int(11) NOT NULL AUTO_INCREMENT,
  `name`            varchar(100) NOT NULL,
  `email`           varchar(255) NOT NULL UNIQUE,
  `password_hash`   varchar(255) NOT NULL,
  `role`            enum('super_admin','admin','viewer') NOT NULL DEFAULT 'viewer',
  `is_active`       tinyint(1) NOT NULL DEFAULT 1,
  `otp_code`        varchar(10) DEFAULT NULL,
  `otp_expires`     datetime DEFAULT NULL,
  `last_login`      datetime DEFAULT NULL,
  `login_attempts`  int(11) DEFAULT 0,
  `locked_until`    datetime DEFAULT NULL,
  `created_by`      int(11) DEFAULT NULL,
  `created_at`      datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at`      datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_email` (`email`),
  KEY `idx_role`  (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---- Audit log table ----
CREATE TABLE IF NOT EXISTS `email_mgmt_audit` (
  `id`         int(11) NOT NULL AUTO_INCREMENT,
  `user_id`    int(11) DEFAULT NULL,
  `user_email` varchar(255) DEFAULT NULL,
  `action`     varchar(100) NOT NULL,
  `details`    text DEFAULT NULL,
  `ip_address` varchar(50) DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user`   (`user_id`),
  KEY `idx_action` (`action`),
  KEY `idx_date`   (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---- Default super_admin user ----
-- Password: Admin@1234  (change immediately after first login)
-- Hash generated with bcrypt rounds=12
INSERT IGNORE INTO `email_mgmt_users`
  (`name`, `email`, `password_hash`, `role`, `is_active`)
VALUES (
  'Super Admin',
  'admin@worktual.tech',
  '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMeSSm4Y7fYnL1xG5TDyN0D9Hy',
  'super_admin',
  1
);

-- Verify
SELECT id, name, email, role, is_active, created_at FROM email_mgmt_users;
