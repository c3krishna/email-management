-- V1 extensions for quarantine, policies, settings, blocklist
-- Run against worktual_email_campaign (app + campaign hosts) and threat_platform as noted.

-- ---- On worktual_email_campaign (both app + campaign DB hosts) ----
CREATE TABLE IF NOT EXISTS email_quarantine (
  id              BIGINT AUTO_INCREMENT PRIMARY KEY,
  source_log_id   BIGINT NULL,
  queue_id        VARCHAR(128) NULL,
  mail_from       VARCHAR(255) NULL,
  mail_to         VARCHAR(255) NULL,
  subject         VARCHAR(500) NULL,
  classification  VARCHAR(64)  NULL,
  spam_score      DECIMAL(8,2) NULL,
  status          VARCHAR(32)  NOT NULL DEFAULT 'quarantined',
  reason          TEXT NULL,
  direction       VARCHAR(32)  NULL,
  relay_ip        VARCHAR(64)  NULL,
  dkim_result     VARCHAR(32)  NULL,
  spf_result      VARCHAR(32)  NULL,
  body_preview    TEXT NULL,
  action_by       VARCHAR(128) NULL,
  action_at       DATETIME NULL,
  action_note     VARCHAR(500) NULL,
  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_q_status (status),
  INDEX idx_q_created (created_at),
  INDEX idx_q_from (mail_from),
  INDEX idx_q_source (source_log_id)
);

CREATE TABLE IF NOT EXISTS app_settings (
  setting_key   VARCHAR(128) PRIMARY KEY,
  setting_value TEXT NULL,
  updated_by    VARCHAR(128) NULL,
  updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS policy_blocklist (
  id         BIGINT AUTO_INCREMENT PRIMARY KEY,
  type       ENUM('domain','ip','email','cidr') NOT NULL,
  value      VARCHAR(255) NOT NULL,
  reason     VARCHAR(500) NULL,
  active     TINYINT NOT NULL DEFAULT 1,
  added_by   VARCHAR(128) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_block_type_value (type, value),
  INDEX idx_block_active (active)
);

-- ---- On threat_platform (optional VIP alert review columns) ----
-- ALTER TABLE impersonation_alerts ADD COLUMN IF NOT EXISTS reviewed TINYINT DEFAULT 0;
-- ALTER TABLE sender_anomaly_alerts ADD COLUMN IF NOT EXISTS reviewed TINYINT DEFAULT 0;
