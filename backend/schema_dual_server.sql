-- Dual mail-server AI/security schema (run on threat_platform + both email DBs)
-- App = mail.worktual.tech | Campaign = mail.worktual.pl

-- ---- threat_platform ----
ALTER TABLE customers
  ADD COLUMN IF NOT EXISTS mail_server ENUM('app','campaign','both') NOT NULL DEFAULT 'app';

ALTER TABLE spam_whitelist
  ADD COLUMN IF NOT EXISTS mail_server ENUM('app','campaign','both') NOT NULL DEFAULT 'both';

ALTER TABLE spam_detections
  MODIFY COLUMN server VARCHAR(20) NOT NULL DEFAULT 'app';

ALTER TABLE wazuh_agents
  ADD COLUMN IF NOT EXISTS mail_server ENUM('app','campaign','both') NOT NULL DEFAULT 'app';
ALTER TABLE wazuh_alerts
  ADD COLUMN IF NOT EXISTS mail_server ENUM('app','campaign','both') NOT NULL DEFAULT 'app';
ALTER TABLE wazuh_vulnerabilities
  ADD COLUMN IF NOT EXISTS mail_server ENUM('app','campaign','both') NOT NULL DEFAULT 'app';
ALTER TABLE wazuh_compliance
  ADD COLUMN IF NOT EXISTS mail_server ENUM('app','campaign','both') NOT NULL DEFAULT 'app';

CREATE TABLE IF NOT EXISTS wazuh_clusters (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(128) NOT NULL,
  mail_server ENUM('app','campaign') NOT NULL,
  customer_id INT NOT NULL DEFAULT 1,
  api_url VARCHAR(255) NULL,
  indexer_url VARCHAR(255) NULL,
  active TINYINT NOT NULL DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_mail_server (mail_server, customer_id)
);

INSERT IGNORE INTO wazuh_clusters (name, mail_server, customer_id, active) VALUES
  ('App Mail Wazuh', 'app', 1, 1),
  ('Campaign Mail Wazuh', 'campaign', 1, 1);

CREATE TABLE IF NOT EXISTS mail_server_bindings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  customer_id INT NOT NULL,
  mail_server ENUM('app','campaign') NOT NULL,
  domains JSON NULL,
  vip_ip VARCHAR(64) NULL,
  notes VARCHAR(500) NULL,
  active TINYINT NOT NULL DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_cust_server (customer_id, mail_server)
);

-- ---- worktual_email_campaign (on BOTH app + campaign DB hosts) ----
-- ALTER TABLE email_quarantine ADD COLUMN IF NOT EXISTS server VARCHAR(20) NOT NULL DEFAULT 'app';
