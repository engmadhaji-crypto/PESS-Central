-- PESS centralized MySQL schema. MySQL 8.0.16+ recommended.
-- Run against a NEW database first. Do not run against production before backup/review.

CREATE TABLE IF NOT EXISTS app_users (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(80) NOT NULL UNIQUE,
  display_name VARCHAR(160) NOT NULL,
  pin_hash VARCHAR(255) NOT NULL,
  role ENUM('owner','admin','operator','viewer') NOT NULL DEFAULT 'operator',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS customers (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  legacy_id VARCHAR(100) NULL,
  name VARCHAR(200) NOT NULL,
  phone VARCHAR(40) NULL,
  address TEXT NULL,
  notes TEXT NULL,
  status ENUM('active','archived') NOT NULL DEFAULT 'active',
  extra JSON NULL,
  created_by BIGINT UNSIGNED NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  archived_at TIMESTAMP(3) NULL,
  UNIQUE KEY uq_customers_legacy_id (legacy_id),
  KEY idx_customers_name (name),
  KEY idx_customers_phone (phone),
  CONSTRAINT fk_customers_user FOREIGN KEY (created_by) REFERENCES app_users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS contracts (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  customer_id BIGINT UNSIGNED NOT NULL,
  legacy_id VARCHAR(100) NULL,
  contract_number VARCHAR(100) NULL,
  title VARCHAR(220) NOT NULL,
  description TEXT NULL,
  total_amount DECIMAL(15,2) NOT NULL DEFAULT 0,
  cost_amount DECIMAL(15,2) NOT NULL DEFAULT 0,
  currency CHAR(3) NOT NULL DEFAULT 'YER',
  status ENUM('draft','active','completed','cancelled','archived') NOT NULL DEFAULT 'active',
  start_date DATE NULL,
  end_date DATE NULL,
  extra JSON NULL,
  created_by BIGINT UNSIGNED NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  archived_at TIMESTAMP(3) NULL,
  UNIQUE KEY uq_contracts_legacy_id (legacy_id),
  KEY idx_contracts_customer (customer_id),
  KEY idx_contracts_status (status),
  CONSTRAINT fk_contracts_customer FOREIGN KEY (customer_id) REFERENCES customers(id),
  CONSTRAINT fk_contracts_user FOREIGN KEY (created_by) REFERENCES app_users(id) ON DELETE SET NULL,
  CONSTRAINT chk_contract_amounts CHECK (total_amount >= 0 AND cost_amount >= 0)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS contract_due_dates (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  contract_id BIGINT UNSIGNED NOT NULL,
  due_date DATE NOT NULL,
  amount DECIMAL(15,2) NOT NULL,
  label VARCHAR(160) NULL,
  status ENUM('pending','paid','overdue','cancelled') NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  KEY idx_due_contract_date (contract_id, due_date),
  CONSTRAINT fk_due_contract FOREIGN KEY (contract_id) REFERENCES contracts(id),
  CONSTRAINT chk_due_amount CHECK (amount >= 0)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS payments (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  customer_id BIGINT UNSIGNED NOT NULL,
  contract_id BIGINT UNSIGNED NULL,
  legacy_id VARCHAR(100) NULL,
  payment_date DATE NOT NULL,
  amount DECIMAL(15,2) NOT NULL,
  method VARCHAR(80) NULL,
  reference_no VARCHAR(120) NULL,
  notes TEXT NULL,
  status ENUM('posted','voided') NOT NULL DEFAULT 'posted',
  created_by BIGINT UNSIGNED NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  voided_at TIMESTAMP(3) NULL,
  UNIQUE KEY uq_payments_legacy_id (legacy_id),
  KEY idx_payments_customer_date (customer_id, payment_date),
  KEY idx_payments_contract_date (contract_id, payment_date),
  CONSTRAINT fk_payments_customer FOREIGN KEY (customer_id) REFERENCES customers(id),
  CONSTRAINT fk_payments_contract FOREIGN KEY (contract_id) REFERENCES contracts(id),
  CONSTRAINT fk_payments_user FOREIGN KEY (created_by) REFERENCES app_users(id) ON DELETE SET NULL,
  CONSTRAINT chk_payment_amount CHECK (amount > 0)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS payment_allocations (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  payment_id BIGINT UNSIGNED NOT NULL,
  contract_id BIGINT UNSIGNED NOT NULL,
  amount DECIMAL(15,2) NOT NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  KEY idx_alloc_contract (contract_id),
  CONSTRAINT fk_alloc_payment FOREIGN KEY (payment_id) REFERENCES payments(id),
  CONSTRAINT fk_alloc_contract FOREIGN KEY (contract_id) REFERENCES contracts(id),
  CONSTRAINT chk_alloc_amount CHECK (amount > 0)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS securityevents (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  event_type VARCHAR(100) NOT NULL,
  severity ENUM('info','low','medium','high','critical') NOT NULL DEFAULT 'info',
  actor_user_id BIGINT UNSIGNED NULL,
  ip_address VARBINARY(16) NULL,
  user_agent VARCHAR(500) NULL,
  request_id CHAR(36) NULL,
  metadata JSON NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  KEY idx_security_event_time (created_at),
  KEY idx_security_event_type (event_type),
  KEY idx_security_severity_time (severity, created_at),
  CONSTRAINT fk_security_actor FOREIGN KEY (actor_user_id) REFERENCES app_users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  entity_type VARCHAR(80) NOT NULL,
  entity_id BIGINT UNSIGNED NOT NULL,
  action ENUM('create','update','archive','void','restore','import') NOT NULL,
  actor_user_id BIGINT UNSIGNED NULL,
  before_data JSON NULL,
  after_data JSON NULL,
  request_id CHAR(36) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  KEY idx_audit_entity (entity_type, entity_id, created_at),
  KEY idx_audit_time (created_at),
  CONSTRAINT fk_audit_actor FOREIGN KEY (actor_user_id) REFERENCES app_users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS pin_attempts (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(80) NOT NULL,
  succeeded BOOLEAN NOT NULL,
  ip_address VARBINARY(16) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  KEY idx_pin_username_time (username, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS login_locks (
  username VARCHAR(80) NOT NULL PRIMARY KEY,
  failed_attempts INT UNSIGNED NOT NULL DEFAULT 0,
  locked_until TIMESTAMP(3) NULL,
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS alert_rules (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(160) NOT NULL,
  event_type VARCHAR(100) NOT NULL,
  min_severity ENUM('info','low','medium','high','critical') NOT NULL DEFAULT 'medium',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  webhook_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS alerts (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  rule_id BIGINT UNSIGNED NULL,
  security_event_id BIGINT UNSIGNED NULL,
  status ENUM('new','acknowledged','resolved') NOT NULL DEFAULT 'new',
  summary VARCHAR(500) NOT NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  KEY idx_alert_status_time (status, created_at),
  CONSTRAINT fk_alert_rule FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE SET NULL,
  CONSTRAINT fk_alert_event FOREIGN KEY (security_event_id) REFERENCES securityevents(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS alert_delivery_attempts (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  alert_id BIGINT UNSIGNED NOT NULL,
  channel ENUM('webhook') NOT NULL,
  outcome ENUM('queued','sent','failed') NOT NULL,
  http_status SMALLINT UNSIGNED NULL,
  response_excerpt VARCHAR(500) NULL,
  attempted_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  KEY idx_delivery_alert_time (alert_id, attempted_at),
  CONSTRAINT fk_delivery_alert FOREIGN KEY (alert_id) REFERENCES alerts(id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS system_settings (
  setting_key VARCHAR(120) NOT NULL PRIMARY KEY,
  setting_value JSON NOT NULL,
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB;
