-- ============================================================
-- Finance Tables for Officer Dashboard
-- Purpose: Create tables for financial transactions, expenses, budget, and audit logs
-- ============================================================

-- Expenses/Receipts Table
CREATE TABLE IF NOT EXISTS expenses (
  id INT AUTO_INCREMENT PRIMARY KEY,
  club_id INT NOT NULL,
  submitted_by INT, -- officer_id who submitted
  title VARCHAR(200) NOT NULL,
  description TEXT,
  amount DECIMAL(10, 2) NOT NULL,
  category VARCHAR(100), -- Equipment, Supplies, Events, etc.
  receipt_url VARCHAR(255), -- URL to uploaded receipt
  status VARCHAR(50) DEFAULT 'pending', -- pending, approved, rejected, flagged
  reviewed_by INT, -- officer_id who reviewed (auditor)
  reviewed_at TIMESTAMP NULL,
  notes TEXT, -- Review notes from auditor
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (club_id) REFERENCES clubs(id) ON DELETE CASCADE,
  FOREIGN KEY (submitted_by) REFERENCES officers(id) ON DELETE SET NULL,
  FOREIGN KEY (reviewed_by) REFERENCES officers(id) ON DELETE SET NULL,
  INDEX idx_club_status (club_id, status),
  INDEX idx_status (status),
  INDEX idx_created_at (created_at)
);

-- Budget Table
CREATE TABLE IF NOT EXISTS budget (
  id INT AUTO_INCREMENT PRIMARY KEY,
  club_id INT NOT NULL,
  fiscal_year YEAR NOT NULL, -- e.g., 2024
  total_budget DECIMAL(10, 2) NOT NULL,
  allocated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (club_id) REFERENCES clubs(id) ON DELETE CASCADE,
  UNIQUE KEY unique_club_year (club_id, fiscal_year),
  INDEX idx_club_year (club_id, fiscal_year)
);

-- Financial Reports Table
CREATE TABLE IF NOT EXISTS financial_reports (
  id INT AUTO_INCREMENT PRIMARY KEY,
  club_id INT NOT NULL,
  report_type VARCHAR(50) NOT NULL, -- monthly, quarterly, annual
  period_start DATE NOT NULL,
  period_end DATE NOT NULL,
  due_date DATE NOT NULL,
  status VARCHAR(50) DEFAULT 'pending', -- pending, submitted, approved
  submitted_by INT,
  submitted_at TIMESTAMP NULL,
  file_url VARCHAR(255), -- URL to uploaded report file
  notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (club_id) REFERENCES clubs(id) ON DELETE CASCADE,
  FOREIGN KEY (submitted_by) REFERENCES officers(id) ON DELETE SET NULL,
  INDEX idx_club_status (club_id, status),
  INDEX idx_due_date (due_date),
  INDEX idx_status (status)
);

-- Compliance Issues Table
CREATE TABLE IF NOT EXISTS compliance_issues (
  id INT AUTO_INCREMENT PRIMARY KEY,
  club_id INT NOT NULL,
  issue_type VARCHAR(100) NOT NULL, -- missing_receipt, budget_overrun, late_report, etc.
  severity VARCHAR(50) DEFAULT 'medium', -- low, medium, high, critical
  title VARCHAR(200) NOT NULL,
  description TEXT,
  status VARCHAR(50) DEFAULT 'open', -- open, in_review, resolved, closed
  flagged_by INT, -- officer_id (usually auditor)
  flagged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  resolved_by INT,
  resolved_at TIMESTAMP NULL,
  resolution_notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (club_id) REFERENCES clubs(id) ON DELETE CASCADE,
  FOREIGN KEY (flagged_by) REFERENCES officers(id) ON DELETE SET NULL,
  FOREIGN KEY (resolved_by) REFERENCES officers(id) ON DELETE SET NULL,
  INDEX idx_club_status (club_id, status),
  INDEX idx_status (status),
  INDEX idx_severity (severity)
);

-- Audit Log Table
CREATE TABLE IF NOT EXISTS audit_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  club_id INT NOT NULL,
  action_type VARCHAR(100) NOT NULL, -- expense_approved, expense_rejected, report_submitted, etc.
  entity_type VARCHAR(50) NOT NULL, -- expense, report, budget, etc.
  entity_id INT NOT NULL,
  performed_by INT, -- officer_id who performed the action
  description TEXT,
  changes JSON, -- Store before/after values if needed
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (club_id) REFERENCES clubs(id) ON DELETE CASCADE,
  FOREIGN KEY (performed_by) REFERENCES officers(id) ON DELETE SET NULL,
  INDEX idx_club_created (club_id, created_at),
  INDEX idx_entity (entity_type, entity_id),
  INDEX idx_performed_by (performed_by),
  INDEX idx_created_at (created_at)
);

