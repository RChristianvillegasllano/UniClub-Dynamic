import express from "express";
import { body, validationResult } from "express-validator";
import pool from "../config/db.js";
import { requireOfficer } from "./officerAuthRoutes.js";
import { writeLimiter, csrfProtection } from "../middleware/security.js";
import { canAccessPage, getDashboardPagesForRole, hasPermission, getPermissionsForRole } from "../config/tierPermissions.js";
import { uploadEventDocuments, uploadClubPhoto } from "../middleware/upload.js";
import { updateEventStatuses } from "../utils/eventStatus.js";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const router = express.Router();

// Profile picture upload route - must be before CSRF protection to handle JSON requests
router.post("/profile/picture", requireOfficer, requirePageAccess('home'), async (req, res) => {
  // Set JSON content type
  res.setHeader('Content-Type', 'application/json');
  
  try {
    const officer = req.session.officer;
    const officerId = officer?.id;

    if (!officerId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    // Manual CSRF validation for JSON requests
    const csrfToken = req.body._csrf || req.headers['x-csrf-token'];
    if (!csrfToken) {
      return res.status(403).json({ success: false, error: "CSRF token missing. Please refresh the page and try again." });
    }

    const { profile_picture } = req.body;

    // Validate profile picture (can be URL or base64 data URL)
    let pictureToStore = null;
    if (profile_picture && profile_picture.trim()) {
      const trimmed = profile_picture.trim();
      
      // Check if it's a base64 data URL (starts with data:image/)
      if (trimmed.startsWith('data:image/')) {
        // Store base64 data URL
        pictureToStore = trimmed;
      } else if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
        // Valid URL
        pictureToStore = trimmed;
      } else {
        return res.status(400).json({ success: false, error: "Invalid image format. Please use a valid URL or upload an image file." });
      }
    }

    // Ensure profile_picture column exists and is MEDIUMTEXT (supports larger data URLs / file paths)
    try {
      const colCheck = await pool.query(
        `SELECT DATA_TYPE 
           FROM information_schema.COLUMNS 
          WHERE TABLE_SCHEMA = DATABASE() 
            AND TABLE_NAME = 'officers' 
            AND COLUMN_NAME = 'profile_picture'`
      );
      if (!colCheck.rows.length) {
        await pool.query(`ALTER TABLE officers ADD COLUMN profile_picture MEDIUMTEXT`);
      } else {
        const dataType = (colCheck.rows[0]?.DATA_TYPE || '').toLowerCase();
        if (dataType !== 'mediumtext') {
          await pool.query(`ALTER TABLE officers MODIFY COLUMN profile_picture MEDIUMTEXT`);
        }
      }
    } catch (err) {
      console.error('Column ensure/modify failed for profile_picture:', err.message);
    }

    // Update profile picture
    await pool.query(
      `UPDATE officers SET profile_picture = ? WHERE id = ?`,
      [pictureToStore, officerId]
    );

    // Update session if it exists
    if (req.session.officer) {
      req.session.officer.profile_picture = pictureToStore;
    }

    res.json({ success: true, message: "Profile picture updated successfully" });
  } catch (error) {
    console.error("Error updating profile picture:", error);
    res.status(500).json({ success: false, error: "Failed to update profile picture" });
  }
});

// Apply CSRF protection to all POST/PUT/DELETE routes
router.use(csrfProtection);

async function ensureOfficerProfileColumns() {
  // MySQL doesn't support IF NOT EXISTS in ALTER TABLE, so we'll try to add columns and ignore errors if they exist
  const columnsToAdd = [
    { name: 'email', def: 'TEXT' },
    { name: 'facebook', def: 'TEXT' },
    { name: 'bio', def: 'TEXT' },
    { name: 'department', def: 'TEXT' },
    { name: 'program', def: 'TEXT' }
  ];
  
  for (const col of columnsToAdd) {
    try {
      await pool.query(`ALTER TABLE officers ADD COLUMN ${col.name} ${col.def}`);
    } catch (err) {
      // Silently ignore duplicate column errors (MySQL error code 1060)
      // These are expected when columns already exist
      const isDuplicateColumn = 
        err.code === 'ER_DUP_FIELDNAME' || 
        err.errno === 1060 || 
        err.message?.includes('Duplicate column name') || 
        err.sqlMessage?.includes('Duplicate column name');
      
      if (!isDuplicateColumn) {
        // Only log unexpected errors, but don't throw to avoid breaking the flow
        console.warn(`Warning: Could not add column ${col.name}:`, err.message);
      }
      // Continue silently for duplicate column errors
    }
  }
}

// List of valid academic programs
const VALID_PROGRAMS = [
  "Bachelor of Science in Accountancy",
  "Bachelor of Science in Management Accounting",
  "Bachelor of Arts Major in English Language",
  "Bachelor of Science in Psychology",
  "Bachelor of Science in Business Administration - Financial Management",
  "Bachelor of Science in Business Administration - Human Resource Management",
  "Bachelor of Science in Business Administration - Marketing Management",
  "Bachelor of Science in Information Technology",
  "Bachelor of Science in Computer Science",
  "Bachelor of Science in Criminology",
  "Bachelor of Science in Computer Engineering",
  "Bachelor of Science in Electrical Engineering",
  "Bachelor of Science in Electronics & Communications Engineering",
  "Bachelor of Science in Hospitality Management",
  "Bachelor of Science in Tourism Management",
  "Bachelor of Elementary Education",
  "Bachelor of Physical Education",
  "Bachelor of Secondary Education - Major in English",
  "Bachelor of Secondary Education - Major in Filipino",
  "Bachelor of Secondary Education - Major in General Science",
  "Bachelor of Secondary Education - Major in Mathematics",
  "Bachelor of Secondary Education - Major in Social Studies"
];

function normalizeProgramValue(value) {
  if (!value) return null;
  
  let programValue = null;
  
  if (Array.isArray(value)) {
    programValue = value
      .map((entry) => (typeof entry === "string" ? entry.trim() : entry))
      .filter((entry) => entry)
      .join(", ");
  } else if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) return null;
    const isPgArray = trimmed.startsWith("{") && trimmed.endsWith("}");
    if (isPgArray) {
      programValue = trimmed
        .slice(1, -1)
        .split(",")
        .map((entry) => entry.replace(/(^"|"$)/g, "").trim())
        .filter((entry) => entry)
        .join(", ");
    } else {
      programValue = trimmed;
    }
  } else {
    programValue = String(value);
  }
  
  // Filter out invalid program values (like club names, organization names, etc.)
  if (programValue) {
    const lowerValue = programValue.toLowerCase();
    
    // Check if it contains invalid keywords (club names, org names, etc.)
    const isInvalidValue = 
      lowerValue.includes('umtc') ||
      lowerValue.includes('prism') ||
      lowerValue.includes('club') ||
      lowerValue.includes('organization') ||
      lowerValue.includes('org');
    
    // Check if it's a valid program (case-insensitive partial match)
    const isValidProgram = VALID_PROGRAMS.some(validProgram => {
      const lowerValid = validProgram.toLowerCase();
      return lowerValue.includes(lowerValid) || lowerValid.includes(lowerValue);
    });
    
    // If it contains invalid keywords or doesn't match any valid program, return null
    if (isInvalidValue || (!isValidProgram && programValue.length < 15)) {
      return null;
    }
  }
  
  return programValue || null;
}

/**
 * Middleware to check if officer can access a specific dashboard page
 * @param {string} pageId - The dashboard page identifier (e.g., 'announcements', 'events', 'finance')
 */
function requirePageAccess(pageId) {
  return async (req, res, next) => {
    try {
      const officer = req.session?.officer;
      if (!officer) {
        return res.redirect("/officer/login");
      }

      const role = officer.role || '';
      const normalizedRole = role.toLowerCase().trim();
      
      // Hard allow for any president variant to avoid false 403
      // Use word boundary check to exclude "Vice President"
      if (normalizedRole.includes('vice')) {
        // Vice President is not a president-level role
      } else if (/\bpresident\b/.test(normalizedRole)) {
        return next();
      }
      
      const accessiblePages = getDashboardPagesForRole(role);
      
      // Parse permissions (may be stored as JSON string)
      let permissions = officer.permissions || [];
      if (typeof permissions === 'string') {
        try {
          permissions = JSON.parse(permissions);
        } catch (e) {
          permissions = [];
        }
      }
      if (!Array.isArray(permissions) && typeof permissions === 'object' && permissions !== null) {
        permissions = Object.keys(permissions).filter(k => permissions[k]);
      }
      
      // If permissions imply finance access, allow finance page
      if (pageId === 'finance') {
        const financePerms = ['view_financial_records', 'approve_expenses', 'record_transactions', 'manage_budget', 'generate_financial_reports', 'view_financial_reports'];
        const hasFinancePermission = Array.isArray(permissions) && permissions.some(p => financePerms.includes(p));
        if (hasFinancePermission) {
          return next();
        }
        // As a last resort to unblock presidents/VIPs with mismapped roles, allow authenticated officers through to finance.
        // The page itself enforces actions by permission, so view-only access here is safe.
        return next();
      }
      
      // If role is not defined in tier system, deny access (except for home/messages)
      if (!accessiblePages || accessiblePages.length === 0) {
        // Only allow home and messages for undefined roles
        if (pageId === 'home' || pageId === 'messages') {
          return next();
        }
        console.log(`[Access Denied] Officer ${officer.id} (${role}) has undefined role - attempted to access restricted page: ${pageId}`);
        return res.status(403).render("errors/403", {
          title: "Access Denied | UniClub",
          message: "You don't have permission to access this page. Your role is not properly configured.",
          officer,
        });
      }
      
      // Tier 1 (President) has access to all pages
      if (accessiblePages.includes('all')) {
        return next();
      }

      // Check if the officer can access this specific page
      if (!canAccessPage(role, pageId)) {
        // Attempt one-time refresh of role/permissions from DB before denying
        try {
          const { rows: freshRows } = await pool.query(
            `SELECT role, permissions 
               FROM officers 
              WHERE id = ? 
              LIMIT 1`,
            [officer.id]
          );
          if (freshRows && freshRows[0]) {
            const freshRole = freshRows[0].role || role;
            let freshPermissions = freshRows[0].permissions || permissions;
            if (typeof freshPermissions === 'string') {
              try { freshPermissions = JSON.parse(freshPermissions); } catch (e) { freshPermissions = []; }
            }
            if (!Array.isArray(freshPermissions) && typeof freshPermissions === 'object' && freshPermissions !== null) {
              freshPermissions = Object.keys(freshPermissions).filter(k => freshPermissions[k]);
            }

            // Update session with fresh data
            req.session.officer = {
              ...req.session.officer,
              role: freshRole,
              permissions: freshPermissions,
            };

            const freshNormalized = (freshRole || '').toLowerCase().trim();
            if (freshNormalized.includes('president')) {
              return next();
            }

            const freshPages = getDashboardPagesForRole(freshRole);
            if (freshPages.includes('all') || freshPages.includes(pageId) || canAccessPage(freshRole, pageId)) {
              if (pageId === 'finance') {
                const financePerms = ['view_financial_records', 'approve_expenses', 'record_transactions', 'manage_budget', 'generate_financial_reports', 'view_financial_reports'];
                const hasFinancePermission = Array.isArray(freshPermissions) && freshPermissions.some(p => financePerms.includes(p));
                if (hasFinancePermission) return next();
              }
              return next();
            }
          }
        } catch (refreshErr) {
          console.warn("Failed to refresh officer role/permissions before 403:", refreshErr.message);
        }

        console.log(`[Access Denied] Officer ${officer.id} (${role}) attempted to access restricted page: ${pageId}`);
        return res.status(403).render("errors/403", {
          title: "Access Denied | UniClub",
          message: "You don't have permission to access this page based on your role.",
          officer,
        });
      }

      next();
    } catch (error) {
      console.error("Error checking page access:", error);
      return res.status(500).render("errors/500", { title: "Server Error", error });
    }
  };
}

/**
 * Middleware to check if officer has a specific permission for actions (POST/PUT/DELETE)
 * @param {string} permission - The permission to check (e.g., 'create_events', 'approve_expenses')
 */
function requirePermission(permission) {
  return async (req, res, next) => {
    try {
      const officer = req.session?.officer;
      if (!officer) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      const role = officer.role || '';
      
      // Check if the officer has the required permission
      if (!hasPermission(role, permission)) {
        console.log(`[Permission Denied] Officer ${officer.id} (${role}) attempted action requiring permission: ${permission}`);
        return res.status(403).json({ 
          error: "You don't have permission to perform this action based on your role." 
        });
      }

      next();
    } catch (error) {
      console.error("Error checking permission:", error);
      return res.status(500).json({ error: "Server error" });
    }
  };
}

// Map route paths to tier dashboard page identifiers
const PAGE_MAPPING = {
  '/officer': 'home', // Dashboard home
  '/officer/member-approvals': 'members',
  '/officer/attendance': 'attendance',
  '/officer/analytics': 'reports',
  '/officer/messages': 'home', // Messages accessible to all
  '/officer/communication': 'announcements',
  '/officer/records': 'members',
  '/officer/records-roles': 'members',
  '/officer/records-requirements': 'documents',
  '/officer/finance': 'finance',
  '/officer/finance/reviews': 'finance',
  '/officer/finance/budget': 'finance',
  '/officer/finance/reports': 'finance',
  '/officer/finance/transactions': 'finance',
  '/officer/finance/audit': 'audit',
  '/officer/calendar': 'events',
  '/officer/calendar/create': 'events',
  '/officer/calendar/edit': 'events',
};

// Map sidebar menu items to tier dashboard page identifiers
const SIDEBAR_PAGE_MAPPING = {
  'dashboard': 'home',
  'approvals': 'members',
  'attendance': 'attendance',
  'analytics': 'reports',
  'messages': 'home', // Accessible to all
  'communication': 'announcements',
  'records': 'members',
  'records-roles': 'members',
  'records-requirements': 'documents',
};

// Helper function to get accessible pages for an officer
function getAccessiblePagesForOfficer(officer) {
  const role = officer?.role || '';
  return getDashboardPagesForRole(role);
}

// Middleware to add accessiblePages to all templates
function addAccessiblePagesToLocals(req, res, next) {
  const officer = req.session?.officer;
  if (officer) {
    const role = officer.role || '';
    const normalizedRole = role.toLowerCase().trim();
    let pages = getAccessiblePagesForOfficer(officer);
    // Presidents get full access even if the stored role string is slightly off
    // Use word boundary check to exclude "Vice President"
    if (normalizedRole.includes('vice')) {
      // Vice President is not a president-level role
    } else if (/\bpresident\b/.test(normalizedRole)) {
      pages = ['all'];
    }
    res.locals.accessiblePages = pages;
    res.locals.officerRole = role;
  } else {
    res.locals.accessiblePages = [];
    res.locals.officerRole = '';
  }
  next();
}

// Apply to all officer dashboard routes
router.use(addAccessiblePagesToLocals);

router.get("/", requireOfficer, requirePageAccess('home'), async (req, res) => {
  // Auto-update event statuses before loading dashboard
  await updateEventStatuses();
  
  try {
    const officer = { ...req.session.officer };
    if (officer && typeof officer.permissions === "string") {
      try {
        officer.permissions = JSON.parse(officer.permissions);
      } catch (err) {
        officer.permissions = {};
      }
    }

    const clubId = officer.club_id;

    const [
      { rows: clubs },
      { rows: announcements },
      { rows: attendance },
      applicationsResult,
      eventsResult,
      statsResult,
      membersResult,
      unreadMessagesResult
    ] = await Promise.all([
      pool.query(
        `SELECT id, name, description, adviser, category, department, program, status
           FROM clubs WHERE id = ?`,
        [clubId]
      ).catch(() => ({ rows: [] })),
      pool.query(
        `SELECT id, subject AS title, content AS message, audience, created_at
           FROM announcements
          WHERE club_id = ? OR audience = 'All Members'
          ORDER BY created_at DESC LIMIT 20`,
        [clubId]
      ).catch((err) => {
        // Handle missing table (MySQL error code 1146)
        if (err?.code === 'ER_NO_SUCH_TABLE' || err?.errno === 1146) {
          return { rows: [] };
        }
        return { rows: [] };
      }),
      pool.query(
        `SELECT id, member_name, status, created_at
           FROM attendance
          WHERE club_id = ?
          ORDER BY created_at DESC LIMIT 20`,
        [clubId]
      ).catch((err) => {
        // Handle missing table (MySQL error code 1146)
        if (err?.code === 'ER_NO_SUCH_TABLE' || err?.errno === 1146) {
          return { rows: [] };
        }
        return { rows: [] };
      }),
      pool.query(
        `SELECT id, name, applying_for, current_clubs, status, created_at
           FROM membership_applications
          WHERE club_id = ?
          ORDER BY created_at DESC LIMIT 20`,
        [clubId]
      ).catch((err) => {
        // Handle missing table (MySQL error code 1146 or PostgreSQL 42P01)
        if (err?.code === 'ER_NO_SUCH_TABLE' || err?.errno === 1146 || err?.code === "42P01") {
          return { rows: [] };
        }
        return { rows: [] };
      }),
      pool.query(
        `SELECT id, name, date, location, description, club_id
           FROM events
          WHERE club_id = ? 
            AND COALESCE(status, 'pending_approval') != 'pending_approval'
            AND COALESCE(status, 'pending_approval') != 'rejected'
            AND COALESCE(status, '') NOT IN ('Completed', 'completed', 'Cancelled', 'cancelled')
            -- Exclude events that have ended (show only upcoming and ongoing events)
            AND (
              -- Event is upcoming (date in future)
              DATE(date) > CURDATE()
              OR
              -- Event is ongoing (date is today or past, but end_date is today or future)
              (DATE(date) <= CURDATE() AND (end_date IS NULL OR DATE(end_date) >= CURDATE()))
              OR
              -- Event with no date (scheduled but date TBA)
              date IS NULL
            )
          ORDER BY date ASC LIMIT 10`,
        [clubId]
      ).catch(() => ({ rows: [] })),
      pool.query(
        `SELECT 
           COUNT(DISTINCT CASE WHEN status = 'Present' THEN id END) as present_count,
           COUNT(DISTINCT CASE WHEN status = 'Absent' THEN id END) as absent_count,
           COUNT(DISTINCT id) as total_attendance
         FROM attendance
         WHERE club_id = ?`,
        [clubId]
      ).catch((err) => {
        // Handle missing table
        if (err?.code === 'ER_NO_SUCH_TABLE' || err?.errno === 1146) {
          return { rows: [{ present_count: 0, absent_count: 0, total_attendance: 0 }] };
        }
        return { rows: [{ present_count: 0, absent_count: 0, total_attendance: 0 }] };
      }),
      pool.query(
        `SELECT COUNT(*) as total_members
         FROM membership_applications
         WHERE club_id = ? AND status = 'approved'`,
        [clubId]
      ).catch((err) => {
        // Handle missing table
        if (err?.code === 'ER_NO_SUCH_TABLE' || err?.errno === 1146) {
          return { rows: [{ total_members: 0 }] };
        }
        return { rows: [{ total_members: 0 }] };
      }),
      // Get unread message count
      (async () => {
        try {
          const officerId = officer.id;
          // First check if recipient_type column exists
          const columnCheck = await pool.query(`
            SELECT COLUMN_NAME 
            FROM INFORMATION_SCHEMA.COLUMNS 
            WHERE TABLE_SCHEMA = DATABASE() 
            AND TABLE_NAME = 'messages' 
            AND COLUMN_NAME = 'recipient_type'
          `).catch(() => ({ rows: [] }));
          
          if (columnCheck.rows.length > 0) {
            // Columns exist, use new query
            const unreadQuery = `
              SELECT COUNT(*) as count
              FROM messages
              WHERE ((recipient_type = 'officer' AND recipient_id = ?) 
                 OR (recipient_type = 'officer' AND recipient_id IS NULL))
                AND \`read\` = false
            `;
            const result = await pool.query(unreadQuery, [officerId]);
            return { rows: [{ count: result.rows[0]?.count || 0 }] };
          } else {
            // Columns don't exist, use fallback
            const fallback = await pool.query(
              `SELECT COUNT(*) as count FROM messages WHERE sender_name = 'Admin' AND \`read\` = false`
            ).catch(() => ({ rows: [{ count: 0 }] }));
            return { rows: [{ count: fallback.rows[0]?.count || 0 }] };
          }
        } catch (err) {
          // If any error, return 0
          return { rows: [{ count: 0 }] };
        }
      })(),
    ]);

    const applications = applicationsResult.rows || [];
    const events = eventsResult.rows || [];
    const stats = statsResult.rows[0] || { present_count: 0, absent_count: 0, total_attendance: 0 };
    const members = membersResult.rows[0] || { total_members: 0 };
    const unreadCount = Number(unreadMessagesResult.rows[0]?.count || 0);
    
    const pendingCount = applications.filter(app => 
      !app.status || app.status.toLowerCase() === 'pending'
    ).length;
    
    const approvedCount = applications.filter(app => 
      app.status && app.status.toLowerCase() === 'approved'
    ).length;
    
    const rejectedCount = applications.filter(app => 
      app.status && app.status.toLowerCase() === 'rejected'
    ).length;
    
    const totalMembers = Number(members.total_members) || 0;

    // Get accessible dashboard pages for sidebar filtering
    const role = officer.role || '';
    const accessiblePages = getDashboardPagesForRole(role);
    
    // Check if officer is auditor or has finance access
    const officerRoleLower = role.toLowerCase();
    const isAuditor = officerRoleLower.includes('auditor');
    const isTreasurer = officerRoleLower.includes('treasurer') || officerRoleLower.includes('finance');
    const isFinanceRole = isAuditor || isTreasurer;
    
    // Fetch financial data if officer has finance access
    let financialData = {
      pendingExpenses: [],
      pendingExpensesCount: 0,
      budget: null,
      budgetUtilization: 0,
      reportsDue: [],
      reportsDueCount: 0,
      complianceIssues: [],
      complianceIssuesCount: 0,
      recentTransactions: [],
      auditHistory: []
    };
    
    if (isFinanceRole) {
      try {
        const currentYear = new Date().getFullYear();
        const currentMonth = new Date().getMonth() + 1;
        const firstDayOfMonth = new Date(currentYear, currentMonth - 1, 1);
        const lastDayOfMonth = new Date(currentYear, currentMonth, 0);
        
        // Fetch pending expenses
        const pendingExpensesResult = await pool.query(
          `SELECT id, title, amount, category, status, created_at,
                  (SELECT CONCAT(first_name, ' ', last_name) FROM officers WHERE id = submitted_by) as submitted_by_name
           FROM expenses
           WHERE club_id = ? AND status = 'pending'
           ORDER BY created_at DESC LIMIT 10`,
          [clubId]
        ).catch(() => ({ rows: [] }));
        
        // Fetch budget information
        const budgetResult = await pool.query(
          `SELECT id, total_budget, fiscal_year
           FROM budget
           WHERE club_id = ? AND fiscal_year = ?
           ORDER BY fiscal_year DESC LIMIT 1`,
          [clubId, currentYear]
        ).catch(() => ({ rows: [] }));
        
        // Calculate budget utilization
        let totalBudget = 0;
        let totalSpent = 0;
        if (budgetResult.rows.length > 0) {
          totalBudget = Number(budgetResult.rows[0].total_budget) || 0;
          const spentResult = await pool.query(
            `SELECT COALESCE(SUM(amount), 0) as total_spent
             FROM expenses
             WHERE club_id = ? AND status IN ('approved', 'pending')
             AND YEAR(created_at) = ?`,
            [clubId, currentYear]
          ).catch(() => ({ rows: [{ total_spent: 0 }] }));
          totalSpent = Number(spentResult.rows[0]?.total_spent || 0);
        }
        
        const budgetUtilization = totalBudget > 0 ? Math.round((totalSpent / totalBudget) * 100) : 0;
        
        // Fetch reports due this month
        const reportsDueResult = await pool.query(
          `SELECT id, report_type, period_start, period_end, due_date, status, title
           FROM financial_reports
           WHERE club_id = ? 
           AND due_date >= ? AND due_date <= ?
           AND status != 'approved'
           ORDER BY due_date ASC LIMIT 10`,
          [clubId, firstDayOfMonth, lastDayOfMonth]
        ).catch(() => ({ rows: [] }));
        
        // Fetch compliance issues
        const complianceResult = await pool.query(
          `SELECT id, issue_type, severity, title, status, flagged_at
           FROM compliance_issues
           WHERE club_id = ? AND status IN ('open', 'in_review')
           ORDER BY 
             CASE severity
               WHEN 'critical' THEN 1
               WHEN 'high' THEN 2
               WHEN 'medium' THEN 3
               WHEN 'low' THEN 4
             END,
             flagged_at DESC
           LIMIT 10`,
          [clubId]
        ).catch(() => ({ rows: [] }));
        
        // Fetch recent transactions (approved expenses)
        const transactionsResult = await pool.query(
          `SELECT id, title, amount, category, status, created_at
           FROM expenses
           WHERE club_id = ? AND status = 'approved'
           ORDER BY created_at DESC LIMIT 10`,
          [clubId]
        ).catch(() => ({ rows: [] }));
        
        // Fetch audit history (for auditors only)
        let auditHistoryResult = { rows: [] };
        if (isAuditor) {
          auditHistoryResult = await pool.query(
            `SELECT id, action_type, entity_type, description, created_at,
                    (SELECT CONCAT(first_name, ' ', last_name) FROM officers WHERE id = performed_by) as performed_by_name
             FROM audit_logs
             WHERE club_id = ?
             ORDER BY created_at DESC LIMIT 10`,
            [clubId]
          ).catch(() => ({ rows: [] }));
        }
        
        financialData = {
          pendingExpenses: pendingExpensesResult.rows || [],
          pendingExpensesCount: pendingExpensesResult.rows?.length || 0,
          budget: budgetResult.rows[0] || null,
          totalBudget: totalBudget,
          totalSpent: totalSpent,
          budgetUtilization: budgetUtilization,
          reportsDue: reportsDueResult.rows || [],
          reportsDueCount: reportsDueResult.rows?.length || 0,
          complianceIssues: complianceResult.rows || [],
          complianceIssuesCount: complianceResult.rows?.length || 0,
          recentTransactions: transactionsResult.rows || [],
          auditHistory: auditHistoryResult.rows || []
        };
      } catch (err) {
        console.error("Error fetching financial data:", err);
        // Continue with empty financial data if tables don't exist yet
      }
    }

    // Get permissions for the role to pass to view
    const permissions = getPermissionsForRole(role);

    res.render("officer/dashboard", {
      title: "Officer Dashboard | UniClub",
      officer,
      club: clubs[0] || null,
      announcements,
      attendance,
      applications,
      events,
      pendingCount,
      approvedCount,
      unreadCount,
      rejectedCount,
      stats,
      totalMembers,
      accessiblePages,
      financialData, // Pass financial data to template
      permissions, // Pass permissions to view for action button checks
    });
  } catch (err) {
    console.error("Officer dashboard error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

// Settings page (GET) - accessible to all officers
router.get("/settings", requireOfficer, requirePageAccess('home'), async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;
    
    // Get club information including photo
    let club = null;
    if (clubId) {
      const { rows } = await pool.query(
        `SELECT id, name, photo FROM clubs WHERE id = ?`,
        [clubId]
      ).catch(() => ({ rows: [] }));
      club = rows[0] || null;
    }
    
    // Check if officer has permission to edit clubs
    const role = (officer.role || '').toLowerCase();
    const canEditClub = hasPermission(role, 'edit_clubs');
    
    res.render("officer/settings", {
      title: "Settings | UniClub",
      officer,
      club,
      canEditClub,
      submitted: false,
      csrfToken: req.csrfToken ? req.csrfToken() : ''
    });
  } catch (err) {
    console.error("Officer settings GET error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

// Settings submit (POST) - accessible to all officers
router.post("/settings", requireOfficer, requirePageAccess('home'), writeLimiter, async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    // In a full implementation, you'd validate and persist requests here:
    // - If action === 'update-name' => create admin approval request
    // - If action === 'update-account' => validate username, change password securely
    // For now, just reflect submission back to the page.
    res.render("officer/settings", {
      title: "Settings | UniClub",
      officer: {
        ...officer,
        // Echo inputs back for better UX
        name: req.body?.display_name || officer.name,
        username: req.body?.username || officer.username,
      },
      submitted: true,
    });
  } catch (err) {
    console.error("Officer settings POST error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

// Profile page (GET)
router.get("/profile", requireOfficer, requirePageAccess('home'), async (req, res) => {
  try {
    await ensureOfficerProfileColumns();
    
    // Ensure profile_picture column exists
    try {
      const colCheck = await pool.query(
        `SELECT DATA_TYPE 
           FROM information_schema.COLUMNS 
          WHERE TABLE_SCHEMA = DATABASE() 
            AND TABLE_NAME = 'officers' 
            AND COLUMN_NAME = 'profile_picture'`
      );
      if (!colCheck.rows.length) {
        await pool.query(`ALTER TABLE officers ADD COLUMN profile_picture MEDIUMTEXT`);
      }
    } catch (err) {
      console.error('Column check failed for profile_picture:', err.message);
    }
    
    const sessionOfficer = { ...(req.session.officer || {}) };
    const officerId = sessionOfficer.id;
    if (!officerId) return res.redirect("/officer/login");

    const { rows: officerRows } = await pool
      .query(
        `SELECT 
           id,
           first_name,
           last_name,
           CONCAT(first_name, ' ', last_name) AS name,
           role,
           department,
           program,
           email,
           facebook,
           bio,
           club_id,
           username,
           permissions,
           profile_picture
         FROM officers
         WHERE id = ?
         LIMIT 1`,
        [officerId]
      )
      .catch(() => ({ rows: [] }));

    let officer = { ...sessionOfficer };
    const dbOfficer = officerRows?.[0];
    if (dbOfficer) {
      const computedName =
        (dbOfficer.name || `${dbOfficer.first_name || ""} ${dbOfficer.last_name || ""}`).trim() ||
        officer.name ||
        "Officer";
      officer = {
        ...officer,
        ...dbOfficer,
        name: computedName,
      };
      req.session.officer = {
        ...req.session.officer,
        ...officer,
      };
    }

    let club = null;
    if (officer && officer.club_id) {
      const { rows } = await pool
        .query(
          `SELECT id, name, description, adviser, category, department, program
             FROM clubs WHERE id = ?`,
          [officer.club_id]
        )
        .catch(() => ({ rows: [] }));
      club = rows?.[0] || null;
    }

    res.render("officer/profile", {
      title: "Profile | UniClub",
      officer: {
        ...officer,
        role: officer?.role?.trim() || sessionOfficer.role || null,
        department:
          (officer?.department && officer.department.trim()) ||
          (club?.department && club.department.trim()) ||
          null,
        program:
          normalizeProgramValue(officer?.program) || normalizeProgramValue(club?.program) || null,
      },
      club,
      updated: req.query.updated === "1",
      csrfToken: req.csrfToken ? req.csrfToken() : ''
    });
  } catch (err) {
    console.error("Officer profile GET error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

router.post("/profile", 
  requireOfficer, 
  requirePageAccess('home'), 
  writeLimiter,
  body('role').optional().trim().isLength({ max: 100 }),
  body('email').optional().trim().isEmail().normalizeEmail(),
  body('facebook').optional().trim().isURL().withMessage('Facebook must be a valid URL'),
  body('bio').optional().trim().isLength({ max: 1000 }),
  async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render("officer/profile", {
      title: "Profile | UniClub",
      error: errors.array()[0].msg,
      officer: req.session.officer,
    });
  }
  try {
    await ensureOfficerProfileColumns();
    const officerId = req.session.officer?.id;
    if (!officerId) return res.redirect("/officer/login");

    const sanitize = (value) => {
      if (typeof value !== "string") return null;
      const trimmed = value.trim();
      return trimmed.length ? trimmed : null;
    };

    const role = sanitize(req.body.role);
    const email = sanitize(req.body.email);
    const facebook = sanitize(req.body.facebook);
    const bio = sanitize(req.body.bio);

    // Ensure profile_picture column exists before fetching
    try {
      const colCheck = await pool.query(
        `SELECT DATA_TYPE 
           FROM information_schema.COLUMNS 
          WHERE TABLE_SCHEMA = DATABASE() 
            AND TABLE_NAME = 'officers' 
            AND COLUMN_NAME = 'profile_picture'`
      );
      if (!colCheck.rows.length) {
        await pool.query(`ALTER TABLE officers ADD COLUMN profile_picture MEDIUMTEXT`);
      }
    } catch (err) {
      console.error('Column check failed for profile_picture:', err.message);
    }

    // MySQL doesn't support RETURNING, so update first then fetch
    await pool.query(
      `UPDATE officers
          SET role = ?,
              email = ?,
              facebook = ?,
              bio = ?
        WHERE id = ?`,
      [role, email, facebook, bio, officerId]
    );
    
    // Fetch the updated officer
    const { rows } = await pool.query(
      `SELECT 
          id,
          first_name,
          last_name,
          CONCAT(first_name, ' ', last_name) AS name,
          role,
          department,
          program,
          email,
          facebook,
          bio,
          club_id,
          username,
          permissions,
          profile_picture
        FROM officers
        WHERE id = ?`,
      [officerId]
    );

    const updatedOfficer = rows?.[0];
    if (updatedOfficer) {
      req.session.officer = {
        ...req.session.officer,
        ...updatedOfficer,
        name:
          (updatedOfficer.name ||
            `${updatedOfficer.first_name || ""} ${updatedOfficer.last_name || ""}`.trim()) ||
          req.session.officer.name,
      };
    }

    res.redirect("/officer/profile?updated=1");
  } catch (err) {
    console.error("Officer profile update error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

// Update Club Photo (for Tier 1 officers with edit_clubs permission)
router.post("/club/photo", requireOfficer, requirePermission('edit_clubs'), writeLimiter, uploadClubPhoto.single('photo'), async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;
    const officerId = officer.id;

    if (!clubId) {
      return res.status(400).json({ success: false, error: "No club assigned" });
    }

    // Verify officer has permission to edit clubs
    const role = (officer.role || '').toLowerCase();
    if (!hasPermission(role, 'edit_clubs')) {
      return res.status(403).json({ success: false, error: "You don't have permission to edit club photos" });
    }

    // Verify club belongs to officer
    const clubCheck = await pool.query(
      `SELECT id, photo FROM clubs WHERE id = ?`,
      [clubId]
    ).catch(() => ({ rows: [] }));

    if (clubCheck.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Club not found" });
    }

    const currentPhoto = clubCheck.rows[0].photo;

    // Handle photo deletion
    if (req.body.delete_photo === 'true' || req.body.delete_photo === 'on') {
      if (currentPhoto) {
        const filePath = path.join(__dirname, '../public', currentPhoto);
        fs.unlink(filePath, (err) => {
          if (err && err.code !== 'ENOENT') console.error('Error deleting old photo:', err);
        });
      }
      
      await pool.query(
        `UPDATE clubs SET photo = NULL WHERE id = ?`,
        [clubId]
      );

      return res.json({ 
        success: true, 
        message: "Club photo deleted successfully",
        photo: null
      });
    }

    // Handle photo upload
    if (!req.file) {
      return res.status(400).json({ success: false, error: "No photo file provided" });
    }

    // Delete old photo if exists
    if (currentPhoto) {
      const oldFilePath = path.join(__dirname, '../public', currentPhoto);
      fs.unlink(oldFilePath, (err) => {
        if (err && err.code !== 'ENOENT') console.error('Error deleting old photo:', err);
      });
    }

    // Update club photo
    const photoPath = `/img/clubs/${req.file.filename}`;
    await pool.query(
      `UPDATE clubs SET photo = ? WHERE id = ?`,
      [photoPath, clubId]
    );

    console.log(`[Club Photo] Officer ${officerId} updated photo for club ${clubId}`);

    res.json({ 
      success: true, 
      message: "Club photo updated successfully",
      photo: photoPath
    });
  } catch (error) {
    console.error("Error updating club photo:", error);
    
    // Delete uploaded file if there was an error
    if (req.file) {
      const filePath = path.join(__dirname, '../public/img/clubs', req.file.filename);
      fs.unlink(filePath, (err) => {
        if (err) console.error('Error deleting uploaded file:', err);
      });
    }
    
    res.status(500).json({ success: false, error: "Failed to update club photo" });
  }
});

// Member Approvals page (GET)
router.get("/member-approvals", requireOfficer, requirePageAccess('members'), async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const officerId = officer.id;
    const clubId = officer.club_id;

    // Get club info
    const { rows: clubs } = await pool.query(
      `SELECT id, name, description, adviser, category, department, program, status
         FROM clubs WHERE id = ?`,
      [clubId]
    ).catch(() => ({ rows: [] }));

    // Get unread message count
    let unreadCount = 0;
    try {
      // Check if recipient_type column exists
      const columnCheck = await pool.query(`
        SELECT COLUMN_NAME 
        FROM INFORMATION_SCHEMA.COLUMNS 
        WHERE TABLE_SCHEMA = DATABASE() 
        AND TABLE_NAME = 'messages' 
        AND COLUMN_NAME = 'recipient_type'
      `).catch(() => ({ rows: [] }));
      
      if (columnCheck.rows.length > 0) {
        // Columns exist, use new query
        const unreadQuery = `
          SELECT COUNT(*) as count
          FROM messages
          WHERE ((recipient_type = 'officer' AND recipient_id = ?) 
             OR (recipient_type = 'officer' AND recipient_id IS NULL))
            AND \`read\` = false
        `;
        const unreadResult = await pool.query(unreadQuery, [officerId]);
        unreadCount = Number(unreadResult.rows[0]?.count || 0);
      } else {
        // Columns don't exist, use fallback
        const fallback = await pool.query(
          `SELECT COUNT(*) as count FROM messages WHERE sender_name = 'Admin' AND \`read\` = false`
        ).catch(() => ({ rows: [{ count: 0 }] }));
        unreadCount = Number(fallback.rows[0]?.count || 0);
      }
    } catch (err) {
      unreadCount = 0;
    }

    // Get all membership applications
    let applicationsResult = { rows: [] };
    let tableExists = true;
    try {
      // First check if table exists
      const tableCheck = await pool.query(`
        SELECT COUNT(*) as count 
        FROM information_schema.tables 
        WHERE table_schema = DATABASE() 
        AND table_name = 'membership_applications'
      `).catch(() => ({ rows: [{ count: 0 }] }));
      
      tableExists = Number(tableCheck.rows[0]?.count || 0) > 0;
      
      if (tableExists) {
        applicationsResult = await pool.query(
          `SELECT id, name, student_id, applying_for, current_clubs, status, created_at
             FROM membership_applications
            WHERE club_id = ?
            ORDER BY 
              CASE WHEN status IS NULL OR LOWER(status) = 'pending' THEN 1 ELSE 2 END,
              created_at DESC`,
          [clubId]
        );
        console.log(`[Member Approvals] Found ${applicationsResult.rows.length} applications for club_id ${clubId}`);
      } else {
        console.warn('[Member Approvals] membership_applications table does not exist');
      }
    } catch (err) {
      // Handle missing table (MySQL error code 1146 or PostgreSQL 42P01)
      console.error('[Member Approvals] Error fetching applications:', err.message);
      if (err.code === 'ER_NO_SUCH_TABLE' || err.code === '42P01' || err.errno === 1146) {
        tableExists = false;
        console.warn('[Member Approvals] membership_applications table does not exist');
      }
      applicationsResult = { rows: [] };
    }

    const applications = applicationsResult.rows || [];
    
    const pendingCount = applications.filter(app => 
      !app.status || app.status.toLowerCase() === 'pending'
    ).length;
    
    const approvedCount = applications.filter(app => 
      app.status && app.status.toLowerCase() === 'approved'
    ).length;
    
    const rejectedCount = applications.filter(app => 
      app.status && app.status.toLowerCase() === 'rejected'
    ).length;

    // Get permissions and accessible pages for the role
    const role = officer.role || '';
    const permissions = getPermissionsForRole(role);
    const accessiblePages = getDashboardPagesForRole(role);

    res.render("officer/memberApprovals", {
      title: "Member Approvals | UniClub",
      officer,
      club: clubs[0] || null,
      applications,
      pendingCount,
      approvedCount,
      rejectedCount,
      unreadCount,
      tableExists,
      clubId,
      accessiblePages,
      permissions, // Pass permissions to view
      canApproveApplications: hasPermission(role, 'approve_applications'),
    });
  } catch (err) {
    console.error("Officer member approvals error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

// Attendance page (GET)
router.get("/attendance", requireOfficer, requirePageAccess('attendance'), async (req, res) => {
  // Auto-update event statuses before loading attendance page
  await updateEventStatuses();
  
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;

    // Get club info
    const { rows: clubs } = await pool.query(
      `SELECT id, name, description, adviser, category, department, program, status
         FROM clubs WHERE id = ?`,
      [clubId]
    ).catch(() => ({ rows: [] }));

    // We'll get all attendance from RSVP students below, so no need for separate attendance query
    // This prevents duplicates - all attendance comes from event_attendance via RSVP students
    const attendance = [];

    // Get stats from event_attendance - count all RSVP students
    const statsResult = await pool.query(
      `SELECT 
         COUNT(DISTINCT CASE WHEN ea.attendance_status = 'Present' THEN ea.id END) as present_count,
         COUNT(DISTINCT CASE WHEN ea.attendance_status = 'Absent' THEN ea.id END) as absent_count,
         COUNT(DISTINCT CASE WHEN (ea.attendance_status IS NULL OR ea.attendance_status = '' OR ea.attendance_status = 'Not Marked') THEN ea.id END) as not_marked_count,
         COUNT(DISTINCT ea.id) as total_count
       FROM event_attendance ea
       INNER JOIN events e ON ea.event_id = e.id
       WHERE e.club_id = ?`,
      [clubId]
    ).catch(() => ({ rows: [{ present_count: 0, absent_count: 0, not_marked_count: 0, total_count: 0 }] }));

    const stats = statsResult.rows[0] || { present_count: 0, absent_count: 0, not_marked_count: 0, total_count: 0 };

    const presentCount = Number(stats.present_count) || 0;
    const absentCount = Number(stats.absent_count) || 0;
    const notMarkedCount = Number(stats.not_marked_count) || 0;
    const totalCount = Number(stats.total_count) || 0;

    // Get events with RSVP data (exclude ended events)
    const eventsWithRSVPs = await pool.query(
      `SELECT 
        e.id,
        e.name,
        e.date,
        e.end_date,
        COALESCE(e.end_date, e.date) as end_date_calc,
        e.location,
        COALESCE(e.status, 'Scheduled') as event_status,
        COUNT(DISTINCT CASE WHEN ea.status = 'going' OR ea.status IS NULL THEN ea.id END) as going_count,
        COUNT(DISTINCT CASE WHEN ea.status = 'interested' THEN ea.id END) as interested_count,
        COUNT(DISTINCT ea.id) as total_rsvps
      FROM events e
      LEFT JOIN event_attendance ea ON ea.event_id = e.id
      WHERE e.club_id = ?
        AND COALESCE(e.status, 'pending_approval') != 'pending_approval'
        AND COALESCE(e.status, 'pending_approval') != 'rejected'
        AND COALESCE(e.status, '') NOT IN ('Completed', 'completed', 'Cancelled', 'cancelled')
        AND (e.posted_to_students = 1 OR e.posted_to_students IS NULL)
        -- Exclude events that have ended (show only upcoming and ongoing events)
        AND (
          -- Event is upcoming (date in future)
          DATE(e.date) > CURDATE()
          OR
          -- Event is ongoing (date is today or past, but end_date is today or future)
          (DATE(e.date) <= CURDATE() AND (e.end_date IS NULL OR DATE(e.end_date) >= CURDATE()))
          OR
          -- Event with no date (scheduled but date TBA)
          e.date IS NULL
        )
      GROUP BY e.id, e.name, e.date, e.end_date, e.location, e.status
      ORDER BY e.date ASC
      LIMIT 10`,
      [clubId]
    ).catch(() => ({ rows: [] }));

    // Get all RSVP'd students from all events (flattened list)
    const allRSVPStudents = [];
    for (const event of eventsWithRSVPs.rows || []) {
      // Calculate event status for this event using the same logic as updateEventStatuses
      let eventStatus = event.event_status;
      
      // Normalize the status from database
      if (eventStatus) {
        eventStatus = eventStatus.charAt(0).toUpperCase() + eventStatus.slice(1).toLowerCase();
      }
      
      // If status is not a final status (Ongoing, Completed, Cancelled), calculate it
      if (!eventStatus || !['Ongoing', 'Completed', 'Cancelled'].includes(eventStatus)) {
        const eventDate = event.date ? new Date(event.date) : null;
        const eventEndDate = event.end_date ? new Date(event.end_date) : eventDate;
        
        if (eventDate) {
          const today = new Date();
          today.setHours(0, 0, 0, 0);
          const eventDateOnly = new Date(eventDate);
          eventDateOnly.setHours(0, 0, 0, 0);
          const eventEndDateOnly = eventEndDate ? new Date(eventEndDate) : eventDateOnly;
          eventEndDateOnly.setHours(23, 59, 59, 999);
          
          // Check if today is between event date and end_date (inclusive)
          if (today >= eventDateOnly && today <= eventEndDateOnly) {
            eventStatus = 'Ongoing';
          } else if (today > eventEndDateOnly) {
            eventStatus = 'Completed';
          } else {
            eventStatus = 'Scheduled';
          }
        } else {
          eventStatus = 'Scheduled';
        }
      }
      
      const rsvpDetails = await pool.query(
        `SELECT 
          ea.id,
          ea.status as rsvp_status,
          ea.created_at as rsvp_date,
          COALESCE(ea.attendance_status, 'Not Marked') as attendance_status,
          e.id as event_id,
          e.name as event_name,
          e.date as event_date,
          e.end_date as event_end_date,
          s.id as student_id,
          s.first_name,
          s.last_name,
          CONCAT(s.first_name, ' ', s.last_name) as student_name,
          s.studentid,
          s.email,
          s.program,
          s.year_level,
          s.profile_picture
        FROM event_attendance ea
        INNER JOIN students s ON ea.student_id = s.id
        INNER JOIN events e ON ea.event_id = e.id
        WHERE ea.event_id = ?
        ORDER BY 
          CASE ea.status
            WHEN 'going' THEN 1
            WHEN 'interested' THEN 2
            ELSE 3
          END,
          ea.created_at DESC`,
        [event.id]
      ).catch(() => ({ rows: [] }));
      
      // Add each RSVP as a separate record with event info
      rsvpDetails.rows.forEach(rsvp => {
        allRSVPStudents.push({
          ...rsvp,
          event_name: event.name,
          event_date: event.date,
          event_id: event.id,
          event_status: eventStatus, // Use the calculated status from the event
          attendance_status: rsvp.attendance_status || 'Not Marked' // Include attendance status
        });
      });
    }

    // Get accessible pages and permissions for view
    const role = officer.role || '';
    const accessiblePages = getDashboardPagesForRole(role);
    const permissions = getPermissionsForRole(role);
    const canCreateAttendance = permissions.includes('create_attendance');

    res.render("officer/attendance", {
      title: "Attendance | UniClub",
      officer,
      club: clubs[0] || null,
      attendance,
      presentCount,
      absentCount,
      notMarkedCount,
      totalCount,
      rsvpStudents: allRSVPStudents,
      activePage: "attendance",
      accessiblePages,
      permissions,
      canCreateAttendance,
      csrfToken: req.csrfToken ? req.csrfToken() : ''
    });
  } catch (err) {
    console.error("Officer attendance error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

// Analytics page (GET)
router.get("/analytics", requireOfficer, requirePageAccess('reports'), async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const officerId = officer.id;
    const clubId = officer.club_id;

    // Get club info
    const { rows: clubs } = await pool.query(
      `SELECT id, name, description, adviser, category, department, program, status
         FROM clubs WHERE id = ?`,
      [clubId]
    ).catch(() => ({ rows: [] }));

    // Get all analytics data in parallel
    const [
      membersResult,
      attendanceStatsResult,
      applicationsResult,
      eventsResult,
      monthlyAttendanceResult,
      monthlyMembersResult,
      monthlyEventsResult
    ] = await Promise.all([
      // Total members
      pool.query(
        `SELECT COUNT(*) as total_members
         FROM membership_applications
         WHERE club_id = ? AND status = 'approved'`,
        [clubId]
      ).catch((err) => {
        if (err?.code === 'ER_NO_SUCH_TABLE' || err?.errno === 1146) {
          return { rows: [{ total_members: 0 }] };
        }
        return { rows: [{ total_members: 0 }] };
      }),
      
      // Attendance stats from event_attendance
      pool.query(
        `SELECT 
           COUNT(DISTINCT CASE WHEN ea.attendance_status = 'Present' THEN ea.id END) as present_count,
           COUNT(DISTINCT CASE WHEN ea.attendance_status = 'Absent' THEN ea.id END) as absent_count,
           COUNT(DISTINCT CASE WHEN ea.attendance_status IN ('Present', 'Absent') THEN ea.id END) as total_attendance
         FROM event_attendance ea
         INNER JOIN events e ON ea.event_id = e.id
         WHERE e.club_id = ?`,
        [clubId]
      ).catch((err) => {
        if (err?.code === 'ER_NO_SUCH_TABLE' || err?.errno === 1146) {
          return { rows: [{ present_count: 0, absent_count: 0, total_attendance: 0 }] };
        }
        return { rows: [{ present_count: 0, absent_count: 0, total_attendance: 0 }] };
      }),
      
      // Applications stats
      pool.query(
        `SELECT 
           COUNT(CASE WHEN status IS NULL OR LOWER(status) = 'pending' THEN 1 END) as pending_count,
           COUNT(CASE WHEN LOWER(status) = 'approved' THEN 1 END) as approved_count,
           COUNT(CASE WHEN LOWER(status) = 'rejected' THEN 1 END) as rejected_count,
           COUNT(*) as total_applications
         FROM membership_applications
         WHERE club_id = ?`,
        [clubId]
      ).catch((err) => {
        if (err?.code === 'ER_NO_SUCH_TABLE' || err?.errno === 1146) {
          return { rows: [{ pending_count: 0, approved_count: 0, rejected_count: 0, total_applications: 0 }] };
        }
        return { rows: [{ pending_count: 0, approved_count: 0, rejected_count: 0, total_applications: 0 }] };
      }),
      
      // Events stats (exclude ended events from upcoming count)
      pool.query(
        `SELECT 
           COUNT(*) as total_events,
           COUNT(CASE WHEN (
             -- Event is upcoming (date in future)
             DATE(date) > CURDATE()
             OR
             -- Event is ongoing (date is today or past, but end_date is today or future)
             (DATE(date) <= CURDATE() AND (end_date IS NULL OR DATE(end_date) >= CURDATE()))
             OR
             -- Event with no date (scheduled but date TBA)
             date IS NULL
           ) AND COALESCE(status, '') NOT IN ('Completed', 'completed', 'Cancelled', 'cancelled') THEN 1 END) as upcoming_events
         FROM events
         WHERE club_id = ?
           AND COALESCE(status, 'pending_approval') != 'pending_approval'
           AND COALESCE(status, 'pending_approval') != 'rejected'`,
        [clubId]
      ).catch(() => ({ rows: [{ total_events: 0, upcoming_events: 0 }] })),
      
      // Monthly attendance (last 6 months) from event_attendance
      pool.query(
        `SELECT 
           DATE_FORMAT(ea.updated_at, '%Y-%m') as month,
           COUNT(CASE WHEN ea.attendance_status = 'Present' THEN 1 END) as present,
           COUNT(CASE WHEN ea.attendance_status = 'Absent' THEN 1 END) as absent,
           COUNT(CASE WHEN ea.attendance_status IN ('Present', 'Absent') THEN 1 END) as total
         FROM event_attendance ea
         INNER JOIN events e ON ea.event_id = e.id
         WHERE e.club_id = ? 
           AND ea.updated_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
           AND ea.attendance_status IN ('Present', 'Absent')
         GROUP BY DATE_FORMAT(ea.updated_at, '%Y-%m')
         ORDER BY month ASC`,
        [clubId]
      ).catch(() => ({ rows: [] })),
      
      // Monthly members (last 6 months)
      pool.query(
        `SELECT 
           DATE_FORMAT(created_at, '%Y-%m') as month,
           COUNT(*) as new_members
         FROM membership_applications
         WHERE club_id = ? 
           AND status = 'approved'
           AND created_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
         GROUP BY DATE_FORMAT(created_at, '%Y-%m')
         ORDER BY month ASC`,
        [clubId]
      ).catch((err) => {
        if (err?.code === 'ER_NO_SUCH_TABLE' || err?.errno === 1146) {
          return { rows: [] };
        }
        return { rows: [] };
      }),
      
      // Monthly events (last 6 months)
      pool.query(
        `SELECT 
           DATE_FORMAT(COALESCE(date, created_at), '%Y-%m') as month,
           COUNT(*) as events_count
         FROM events
         WHERE club_id = ? 
           AND COALESCE(date, created_at) >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
         GROUP BY DATE_FORMAT(COALESCE(date, created_at), '%Y-%m')
         ORDER BY month ASC`,
        [clubId]
      ).catch(() => ({ rows: [] }))
    ]);

    const totalMembers = Number(membersResult.rows[0]?.total_members || 0);
    const attendanceStats = attendanceStatsResult.rows[0] || { present_count: 0, absent_count: 0, total_attendance: 0 };
    const appStats = applicationsResult.rows[0] || { pending_count: 0, approved_count: 0, rejected_count: 0, total_applications: 0 };
    const eventStats = eventsResult.rows[0] || { total_events: 0, upcoming_events: 0 };
    
    // Format monthly data with proper month labels
    const monthlyAttendance = (monthlyAttendanceResult.rows || []).map(row => ({
      month: row.month,
      present: Number(row.present || 0),
      absent: Number(row.absent || 0),
      total: Number(row.total || 0)
    }));
    
    const monthlyMembers = (monthlyMembersResult.rows || []).map(row => ({
      month: row.month,
      new_members: Number(row.new_members || 0)
    }));
    
    const monthlyEvents = (monthlyEventsResult.rows || []).map(row => ({
      month: row.month,
      events_count: Number(row.events_count || 0)
    }));

    // Calculate attendance rate
    const totalAttendance = Number(attendanceStats.total_attendance) || 0;
    const presentCount = Number(attendanceStats.present_count) || 0;
    const attendanceRate = totalAttendance > 0 ? Math.round((presentCount / totalAttendance) * 100) : 0;

    // Calculate growth (comparing last month to previous month)
    const lastMonthMembers = monthlyMembers.length > 0 ? monthlyMembers[monthlyMembers.length - 1]?.new_members || 0 : 0;
    const prevMonthMembers = monthlyMembers.length > 1 ? monthlyMembers[monthlyMembers.length - 2]?.new_members || 0 : 0;
    const memberGrowth = prevMonthMembers > 0 
      ? Math.round(((lastMonthMembers - prevMonthMembers) / prevMonthMembers) * 100) 
      : (lastMonthMembers > 0 ? 100 : 0);

    // Get unread message count
    let unreadCount = 0;
    try {
      const officerId = officer.id;
      // Check if recipient_type column exists
      const columnCheck = await pool.query(`
        SELECT COLUMN_NAME 
        FROM INFORMATION_SCHEMA.COLUMNS 
        WHERE TABLE_SCHEMA = DATABASE() 
        AND TABLE_NAME = 'messages' 
        AND COLUMN_NAME = 'recipient_type'
      `).catch(() => ({ rows: [] }));
      
      if (columnCheck.rows.length > 0) {
        // Columns exist, use new query
        const unreadQuery = `
          SELECT COUNT(*) as count
          FROM messages
          WHERE ((recipient_type = 'officer' AND recipient_id = ?) 
             OR (recipient_type = 'officer' AND recipient_id IS NULL))
            AND \`read\` = false
        `;
        const unreadResult = await pool.query(unreadQuery, [officerId]);
        unreadCount = Number(unreadResult.rows[0]?.count || 0);
      } else {
        // Columns don't exist, use fallback
        const fallback = await pool.query(
          `SELECT COUNT(*) as count FROM messages WHERE sender_name = 'Admin' AND \`read\` = false`
        ).catch(() => ({ rows: [{ count: 0 }] }));
        unreadCount = Number(fallback.rows[0]?.count || 0);
      }
    } catch (err) {
      unreadCount = 0;
    }

    // Get accessible pages and permissions for view
    const role = officer.role || '';
    const accessiblePages = getDashboardPagesForRole(role);
    const permissions = getPermissionsForRole(role);

    res.render("officer/analytics", {
      title: "Analytics | UniClub",
      officer,
      club: clubs[0] || null,
      accessiblePages,
      permissions,
      totalMembers,
      attendanceStats: {
        present: presentCount,
        absent: Number(attendanceStats.absent_count) || 0,
        total: totalAttendance,
        rate: attendanceRate
      },
      appStats: {
        pending: Number(appStats.pending_count) || 0,
        approved: Number(appStats.approved_count) || 0,
        rejected: Number(appStats.rejected_count) || 0,
        total: Number(appStats.total_applications) || 0
      },
      eventStats: {
        total: Number(eventStats.total_events) || 0,
        upcoming: Number(eventStats.upcoming_events) || 0
      },
      monthlyAttendance,
      monthlyMembers,
      monthlyEvents,
      memberGrowth,
      unreadCount,
    });
  } catch (err) {
    console.error("Officer analytics error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

// Messages/Inbox for officers
router.get("/messages", requireOfficer, requirePageAccess('home'), async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const officerId = officer.id;
    const clubId = officer.club_id;

    // Get club information
    const clubResult = await pool.query(
      `SELECT id, name, description, adviser, category, department, program, status
       FROM clubs WHERE id = ?`,
      [clubId]
    ).catch(() => ({ rows: [] }));

    // Get messages sent to this specific officer OR to all officers
    let messagesResult;
    // First check if recipient_type column exists
    const columnCheck = await pool.query(`
      SELECT COLUMN_NAME 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = 'messages' 
      AND COLUMN_NAME = 'recipient_type'
    `).catch(() => ({ rows: [] }));
    
    if (columnCheck.rows.length > 0) {
      // Columns exist, use new query
      try {
        const messagesQuery = `
          SELECT id, sender_name, sender_email, subject, content, created_at, \`read\`, recipient_type, recipient_id, recipient_name
          FROM messages
          WHERE (recipient_type = 'officer' AND recipient_id = ?) 
             OR (recipient_type = 'officer' AND (recipient_id IS NULL OR recipient_id = 0))
             OR (recipient_type IS NULL AND sender_name = 'Admin')
          ORDER BY created_at DESC
        `;
        messagesResult = await pool.query(messagesQuery, [officerId]);
      } catch (err) {
        // If query fails, use fallback
        const fallbackQuery = `
          SELECT id, sender_name, sender_email, subject, content, created_at, \`read\`
          FROM messages
          WHERE sender_name = 'Admin' OR sender_email = 'admin@uniclub.local'
          ORDER BY created_at DESC
        `;
        messagesResult = await pool.query(fallbackQuery).catch(() => ({ rows: [] }));
      }
    } else {
      // Columns don't exist, use fallback
      const fallbackQuery = `
        SELECT id, sender_name, sender_email, subject, content, created_at, \`read\`
        FROM messages
        WHERE sender_name = 'Admin' OR sender_email = 'admin@uniclub.local'
        ORDER BY created_at DESC
      `;
      messagesResult = await pool.query(fallbackQuery).catch(() => ({ rows: [] }));
    }

    // Count unread messages
    const unreadCount = messagesResult.rows.filter(m => !m.read).length;

    res.render("officer/messages", {
      title: "Messages | UniClub",
      officer,
      club: clubResult.rows[0] || null,
      messages: messagesResult.rows || [],
      unreadCount,
    });
  } catch (err) {
    console.error("Officer messages error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

// View a single message (mark as read)
router.get("/messages/view/:id", requireOfficer, requirePageAccess('home'), async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const officerId = officer.id;
    const clubId = officer.club_id;
    const messageId = req.params.id;

    // Get club information
    const clubResult = await pool.query(
      `SELECT id, name, description, adviser, category, department, program, status
       FROM clubs WHERE id = ?`,
      [clubId]
    ).catch(() => ({ rows: [] }));

    // Get message and verify it's for this officer
    let messageResult;
    // First check if recipient_type column exists
    const columnCheck = await pool.query(`
      SELECT COLUMN_NAME 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = 'messages' 
      AND COLUMN_NAME = 'recipient_type'
    `).catch(() => ({ rows: [] }));
    
    if (columnCheck.rows.length > 0) {
      // Columns exist, use new query
      try {
        messageResult = await pool.query(
          `SELECT id, sender_name, sender_email, subject, content, created_at, \`read\`, recipient_type, recipient_id, recipient_name
           FROM messages
           WHERE id = ? AND ((recipient_type = 'officer' AND recipient_id = ?) OR (recipient_type = 'officer' AND recipient_id IS NULL) OR (recipient_type IS NULL))
          `,
          [messageId, officerId]
        );
      } catch (err) {
        // If query fails, use fallback
        messageResult = await pool.query(
          `SELECT id, sender_name, sender_email, subject, content, created_at, \`read\`
           FROM messages
           WHERE id = ?
          `,
          [messageId]
        );
      }
    } else {
      // Columns don't exist, use fallback
      messageResult = await pool.query(
        `SELECT id, sender_name, sender_email, subject, content, created_at, \`read\`
         FROM messages
         WHERE id = ?
        `,
        [messageId]
      );
    }

    if (messageResult.rows.length === 0) {
      return res.redirect("/officer/messages");
    }

    const message = messageResult.rows[0];

    // Mark as read
    if (!message.read) {
      await pool.query("UPDATE messages SET `read` = true WHERE id = ?", [messageId]);
      message.read = true;
    }

    // Get updated unread count
    let unreadCount = 0;
    // Check if recipient_type column exists
    const unreadColumnCheck = await pool.query(`
      SELECT COLUMN_NAME 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = 'messages' 
      AND COLUMN_NAME = 'recipient_type'
    `).catch(() => ({ rows: [] }));
    
    if (unreadColumnCheck.rows.length > 0) {
      // Columns exist, use new query
      try {
        const unreadQuery = `
          SELECT COUNT(*) as count
          FROM messages
          WHERE ((recipient_type = 'officer' AND recipient_id = ?) 
             OR (recipient_type = 'officer' AND recipient_id IS NULL))
            AND \`read\` = false
        `;
        const unreadResult = await pool.query(unreadQuery, [officerId]);
        unreadCount = Number(unreadResult.rows[0]?.count || 0);
      } catch {
        unreadCount = 0;
      }
    } else {
      // Fallback if recipient columns don't exist
      try {
        const fallback = await pool.query(
          `SELECT COUNT(*) as count FROM messages WHERE sender_name = 'Admin' AND \`read\` = false`
        );
        unreadCount = Number(fallback.rows[0]?.count || 0);
      } catch {
        unreadCount = 0;
      }
    }

    res.render("officer/viewMessage", {
      title: "View Message | UniClub",
      officer,
      club: clubResult.rows[0] || null,
      message,
      unreadCount,
    });
  } catch (err) {
    console.error("Error viewing message:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

// Communication hub (GET)
router.get("/communication", requireOfficer, requirePageAccess('announcements'), async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;

    const [{ rows: clubs }, { rows: announcements }] = await Promise.all([
      pool.query(
        `SELECT id, name, description, adviser, category, department, program, status
           FROM clubs WHERE id = ?`,
        [clubId]
      ).catch(() => ({ rows: [] })),
      pool.query(
        `SELECT id, subject AS title, content AS message, audience, created_at
           FROM announcements
          WHERE club_id = ? OR audience = 'All Members'
          ORDER BY created_at DESC LIMIT 50`,
        [clubId]
      ).catch(() => ({ rows: [] })),
    ]);

    const stats = {
      total: announcements.length,
      targeted: announcements.filter(
        (a) => a.audience && a.audience !== "All Members"
      ).length,
      lastSent: announcements[0]?.created_at || null,
    };

    // Get permissions and accessible pages for the role
    const role = (officer.role || '').toLowerCase();
    const permissions = getPermissionsForRole(role);
    const accessiblePages = getDashboardPagesForRole(role);

    res.render("officer/communication", {
      title: "Communication Center | UniClub",
      officer,
      club: clubs[0] || null,
      announcements,
      stats,
      audienceOptions: ["All Members", "Officers Only", "New Members"],
      accessiblePages,
      permissions, // Pass permissions to view
      canPostAnnouncements: hasPermission(role, 'post_announcements'),
      canEditAnnouncements: hasPermission(role, 'edit_announcements'),
      canDeleteAnnouncements: hasPermission(role, 'delete_announcements'),
    });
  } catch (err) {
    console.error("Officer communication error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

router.get("/records", requireOfficer, async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;
    const role = (officer.role || '').toLowerCase();
    const isAuditor = role.includes('auditor');
    const isTreasurer = role.includes('treasurer') || role.includes('finance');
    const isSecretary = role.includes('secretary');
    
    // Check page access - auditors can access for financial records, treasurers for finance, secretaries for documents, others need members access
    const accessiblePages = getDashboardPagesForRole(role);
    const hasAllAccess = accessiblePages.includes('all');
    const hasMembersAccess = hasAllAccess || accessiblePages.includes('members');
    const hasFinanceAccess = hasAllAccess || accessiblePages.includes('finance');
    const hasDocumentsAccess = hasAllAccess || accessiblePages.includes('documents');
    
    // Allow access if they have any of the required permissions
    if (!hasAllAccess && !isAuditor && !isTreasurer && !isSecretary) {
      if (!hasMembersAccess && !hasFinanceAccess && !hasDocumentsAccess) {
        return res.status(403).render("errors/403", {
          title: "Access Denied | UniClub",
          message: "You don't have permission to access this page based on your role.",
          officer,
        });
      }
    }
    
    // Get filter parameters
    const statusFilter = req.query.status || 'All';
    const searchQuery = req.query.search || '';
    const roleFilter = req.query.role || 'all roles';
    
    // Build query for members (from membership_applications)
    let membersQuery = `
      SELECT 
        ma.id,
        ma.student_id,
        ma.name,
        ma.status,
        ma.created_at,
        ma.applying_for,
        s.first_name,
        s.last_name,
        s.email,
        s.studentid,
        s.department,
        s.program,
        s.year_level,
        s.profile_picture,
        o.role as officer_role,
        o.id as officer_id
      FROM membership_applications ma
      LEFT JOIN students s ON s.id = ma.student_id
      LEFT JOIN officers o ON o.studentid = s.studentid AND o.club_id = ?
      WHERE ma.club_id = ?
    `;
    
    const queryParams = [clubId, clubId];
    
    // Apply status filter
    if (statusFilter !== 'All') {
      if (statusFilter === 'Active') {
        membersQuery += ` AND (ma.status = 'approved' OR ma.status = 'Approved')`;
      } else if (statusFilter === 'Pending') {
        membersQuery += ` AND (ma.status IS NULL OR ma.status = 'pending' OR ma.status = 'Pending')`;
      } else if (statusFilter === 'Alumni') {
        membersQuery += ` AND ma.status = 'alumni'`;
      }
    }
    
    // Apply search filter
    if (searchQuery) {
      membersQuery += ` AND (
        ma.name LIKE ? OR 
        s.first_name LIKE ? OR 
        s.last_name LIKE ? OR 
        s.email LIKE ? OR 
        s.studentid LIKE ?
      )`;
      const searchParam = `%${searchQuery}%`;
      queryParams.push(searchParam, searchParam, searchParam, searchParam, searchParam);
    }
    
    // Apply role filter
    if (roleFilter === 'officer') {
      membersQuery += ` AND o.id IS NOT NULL`;
    } else if (roleFilter === 'member') {
      membersQuery += ` AND o.id IS NULL`;
    }
    
    membersQuery += ` ORDER BY ma.created_at DESC`;
    
    // Query for statistics (all members, no filters)
    const statsQuery = `
      SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN ma.status = 'approved' OR ma.status = 'Approved' THEN 1 ELSE 0 END) as active,
        SUM(CASE WHEN ma.status IS NULL OR ma.status = 'pending' OR ma.status = 'Pending' THEN 1 ELSE 0 END) as pending,
        SUM(CASE WHEN ma.status = 'alumni' THEN 1 ELSE 0 END) as alumni
      FROM membership_applications ma
      WHERE ma.club_id = ?
    `;
    
    // Fetch data - include financial data for auditors
    const fetchPromises = [
      pool.query(
        `SELECT id, name, description, adviser, category, department, program, status
         FROM clubs WHERE id = ?`,
        [clubId]
      ).catch(() => ({ rows: [] })),
      pool.query(membersQuery, queryParams).catch(() => ({ rows: [] })),
      pool.query(
        `SELECT id, CONCAT(first_name, ' ', last_name) AS name, role, studentid
         FROM officers
         WHERE club_id = ?`,
        [clubId]
      ).catch(() => ({ rows: [] })),
      pool.query(
        `SELECT COUNT(*) as count
         FROM requirements
         WHERE club_id = ?`,
        [clubId]
      ).catch(() => ({ rows: [{ count: 0 }] })),
      pool.query(statsQuery, [clubId]).catch(() => ({ rows: [{ total: 0, active: 0, pending: 0, alumni: 0 }] }))
    ];
    
    // Add financial data queries for auditors
    if (isAuditor) {
      const currentYear = new Date().getFullYear();
      const currentMonth = new Date().getMonth() + 1;
      
      fetchPromises.push(
        // Pending expenses (for review)
        pool.query(
          `SELECT e.id, e.title, e.description, e.amount, e.category, e.status, e.receipt_url, e.created_at,
                  e.submitted_by,
                  (SELECT CONCAT(first_name, ' ', last_name) FROM officers WHERE id = e.submitted_by) as submitted_by_name
           FROM expenses e
           WHERE e.club_id = ? AND e.status = 'pending'
           ORDER BY e.created_at DESC`,
          [clubId]
        ).catch(() => ({ rows: [] })),
        // All financial transactions
        pool.query(
          `SELECT e.id, e.title, e.description, e.amount, e.category, e.status, e.receipt_url, e.created_at,
                  e.submitted_by, e.reviewed_by, e.reviewed_at, e.notes,
                  (SELECT CONCAT(first_name, ' ', last_name) FROM officers WHERE id = e.submitted_by) as submitted_by_name,
                  (SELECT CONCAT(first_name, ' ', last_name) FROM officers WHERE id = e.reviewed_by) as reviewed_by_name
           FROM expenses e
           WHERE e.club_id = ?
           ORDER BY e.created_at DESC LIMIT 50`,
          [clubId]
        ).catch(() => ({ rows: [] })),
        // Budget information
        pool.query(
          `SELECT id, total_budget, fiscal_year, notes
           FROM budget
           WHERE club_id = ? AND fiscal_year = ?
           ORDER BY fiscal_year DESC LIMIT 1`,
          [clubId, currentYear]
        ).catch(() => ({ rows: [] })),
        // Financial reports
        pool.query(
          `SELECT id, report_type, period_start, period_end, due_date, status, file_url, notes, created_at
           FROM financial_reports
           WHERE club_id = ?
           ORDER BY due_date ASC LIMIT 20`,
          [clubId]
        ).catch(() => ({ rows: [] })),
        // Compliance issues
        pool.query(
          `SELECT id, issue_type, severity, title, description, status, flagged_at,
                  (SELECT CONCAT(first_name, ' ', last_name) FROM officers WHERE id = flagged_by) as flagged_by_name
           FROM compliance_issues
           WHERE club_id = ?
           ORDER BY 
             CASE severity
               WHEN 'critical' THEN 1
               WHEN 'high' THEN 2
               WHEN 'medium' THEN 3
               WHEN 'low' THEN 4
             END,
             flagged_at DESC`,
          [clubId]
        ).catch(() => ({ rows: [] })),
        // Audit logs
        pool.query(
          `SELECT id, action_type, entity_type, entity_id, description, created_at,
                  (SELECT CONCAT(first_name, ' ', last_name) FROM officers WHERE id = performed_by) as performed_by_name
           FROM audit_logs
           WHERE club_id = ?
           ORDER BY created_at DESC LIMIT 50`,
          [clubId]
        ).catch(() => ({ rows: [] })),
        // Total spent this year
        pool.query(
          `SELECT COALESCE(SUM(amount), 0) as total_spent
           FROM expenses
           WHERE club_id = ? AND status IN ('approved', 'pending')
           AND YEAR(created_at) = ?`,
          [clubId, currentYear]
        ).catch(() => ({ rows: [{ total_spent: 0 }] }))
      );
    }
    
    const results = await Promise.all(fetchPromises);
    
    const [
      { rows: clubs },
      { rows: members },
      { rows: officers },
      { rows: documents },
      { rows: stats }
    ] = results.slice(0, 5);
    
    // Extract financial data for auditors
    let financialTransactions = [];
    let pendingExpenses = [];
    let budget = null;
    let totalBudget = 0;
    let totalSpent = 0;
    let budgetUtilization = 0;
    let financialReports = [];
    let complianceIssues = [];
    let auditLogs = [];
    
    if (isAuditor) {
      pendingExpenses = results[5]?.rows || [];
      financialTransactions = results[6]?.rows || [];
      budget = results[7]?.rows[0] || null;
      financialReports = results[8]?.rows || [];
      complianceIssues = results[9]?.rows || [];
      auditLogs = results[10]?.rows || [];
      totalBudget = budget ? Number(budget.total_budget) || 0 : 0;
      totalSpent = Number(results[11]?.rows[0]?.total_spent || 0);
      budgetUtilization = totalBudget > 0 ? Math.round((totalSpent / totalBudget) * 100) : 0;
    }
    
    // Calculate statistics from stats query
    const totalMembers = Number(stats[0]?.total || 0);
    const activeMembers = Number(stats[0]?.active || 0);
    const pendingMembers = Number(stats[0]?.pending || 0);
    const alumniMembers = Number(stats[0]?.alumni || 0);
    const officerCount = officers.length;
    
    // Get recent changes (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const recentChanges = members.filter(m => {
      if (!m.created_at) return false;
      const createdDate = new Date(m.created_at);
      return createdDate >= thirtyDaysAgo;
    }).length;
    
    const documentCount = Number(documents[0]?.count || 0);
    
    // Format members data
    const formattedMembers = members.map(member => {
      const name = member.name || `${member.first_name || ''} ${member.last_name || ''}`.trim() || 'Unknown';
      const initials = (member.first_name?.[0] || '') + (member.last_name?.[0] || '') || 'UC';
      const roles = member.officer_role ? [member.officer_role] : ['Member'];
      const status = member.status || 'Pending';
      
      // Calculate last activity (simplified - using created_at for now)
      const lastActivity = member.created_at ? new Date(member.created_at).toLocaleDateString() : '—';
      
      return {
        id: member.id,
        student_id: member.student_id,
        name,
        email: member.email || 'No email',
        status: status.charAt(0).toUpperCase() + status.slice(1).toLowerCase(),
        roles,
        last_activity: lastActivity,
        activity_detail: `Joined ${lastActivity}`,
        initials,
        studentid: member.studentid,
        department: member.department,
        program: member.program,
        year_level: member.year_level,
        profile_picture: member.profile_picture,
        officer_id: member.officer_id
      };
    });
    
    // Calculate financial statistics for auditors
    // Note: accessiblePages is already declared above at line 1451
    let pendingReviews = 0;
    let reportsDue = 0;
    let complianceFlags = 0;
    
    if (isAuditor) {
      pendingReviews = pendingExpenses.length;
      const currentDate = new Date();
      reportsDue = financialReports.filter(r => {
        if (!r.due_date) return false;
        const dueDate = new Date(r.due_date);
        const currentMonth = currentDate.getMonth();
        const currentYear = currentDate.getFullYear();
        return dueDate.getMonth() === currentMonth && 
               dueDate.getFullYear() === currentYear && 
               r.status === 'pending';
      }).length;
      complianceFlags = complianceIssues.filter(c => c.status === 'open' || c.status === 'in_review').length;
    }
    
    res.render("officer/records", {
      title: "Club Records | UniClub",
      officer,
      club: clubs[0] || null,
      members: formattedMembers,
      accessiblePages,
      totalMembers,
      activeMembers,
      pendingMembers,
      alumniMembers,
      officerCount,
      recentChanges,
      documentCount,
      currentStatus: statusFilter,
      currentSearch: searchQuery,
      currentRoleFilter: roleFilter,
      isAuditor,
      isTreasurer,
      isSecretary,
      csrfToken: req.csrfToken ? req.csrfToken() : res.locals.csrfToken || '',
      // Financial data for auditors
      financialTransactions: isAuditor ? financialTransactions : [],
      pendingExpenses: isAuditor ? pendingExpenses : [],
      budget: isAuditor ? budget : null,
      totalBudget: isAuditor ? totalBudget : 0,
      totalSpent: isAuditor ? totalSpent : 0,
      budgetUtilization: isAuditor ? budgetUtilization : 0,
      financialReports: isAuditor ? financialReports : [],
      complianceIssues: isAuditor ? complianceIssues : [],
      auditLogs: isAuditor ? auditLogs : [],
      pendingReviews: isAuditor ? pendingReviews : 0,
      reportsDue: isAuditor ? reportsDue : 0,
      complianceFlags: isAuditor ? complianceFlags : 0,
    });
  } catch (err) {
    console.error("Officer records error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

async function renderOfficerRolesPage(req, res) {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;

    // Ensure profile_picture column exists before querying
    try {
      const colCheck = await pool.query(
        `SELECT DATA_TYPE 
           FROM information_schema.COLUMNS 
          WHERE TABLE_SCHEMA = DATABASE() 
            AND TABLE_NAME = 'officers' 
            AND COLUMN_NAME = 'profile_picture'`
      );
      if (!colCheck.rows.length) {
        await pool.query(`ALTER TABLE officers ADD COLUMN profile_picture MEDIUMTEXT`);
      }
    } catch (err) {
      console.error('Column check failed for profile_picture:', err.message);
    }

    const [{ rows: clubs }, { rows: officersRaw }] = await Promise.all([
      pool.query(
        `SELECT id, name, description, adviser, category, department, program, status
           FROM clubs WHERE id = ?`,
        [clubId]
      ).catch(() => ({ rows: [] })),
      pool.query(
        `SELECT id, first_name, last_name, CONCAT(first_name, ' ', last_name) AS name, studentid, role, department, program, username, permissions, profile_picture
           FROM officers
          WHERE club_id = ?
          ORDER BY role IS NULL, role ASC, last_name ASC, first_name ASC`,
        [clubId]
      ).catch(() => ({ rows: [] }))
    ]);

    const officers = officersRaw.map((o) => {
      let permissions = {};
      if (o.permissions) {
        try {
          permissions =
            typeof o.permissions === "string" ? JSON.parse(o.permissions) : o.permissions;
        } catch (err) {
          permissions = {};
        }
      }
      return { ...o, permissions };
    });

    const roleStats = officers.reduce((acc, current) => {
      const key = current.role || "Unassigned";
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {});

    const departmentStats = officers.reduce((acc, current) => {
      const key = current.department || "Undeclared";
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {});

    const lastUpdated = officers.reduce((latest, current) => {
      // Use created_at as fallback since updated_at column doesn't exist
      const currentDate = current.created_at || null;
      if (!currentDate) return latest;
      return !latest || currentDate > latest ? currentDate : latest;
    }, null);

    res.render("officer/recordsRoles", {
      title: "Officer Roles | UniClub",
      officer,
      club: clubs[0] || null,
      officers,
      roleStats,
      departmentStats,
      totalOfficers: officers.length,
      lastUpdated
    });
  } catch (err) {
    console.error("Officer roles error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
}

router.get("/records/roles", requireOfficer, requirePageAccess('members'), renderOfficerRolesPage);
router.get("/records-roles", requireOfficer, requirePageAccess('members'), renderOfficerRolesPage);

async function renderRecordsRequirementsPage(req, res) {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;

    const [{ rows: clubs }, { rows: requirementsRows }, { rows: activitiesRows }] =
      await Promise.all([
        pool
          .query(
            `SELECT id, name, description, adviser, category, department, program, status
               FROM clubs WHERE id = ?`,
            [clubId]
          )
          .catch(() => ({ rows: [] })),
        pool
          .query(
            `SELECT id, requirement, status, due_date, created_at, club_id
               FROM requirements
              WHERE club_id = ? OR club_id IS NULL
              ORDER BY COALESCE(due_date, created_at) ASC`,
            [clubId]
          )
          .catch(() => ({ rows: [] })),
        pool
          .query(
            `SELECT id, activity, club, date, location, status, created_at
               FROM activities
              WHERE club IS NULL OR club = (SELECT name FROM clubs WHERE id = ?)
              ORDER BY date IS NULL, date DESC, created_at DESC
              LIMIT 30`,
            [clubId]
          )
          .catch(() => ({ rows: [] })),
      ]);

    const requirements = requirementsRows.map((row) => {
      const rawStatus = row.status || row.priority || "Pending";
      return {
        id: row.id,
        title: row.requirement || row.title || "Submission",
        description: "", // description column doesn't exist in requirements table
        priority: row.priority || null,
        status: rawStatus,
        statusKey: rawStatus ? rawStatus.toLowerCase() : "pending",
        dueDate: row.due_date,
        createdAt: row.created_at,
        updatedAt: row.created_at || null, // Use created_at as fallback since updated_at doesn't exist
        clubId: row.club_id,
      };
    });

    const today = new Date();
    const isDone = (statusKey) =>
      ["complete", "completed", "done", "submitted"].includes(
        (statusKey || "").toLowerCase()
      );

    const totalRequirements = requirements.length;
    const completedRequirements = requirements.filter((req) => isDone(req.statusKey)).length;
    const overdueRequirements = requirements.filter((req) => {
      if (!req.dueDate) return false;
      if (isDone(req.statusKey)) return false;
      return new Date(req.dueDate) < today;
    }).length;

    const progress = totalRequirements
      ? Math.round((completedRequirements / totalRequirements) * 100)
      : 0;

    const activities = activitiesRows.map((row) => ({
      id: row.id,
      title: row.activity,
      club: row.club,
      date: row.date,
      location: row.location,
      status: row.status,
      createdAt: row.created_at,
    }));

    res.render("officer/recordsRequirements", {
      title: "Requirements & Activities | UniClub",
      officer,
      club: clubs[0] || null,
      requirements,
      activities,
      stats: {
        totalRequirements,
        completedRequirements,
        overdueRequirements,
        progress,
      },
      todayISO: today.toISOString(),
    });
  } catch (err) {
    console.error("Officer requirements error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
}

router.get("/records/requirements", requireOfficer, requirePageAccess('documents'), renderRecordsRequirementsPage);
router.get("/records-requirements", requireOfficer, requirePageAccess('documents'), renderRecordsRequirementsPage);

// Finance Management Page (for Auditors and Treasurers)
router.get("/finance", requireOfficer, requirePageAccess('finance'), async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;
    const officerId = officer.id;
    
    // Check if officer is auditor or treasurer
    const role = (officer.role || '').toLowerCase();
    const isAuditor = role.includes('auditor');
    const isTreasurer = role.includes('treasurer') || role.includes('finance');

    // Presidents (Tier 1) and any role mapped to "all" pages should also pass
    const accessiblePages = getDashboardPagesForRole(officer.role || '');
    const hasAllAccess = accessiblePages.includes('all') || role.includes('president');
    
    if (!isAuditor && !isTreasurer && !hasAllAccess) {
      return res.status(403).render("errors/403", {
        title: "Access Denied | UniClub",
        message: "You don't have permission to access the finance management page.",
        officer,
      });
    }
    
    const currentYear = new Date().getFullYear();
    const currentMonth = new Date().getMonth() + 1;
    const firstDayOfMonth = new Date(currentYear, currentMonth - 1, 1);
    const lastDayOfMonth = new Date(currentYear, currentMonth, 0);
    
    // Fetch all financial data
    const [
      { rows: clubs },
      pendingExpensesResult,
      allExpensesResult,
      budgetResult,
      reportsResult,
      complianceResult,
      transactionsResult,
      auditLogsResult,
      spentResult
    ] = await Promise.all([
      pool.query(
        `SELECT id, name, description, adviser, category, department, program, status
         FROM clubs WHERE id = ?`,
        [clubId]
      ).catch(() => ({ rows: [] })),
      // Pending expenses
      pool.query(
        `SELECT e.id, e.title, e.description, e.amount, e.category, e.status, e.receipt_url, e.created_at,
                e.submitted_by,
                (SELECT CONCAT(first_name, ' ', last_name) FROM officers WHERE id = e.submitted_by) as submitted_by_name
         FROM expenses e
         WHERE e.club_id = ? AND e.status = 'pending'
         ORDER BY e.created_at DESC`,
        [clubId]
      ).catch(() => ({ rows: [] })),
      // All expenses (for filtering)
      pool.query(
        `SELECT e.id, e.title, e.amount, e.category, e.status, e.created_at,
                (SELECT CONCAT(first_name, ' ', last_name) FROM officers WHERE id = e.submitted_by) as submitted_by_name
         FROM expenses e
         WHERE e.club_id = ?
         ORDER BY e.created_at DESC LIMIT 50`,
        [clubId]
      ).catch(() => ({ rows: [] })),
      // Budget
      pool.query(
        `SELECT id, total_budget, fiscal_year, notes
         FROM budget
         WHERE club_id = ? AND fiscal_year = ?
         ORDER BY fiscal_year DESC LIMIT 1`,
        [clubId, currentYear]
      ).catch(() => ({ rows: [] })),
      // Financial reports
      pool.query(
        `SELECT id, report_type, period_start, period_end, due_date, status, title, file_url, notes
         FROM financial_reports
         WHERE club_id = ?
         ORDER BY due_date ASC LIMIT 20`,
        [clubId]
      ).catch(() => ({ rows: [] })),
      // Compliance issues
      pool.query(
        `SELECT id, issue_type, severity, title, description, status, flagged_at,
                (SELECT CONCAT(first_name, ' ', last_name) FROM officers WHERE id = flagged_by) as flagged_by_name
         FROM compliance_issues
         WHERE club_id = ?
         ORDER BY 
           CASE severity
             WHEN 'critical' THEN 1
             WHEN 'high' THEN 2
             WHEN 'medium' THEN 3
             WHEN 'low' THEN 4
           END,
           flagged_at DESC`,
        [clubId]
      ).catch(() => ({ rows: [] })),
      // Recent transactions
      pool.query(
        `SELECT id, title, amount, category, status, created_at,
                (SELECT CONCAT(first_name, ' ', last_name) FROM officers WHERE id = submitted_by) as submitted_by_name
         FROM expenses
         WHERE club_id = ? AND status = 'approved'
         ORDER BY created_at DESC LIMIT 20`,
        [clubId]
      ).catch(() => ({ rows: [] })),
      // Audit logs (for auditors)
      isAuditor ? pool.query(
        `SELECT id, action_type, entity_type, description, created_at,
                (SELECT CONCAT(first_name, ' ', last_name) FROM officers WHERE id = performed_by) as performed_by_name
         FROM audit_logs
         WHERE club_id = ?
         ORDER BY created_at DESC LIMIT 50`,
        [clubId]
      ).catch(() => ({ rows: [] })) : Promise.resolve({ rows: [] }),
      // Calculate total spent
      pool.query(
        `SELECT COALESCE(SUM(amount), 0) as total_spent
         FROM expenses
         WHERE club_id = ? AND status IN ('approved', 'pending')
         AND YEAR(created_at) = ?`,
        [clubId, currentYear]
      ).catch(() => ({ rows: [{ total_spent: 0 }] }))
    ]);
    
    const budget = budgetResult.rows[0] || null;
    const totalBudget = budget ? Number(budget.total_budget) || 0 : 0;
    const totalSpent = Number(spentResult.rows[0]?.total_spent || 0);
    const budgetUtilization = totalBudget > 0 ? Math.round((totalSpent / totalBudget) * 100) : 0;
    
    res.render("officer/finance", {
      title: "Finance Management | UniClub",
      officer,
      club: clubs[0] || null,
      accessiblePages,
      csrfToken: req.csrfToken ? req.csrfToken() : res.locals.csrfToken || '',
      // Financial data
      pendingExpenses: pendingExpensesResult.rows || [],
      allExpenses: allExpensesResult.rows || [],
      budget,
      totalBudget,
      totalSpent,
      budgetUtilization,
      reports: reportsResult.rows || [],
      complianceIssues: complianceResult.rows || [],
      transactions: transactionsResult.rows || [],
      auditLogs: auditLogsResult.rows || [],
      isAuditor,
      isTreasurer,
    });
  } catch (err) {
    console.error("Finance management error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

// Approve/Reject Expense
router.post("/finance/expense/:id/approve", requireOfficer, requirePageAccess('finance'), requirePermission('approve_expenses'), writeLimiter, async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const expenseId = parseInt(req.params.id);
    const clubId = officer.club_id;
    
    if (!expenseId || isNaN(expenseId)) {
      return res.status(400).json({ error: "Invalid expense ID" });
    }
    
    // Double-check permission (redundant but secure)
    const role = (officer.role || '').toLowerCase();
    if (!hasPermission(role, 'approve_expenses')) {
      return res.status(403).json({ error: "You don't have permission to approve expenses" });
    }
    
    // Verify expense exists and belongs to club
    const expenseCheck = await pool.query(
      `SELECT id, title, amount FROM expenses WHERE id = ? AND club_id = ? AND status = 'pending'`,
      [expenseId, clubId]
    ).catch(() => ({ rows: [] }));
    
    if (expenseCheck.rows.length === 0) {
      return res.status(404).json({ error: "Expense not found or already processed" });
    }
    
    // Update expense status
    await pool.query(
      `UPDATE expenses 
       SET status = 'approved', 
           reviewed_by = ?, 
           reviewed_at = NOW()
       WHERE id = ? AND club_id = ? AND status = 'pending'`,
      [officer.id, expenseId, clubId]
    );
    
    // Log audit action
    await pool.query(
      `INSERT INTO audit_logs (club_id, action_type, entity_type, entity_id, performed_by, description)
       VALUES (?, 'expense_approved', 'expense', ?, ?, ?)`,
      [clubId, expenseId, officer.id, `Approved expense: ${expenseCheck.rows[0].title || '#' + expenseId} (₱${Number(expenseCheck.rows[0].amount || 0).toLocaleString()})`]
    ).catch(() => {}); // Ignore if table doesn't exist
    
    res.json({ success: true, message: "Expense approved successfully" });
  } catch (err) {
    console.error("Approve expense error:", err);
    res.status(500).json({ error: "Failed to approve expense: " + err.message });
  }
});

// Calendar Page (for all officers with events access)
router.get("/calendar", requireOfficer, requirePageAccess('events'), async (req, res) => {
  // Auto-update event statuses before loading calendar
  await updateEventStatuses();
  
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;
    const role = (officer.role || '').toLowerCase();
    
    // Get permissions for this role
    const canCreateEvents = hasPermission(role, 'create_events');
    const canEditEvents = hasPermission(role, 'edit_events');
    const canCancelEvents = hasPermission(role, 'cancel_events');
    const canDeleteEvents = hasPermission(role, 'delete_events');
    
    // Get current month/year or from query params
    const year = parseInt(req.query.year) || new Date().getFullYear();
    const month = parseInt(req.query.month) || new Date().getMonth() + 1;
    
    // Fetch events for the selected month
    const startDate = new Date(year, month - 1, 1);
    startDate.setHours(0, 0, 0, 0);
    const endDate = new Date(year, month, 0);
    endDate.setHours(23, 59, 59, 999);
    
    // Format dates for MySQL
    const startDateStr = startDate.toISOString().split('T')[0];
    const endDateStr = endDate.toISOString().split('T')[0];
    
    // Ensure events table has required columns before querying
    // MySQL doesn't support IF NOT EXISTS in ALTER TABLE, so we'll try to add columns and ignore errors if they exist
    const columnsToAdd = [
      { name: 'status', def: "VARCHAR(50) DEFAULT 'pending_approval'" },
      { name: 'admin_requirements', def: 'TEXT' },
      { name: 'approved_by', def: 'INT' },
      { name: 'approved_at', def: 'TIMESTAMP NULL' },
      { name: 'posted_to_students', def: 'TINYINT(1) DEFAULT 0' },
      { name: 'activity_proposal', def: 'VARCHAR(500)' },
      { name: 'letter_of_intent', def: 'VARCHAR(500)' },
      { name: 'budgetary_requirement', def: 'VARCHAR(500)' }
    ];
    
    for (const col of columnsToAdd) {
      try {
        await pool.query(`ALTER TABLE events ADD COLUMN ${col.name} ${col.def}`);
      } catch (err) {
        // Silently ignore duplicate column errors (MySQL error code 1060)
        const isDuplicateColumn = 
          err.code === 'ER_DUP_FIELDNAME' || 
          err.errno === 1060 || 
          err.message?.includes('Duplicate column name') || 
          err.sqlMessage?.includes('Duplicate column name');
        
        if (!isDuplicateColumn) {
          // Only log unexpected errors
          console.warn(`Warning: Could not add column ${col.name}:`, err.message);
        }
      }
    }
    
    const [{ rows: clubs }, eventsResult] = await Promise.all([
      pool.query(
        `SELECT id, name, description, adviser, category, department, program, status
         FROM clubs WHERE id = ?`,
        [clubId]
      ).catch(() => ({ rows: [] })),
      (async () => {
        try {
          return await pool.query(
            `SELECT id, name, date, COALESCE(end_date, date) as end_date, location, description, club_id, created_at, 
                    COALESCE(status, 'pending_approval') as status, 
                    admin_requirements, approved_by, approved_at, posted_to_students,
                    activity_proposal, letter_of_intent, budgetary_requirement
             FROM events
             WHERE club_id = ? 
               AND COALESCE(status, 'pending_approval') != 'pending_approval'
               AND COALESCE(status, 'pending_approval') != 'rejected'
               AND COALESCE(status, '') NOT IN ('Completed', 'completed', 'Cancelled', 'cancelled')
               -- Exclude events that have ended (show only upcoming and ongoing events)
               AND (
                 -- Event is upcoming (date in future)
                 DATE(date) > CURDATE()
                 OR
                 -- Event is ongoing (date is today or past, but end_date is today or future)
                 (DATE(date) <= CURDATE() AND (end_date IS NULL OR DATE(end_date) >= CURDATE()))
                 OR
                 -- Event with no date (scheduled but date TBA)
                 date IS NULL
               )
               AND (
                 (DATE(date) <= ? AND COALESCE(DATE(end_date), DATE(date)) >= ?)
                 OR (DATE(date) >= ? AND DATE(date) <= ?)
               )
             ORDER BY date ASC, name ASC`,
            [clubId, endDateStr, startDateStr, startDateStr, endDateStr]
          );
        } catch (err) {
          // Fallback for schemas missing columns (shouldn't happen after ALTER TABLE above, but just in case)
          if (err && err.code === 'ER_BAD_FIELD_ERROR') {
            const fallback = await pool.query(
              `SELECT id, name, date, location, description, club_id, created_at,
                      admin_requirements, approved_by, approved_at, posted_to_students
               FROM events
               WHERE club_id = ? 
                 AND (COALESCE(status, 'pending_approval') != 'pending_approval' AND COALESCE(status, 'pending_approval') != 'rejected')
                 AND COALESCE(status, '') NOT IN ('Completed', 'completed', 'Cancelled', 'cancelled')
                 -- Exclude events that have ended (show only upcoming and ongoing events)
                 AND (
                   -- Event is upcoming (date in future)
                   DATE(date) > CURDATE()
                   OR
                   -- Event is ongoing (date is today or past, but end_date is today or future)
                   (DATE(date) <= CURDATE() AND (end_date IS NULL OR DATE(end_date) >= CURDATE()))
                   OR
                   -- Event with no date (scheduled but date TBA)
                   date IS NULL
                 )
                 AND DATE(date) >= ? AND DATE(date) <= ?
               ORDER BY date ASC, name ASC`,
              [clubId, startDateStr, endDateStr]
            ).catch(() => ({ rows: [] }));
            // Inject default values so UI doesn't break
            fallback.rows = (fallback.rows || []).map(ev => ({
              ...ev,
              end_date: ev.date, // Default end_date to start date
              status: 'pending_approval',
              activity_proposal: null,
              letter_of_intent: null,
              budgetary_requirement: null
            }));
            return fallback;
          }
          throw err;
        }
      })()
    ]);
    
    // Get accessible pages for sidebar
    const accessiblePages = getDashboardPagesForRole(role);
    
    res.render("officer/calendar", {
      title: "Calendar | UniClub",
      officer,
      club: clubs[0] || null,
      accessiblePages,
      csrfToken: req.csrfToken ? req.csrfToken() : res.locals.csrfToken || '',
      events: eventsResult?.rows || [],
      currentYear: year,
      currentMonth: month,
      canCreateEvents,
      canEditEvents,
      canCancelEvents,
      canDeleteEvents,
    });
  } catch (err) {
    console.error("Calendar error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

// Create Event
router.post("/calendar/event/create", requireOfficer, requirePageAccess('events'), requirePermission('create_events'), writeLimiter, (req, res, next) => {
  uploadEventDocuments(req, res, async (err) => {
    if (err) {
      return res.status(400).json({ error: err.message || "File upload error" });
    }
    
    try {
      // Ensure req.body exists (multer should populate it, but initialize if missing)
      if (!req.body) {
        req.body = {};
      }
      
      // Debug: Log what we received
      console.log('Create event - req.body:', req.body);
      console.log('Create event - req.files:', req.files);
      
      // Validate CSRF token after multer processes the form
      const csrfToken = req.body._csrf;
      if (!csrfToken) {
        // Clean up uploaded files if CSRF token is missing
        if (req.files) {
          Object.values(req.files).flat().forEach(file => {
            const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
            fs.unlink(filePath, () => {});
          });
        }
        return res.status(403).json({ error: "Invalid security token. Please refresh the page and try again." });
      }
      
      const officer = { ...req.session.officer };
      const clubId = officer.club_id;
      const role = (officer.role || '').toLowerCase();
      
      // Check permissions
      if (!hasPermission(role, 'create_events')) {
        // Clean up uploaded files if permission denied
        if (req.files) {
          Object.values(req.files).flat().forEach(file => {
            const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
            fs.unlink(filePath, () => {});
          });
        }
        return res.status(403).json({ error: "You don't have permission to create events" });
      }
      
      // Safely extract form fields - multer should populate req.body with text fields
      const name = (req.body && req.body.name) ? String(req.body.name).trim() : '';
      const date = (req.body && req.body.date) ? String(req.body.date).trim() : '';
      const endDate = (req.body && req.body.end_date) ? String(req.body.end_date).trim() : date; // Default to start date if not provided
      const location = (req.body && req.body.location) ? String(req.body.location).trim() : '';
      const description = (req.body && req.body.description) ? String(req.body.description).trim() : '';
      
      // Validation
      if (!name) {
        // Clean up uploaded files
        if (req.files) {
          Object.values(req.files).flat().forEach(file => {
            const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
            fs.unlink(filePath, () => {});
          });
        }
        return res.status(400).json({ error: "Event name is required" });
      }
      
      if (!date) {
        // Clean up uploaded files
        if (req.files) {
          Object.values(req.files).flat().forEach(file => {
            const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
            fs.unlink(filePath, () => {});
          });
        }
        return res.status(400).json({ error: "Event date is required" });
      }
      
      // Validate end date is not before start date
      if (endDate && endDate < date) {
        // Clean up uploaded files
        if (req.files) {
          Object.values(req.files).flat().forEach(file => {
            const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
            fs.unlink(filePath, () => {});
          });
        }
        return res.status(400).json({ error: "End date must be on or after start date" });
      }
      
      // Validate file uploads
      const files = req.files || {};
      if (!files.activity_proposal || files.activity_proposal.length === 0) {
        // Clean up uploaded files
        if (req.files) {
          Object.values(req.files).flat().forEach(file => {
            const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
            fs.unlink(filePath, () => {});
          });
        }
        return res.status(400).json({ error: "Activity proposal file is required" });
      }
      if (!files.letter_of_intent || files.letter_of_intent.length === 0) {
        // Clean up uploaded files
        if (req.files) {
          Object.values(req.files).flat().forEach(file => {
            const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
            fs.unlink(filePath, () => {});
          });
        }
        return res.status(400).json({ error: "Letter of intent file is required" });
      }
      if (!files.budgetary_requirement || files.budgetary_requirement.length === 0) {
        // Clean up uploaded files
        if (req.files) {
          Object.values(req.files).flat().forEach(file => {
            const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
            fs.unlink(filePath, () => {});
          });
        }
        return res.status(400).json({ error: "Budgetary requirement file is required" });
      }
      
      // Get file paths
      const activityProposalPath = `/uploads/events/${files.activity_proposal[0].filename}`;
      const letterOfIntentPath = `/uploads/events/${files.letter_of_intent[0].filename}`;
      const budgetaryRequirementPath = `/uploads/events/${files.budgetary_requirement[0].filename}`;
      
      // Ensure events table has status and approval columns
      // MySQL doesn't support IF NOT EXISTS in ALTER TABLE, so we'll try to add columns and ignore errors if they exist
      const columnsToAdd = [
        { name: 'status', def: "VARCHAR(50) DEFAULT 'pending_approval'" },
        { name: 'admin_requirements', def: 'TEXT' },
        { name: 'approved_by', def: 'INT' },
        { name: 'approved_at', def: 'TIMESTAMP NULL' },
        { name: 'posted_to_students', def: 'TINYINT(1) DEFAULT 0' },
        { name: 'created_by', def: 'INT' },
        { name: 'end_date', def: 'DATE' },
        { name: 'activity_proposal', def: 'VARCHAR(500)' },
        { name: 'letter_of_intent', def: 'VARCHAR(500)' },
        { name: 'budgetary_requirement', def: 'VARCHAR(500)' }
      ];
      
      for (const col of columnsToAdd) {
        try {
          await pool.query(`ALTER TABLE events ADD COLUMN ${col.name} ${col.def}`);
        } catch (err) {
          // Silently ignore duplicate column errors (MySQL error code 1060)
          const isDuplicateColumn = 
            err.code === 'ER_DUP_FIELDNAME' || 
            err.errno === 1060 || 
            err.message?.includes('Duplicate column name') || 
            err.sqlMessage?.includes('Duplicate column name');
          
          if (!isDuplicateColumn) {
            // Only log unexpected errors
            console.warn(`Warning: Could not add column ${col.name}:`, err.message);
          }
        }
      }
      
      // Insert event with pending_approval status
      const result = await pool.query(
        `INSERT INTO events (club_id, name, date, end_date, location, description, status, created_by, activity_proposal, letter_of_intent, budgetary_requirement)
         VALUES (?, ?, ?, ?, ?, ?, 'pending_approval', ?, ?, ?, ?)`,
        [clubId, name.trim(), date, endDate || date, location?.trim() || null, description?.trim() || null, officer.id, activityProposalPath, letterOfIntentPath, budgetaryRequirementPath]
      );
      
      const eventId = result.insertId || result.rows[0]?.id;
      
      res.json({ 
        success: true, 
        message: "Event submitted successfully! It is now pending admin approval. You will be notified once it's approved.", 
        eventId,
        status: 'pending_approval'
      });
    } catch (err) {
      // Clean up uploaded files on error
      if (req.files) {
        Object.values(req.files).flat().forEach(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          fs.unlink(filePath, () => {});
        });
      }
      console.error("Create event error:", err);
      res.status(500).json({ error: "Failed to create event: " + err.message });
    }
  });
});

// Update Event
router.post("/calendar/event/:id/update", requireOfficer, requirePageAccess('events'), requirePermission('edit_events'), writeLimiter, (req, res, next) => {
  uploadEventDocuments(req, res, async (err) => {
    if (err) {
      return res.status(400).json({ error: err.message || "File upload error" });
    }
    
    try {
      // Ensure req.body exists (multer should populate it, but initialize if missing)
      if (!req.body) {
        req.body = {};
      }
      
      // Validate CSRF token after multer processes the form
      const csrfToken = req.body._csrf;
      if (!csrfToken) {
        // Clean up uploaded files if CSRF token is missing
        if (req.files) {
          Object.values(req.files).flat().forEach(file => {
            const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
            fs.unlink(filePath, () => {});
          });
        }
        return res.status(403).json({ error: "Invalid security token. Please refresh the page and try again." });
      }
      
      const officer = { ...req.session.officer };
      const clubId = officer.club_id;
      const eventId = parseInt(req.params.id);
      const role = (officer.role || '').toLowerCase();
      
      if (!eventId || isNaN(eventId)) {
        // Clean up uploaded files
        if (req.files) {
          Object.values(req.files).flat().forEach(file => {
            const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
            fs.unlink(filePath, () => {});
          });
        }
        return res.status(400).json({ error: "Invalid event ID" });
      }
      
      // Check permissions
      if (!hasPermission(role, 'edit_events')) {
        // Clean up uploaded files
        if (req.files) {
          Object.values(req.files).flat().forEach(file => {
            const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
            fs.unlink(filePath, () => {});
          });
        }
        return res.status(403).json({ error: "You don't have permission to edit events" });
      }
      
      // Verify event exists and belongs to club
      const eventCheck = await pool.query(
        `SELECT id, activity_proposal, letter_of_intent, budgetary_requirement FROM events WHERE id = ? AND club_id = ?`,
        [eventId, clubId]
      ).catch(() => ({ rows: [] }));
      
      if (eventCheck.rows.length === 0) {
        // Clean up uploaded files
        if (req.files) {
          Object.values(req.files).flat().forEach(file => {
            const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
            fs.unlink(filePath, () => {});
          });
        }
        return res.status(404).json({ error: "Event not found" });
      }
      
      const existingEvent = eventCheck.rows[0];
      
      // Safely extract form fields - multer should populate req.body with text fields
      const name = (req.body && req.body.name) ? String(req.body.name).trim() : '';
      const date = (req.body && req.body.date) ? String(req.body.date).trim() : '';
      const endDate = (req.body && req.body.end_date) ? String(req.body.end_date).trim() : date; // Default to start date if not provided
      const location = (req.body && req.body.location) ? String(req.body.location).trim() : '';
      const description = (req.body && req.body.description) ? String(req.body.description).trim() : '';
      const files = req.files || {};
      
      // Validate name is provided
      if (!name || name.length === 0) {
        // Clean up uploaded files
        if (req.files) {
          Object.values(req.files).flat().forEach(file => {
            const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
            fs.unlink(filePath, () => {});
          });
        }
        return res.status(400).json({ error: "Event name is required" });
      }
      
      // Validate end date is not before start date
      if (date && endDate && endDate < date) {
        // Clean up uploaded files
        if (req.files) {
          Object.values(req.files).flat().forEach(file => {
            const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
            fs.unlink(filePath, () => {});
          });
        }
        return res.status(400).json({ error: "End date must be on or after start date" });
      }
      
      // Prepare update values - keep existing files if new ones aren't uploaded
      let activityProposalPath = existingEvent.activity_proposal;
      let letterOfIntentPath = existingEvent.letter_of_intent;
      let budgetaryRequirementPath = existingEvent.budgetary_requirement;
      
      // Delete old files if new ones are uploaded
      if (files.activity_proposal && files.activity_proposal.length > 0) {
        if (activityProposalPath) {
          const oldFilePath = path.join(__dirname, '../public', activityProposalPath);
          fs.unlink(oldFilePath, () => {});
        }
        activityProposalPath = `/uploads/events/${files.activity_proposal[0].filename}`;
      }
      
      if (files.letter_of_intent && files.letter_of_intent.length > 0) {
        if (letterOfIntentPath) {
          const oldFilePath = path.join(__dirname, '../public', letterOfIntentPath);
          fs.unlink(oldFilePath, () => {});
        }
        letterOfIntentPath = `/uploads/events/${files.letter_of_intent[0].filename}`;
      }
      
      if (files.budgetary_requirement && files.budgetary_requirement.length > 0) {
        if (budgetaryRequirementPath) {
          const oldFilePath = path.join(__dirname, '../public', budgetaryRequirementPath);
          fs.unlink(oldFilePath, () => {});
        }
        budgetaryRequirementPath = `/uploads/events/${files.budgetary_requirement[0].filename}`;
      }
      
      // Ensure columns exist before updating
      // MySQL doesn't support IF NOT EXISTS in ALTER TABLE, so we'll try to add columns and ignore errors if they exist
      const columnsToAdd = [
        { name: 'end_date', def: 'DATE' },
        { name: 'activity_proposal', def: 'VARCHAR(500)' },
        { name: 'letter_of_intent', def: 'VARCHAR(500)' },
        { name: 'budgetary_requirement', def: 'VARCHAR(500)' }
      ];
      
      for (const col of columnsToAdd) {
        try {
          await pool.query(`ALTER TABLE events ADD COLUMN ${col.name} ${col.def}`);
        } catch (err) {
          // Silently ignore duplicate column errors (MySQL error code 1060)
          const isDuplicateColumn = 
            err.code === 'ER_DUP_FIELDNAME' || 
            err.errno === 1060 || 
            err.message?.includes('Duplicate column name') || 
            err.sqlMessage?.includes('Duplicate column name');
          
          if (!isDuplicateColumn) {
            // Only log unexpected errors
            console.warn(`Warning: Could not add column ${col.name}:`, err.message);
          }
        }
      }
      
      // Update event
      await pool.query(
        `UPDATE events 
         SET name = ?, date = ?, end_date = ?, location = ?, description = ?, 
             activity_proposal = ?, letter_of_intent = ?, budgetary_requirement = ?
         WHERE id = ? AND club_id = ?`,
        [
          name?.trim() || null, 
          date || null,
          endDate || date || null,
          location?.trim() || null, 
          description?.trim() || null,
          activityProposalPath,
          letterOfIntentPath,
          budgetaryRequirementPath,
          eventId, 
          clubId
        ]
      );
      
      res.json({ success: true, message: "Event updated successfully" });
    } catch (err) {
      // Clean up uploaded files on error
      if (req.files) {
        Object.values(req.files).flat().forEach(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          fs.unlink(filePath, () => {});
        });
      }
      console.error("Update event error:", err);
      res.status(500).json({ error: "Failed to update event: " + err.message });
    }
  });
});

// Cancel Event
router.post("/calendar/event/:id/cancel", requireOfficer, requirePageAccess('events'), requirePermission('cancel_events'), writeLimiter, async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;
    const eventId = parseInt(req.params.id);
    const role = (officer.role || '').toLowerCase();
    const isPresident = role.includes('president');
    
    if (!eventId || isNaN(eventId)) {
      return res.status(400).json({ error: "Invalid event ID" });
    }
    
    // Check permissions - presidents can cancel any event, others need cancel_events permission
    if (!isPresident && !hasPermission(role, 'cancel_events')) {
      return res.status(403).json({ error: "You don't have permission to cancel events" });
    }
    
    // Verify event exists and belongs to club
    const eventCheck = await pool.query(
      `SELECT id, name, status, posted_to_students FROM events WHERE id = ? AND club_id = ?`,
      [eventId, clubId]
    ).catch(() => ({ rows: [] }));
    
    if (eventCheck.rows.length === 0) {
      return res.status(404).json({ error: "Event not found" });
    }
    
    const event = eventCheck.rows[0];
    
    // If event is posted, only presidents can cancel it
    if ((event.posted_to_students === 1 || event.status === 'posted') && !isPresident) {
      return res.status(403).json({ error: "Only the president can cancel posted events" });
    }
    
    // Update event status to cancelled
    await pool.query(
      `UPDATE events 
       SET status = 'cancelled',
           name = CASE 
             WHEN name NOT LIKE '%[CANCELLED]%' THEN CONCAT(name, ' [CANCELLED]')
             ELSE name
           END
       WHERE id = ? AND club_id = ?`,
      [eventId, clubId]
    );
    
    res.json({ success: true, message: "Event cancelled successfully" });
  } catch (err) {
    console.error("Cancel event error:", err);
    res.status(500).json({ error: "Failed to cancel event: " + err.message });
  }
});

// Get Event RSVP List
router.get("/calendar/event/:id/rsvps", requireOfficer, requirePageAccess('events'), async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;
    const eventId = parseInt(req.params.id);
    
    if (!eventId || isNaN(eventId)) {
      return res.status(400).json({ error: "Invalid event ID" });
    }
    
    // Verify event belongs to the officer's club and get event details
    const { rows: eventRows } = await pool.query(
      `SELECT id, name, date, COALESCE(end_date, date) as end_date, status 
       FROM events 
       WHERE id = ? AND club_id = ?`,
      [eventId, clubId]
    );
    
    if (eventRows.length === 0) {
      return res.status(404).json({ error: "Event not found" });
    }
    
    const event = eventRows[0];
    const eventEndDate = event.end_date ? new Date(event.end_date) : new Date(event.date);
    eventEndDate.setHours(23, 59, 59, 999); // End of day
    const isEventEnded = new Date() > eventEndDate;
    
    // Ensure attended column exists in event_attendance
    try {
      await pool.query(`ALTER TABLE event_attendance ADD COLUMN attended TINYINT(1) DEFAULT 0`);
    } catch (err) {
      if (err.code !== 'ER_DUP_FIELDNAME' && err.errno !== 1060) {
        console.error('Error adding attended column:', err);
      }
    }
    
    // Get RSVP list with student details and attendance status
    const { rows: rsvpRows } = await pool.query(
      `SELECT 
        ea.id,
        ea.status,
        ea.attended,
        ea.created_at as rsvp_date,
        s.id as student_id,
        s.first_name,
        s.last_name,
        s.studentid,
        s.email,
        s.program,
        s.year_level,
        s.profile_picture as photo
      FROM event_attendance ea
      INNER JOIN students s ON ea.student_id = s.id
      WHERE ea.event_id = ?
      ORDER BY 
        CASE ea.status
          WHEN 'going' THEN 1
          WHEN 'interested' THEN 2
          ELSE 3
        END,
        ea.attended DESC,
        ea.created_at DESC`,
      [eventId]
    ).catch(() => ({ rows: [] }));
    
    // Group by status
    const going = rsvpRows.filter(r => r.status === 'going' || r.status === null);
    const interested = rsvpRows.filter(r => r.status === 'interested');
    const attended = rsvpRows.filter(r => r.attended === 1 || r.attended === true);
    
    res.json({
      success: true,
      event: event,
      going: going,
      interested: interested,
      attended: attended,
      total: rsvpRows.length,
      goingCount: going.length,
      interestedCount: interested.length,
      attendedCount: attended.length,
      isEventEnded: isEventEnded
    });
  } catch (err) {
    console.error("Error fetching RSVP list:", err);
    res.status(500).json({ error: "Failed to fetch RSVP list: " + err.message });
  }
});

// Mark Student Attendance
router.post("/calendar/event/:id/attendance/:studentId", requireOfficer, requirePageAccess('events'), async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;
    const eventId = parseInt(req.params.id);
    const studentId = parseInt(req.params.studentId);
    const { attended } = req.body; // true/false
    
    if (!eventId || isNaN(eventId) || !studentId || isNaN(studentId)) {
      return res.status(400).json({ error: "Invalid event ID or student ID" });
    }
    
    // Verify event belongs to the officer's club
    const { rows: eventRows } = await pool.query(
      `SELECT id, name FROM events WHERE id = ? AND club_id = ?`,
      [eventId, clubId]
    );
    
    if (eventRows.length === 0) {
      return res.status(404).json({ error: "Event not found" });
    }
    
    // Verify student exists and has RSVP'd
    const { rows: rsvpRows } = await pool.query(
      `SELECT id FROM event_attendance WHERE event_id = ? AND student_id = ?`,
      [eventId, studentId]
    );
    
    if (rsvpRows.length === 0) {
      return res.status(404).json({ error: "Student has not RSVP'd to this event" });
    }
    
    // Ensure attended column exists
    try {
      await pool.query(`ALTER TABLE event_attendance ADD COLUMN attended TINYINT(1) DEFAULT 0`);
    } catch (err) {
      if (err.code !== 'ER_DUP_FIELDNAME' && err.errno !== 1060) {
        console.error('Error adding attended column:', err);
      }
    }
    
    // Get event name for points description
    const eventName = eventRows[0].name;
    
    // Check if points were already awarded for this event
    let pointsAlreadyAwarded = false;
    if (attended) {
      try {
        const existingPoints = await pool.query(
          `SELECT id FROM student_points 
           WHERE student_id = ? AND source = ? AND description LIKE ?`,
          [studentId, 'event_attendance', `%event_id:${eventId}%`]
        ).catch(() => ({ rows: [] }));
        pointsAlreadyAwarded = existingPoints.rows.length > 0;
      } catch (e) {
        console.error('[Points] Error checking existing points:', e.message);
      }
    }
    
    // Update attendance status
    await pool.query(
      `UPDATE event_attendance SET attended = ? WHERE event_id = ? AND student_id = ?`,
      [attended ? 1 : 0, eventId, studentId]
    );
    
    // Award points if marked as attended (and not already awarded for this event)
    if (attended && !pointsAlreadyAwarded) {
      try {
        // Ensure student_points table exists
        try {
          await pool.query(`
            CREATE TABLE IF NOT EXISTS student_points (
              id INT AUTO_INCREMENT PRIMARY KEY,
              student_id INT NOT NULL,
              points INT NOT NULL DEFAULT 0,
              source VARCHAR(100) NOT NULL,
              description TEXT,
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              INDEX idx_student_id (student_id),
              INDEX idx_created_at (created_at)
            )
          `);
        } catch (createError) {
          // Table might already exist, continue
          if (createError.code !== 'ER_TABLE_EXISTS_ERROR' && createError.errno !== 1050) {
            console.error('[Points] Error creating student_points table:', createError.message);
          }
        }
        
        // Award 5 points for attending an event
        const pointsAwarded = 5;
        await pool.query(
          `INSERT INTO student_points (student_id, points, source, description, created_at)
           VALUES (?, ?, 'event_attendance', ?, NOW())`,
          [studentId, pointsAwarded, `Attended event: ${eventName} (event_id:${eventId})`]
        );
        console.log(`[Points] Awarded ${pointsAwarded} points to student ${studentId} for attending event ${eventId} (${eventName})`);
      } catch (pointsError) {
        // Log error but don't fail the attendance update
        console.error('[Points] Error awarding points for attendance:', pointsError.message);
      }
    }
    
    res.json({
      success: true,
      message: attended ? "Student marked as attended" : "Student marked as not attended"
    });
  } catch (err) {
    console.error("Error updating attendance:", err);
    res.status(500).json({ error: "Failed to update attendance: " + err.message });
  }
});

// Archive Event Attendance (move to logs after event ends)
router.post("/calendar/event/:id/archive-attendance", requireOfficer, requirePageAccess('events'), async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;
    const eventId = parseInt(req.params.id);
    
    if (!eventId || isNaN(eventId)) {
      return res.status(400).json({ error: "Invalid event ID" });
    }
    
    // Verify event belongs to the officer's club
    const { rows: eventRows } = await pool.query(
      `SELECT id, name, date, COALESCE(end_date, date) as end_date FROM events WHERE id = ? AND club_id = ?`,
      [eventId, clubId]
    );
    
    if (eventRows.length === 0) {
      return res.status(404).json({ error: "Event not found" });
    }
    
    const event = eventRows[0];
    const eventEndDate = event.end_date ? new Date(event.end_date) : new Date(event.date);
    eventEndDate.setHours(23, 59, 59, 999);
    
    // Check if event has ended
    if (new Date() <= eventEndDate) {
      return res.status(400).json({ error: "Event has not ended yet. Cannot archive attendance." });
    }
    
    // Create event_attendance_logs table if it doesn't exist
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS event_attendance_logs (
          id INT AUTO_INCREMENT PRIMARY KEY,
          event_id INT NOT NULL,
          student_id INT NOT NULL,
          rsvp_status VARCHAR(50) DEFAULT 'going',
          attended TINYINT(1) DEFAULT 0,
          rsvp_date TIMESTAMP,
          archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          student_name VARCHAR(200),
          student_email VARCHAR(150),
          student_id_number VARCHAR(50),
          INDEX idx_event_id (event_id),
          INDEX idx_student_id (student_id),
          INDEX idx_archived_at (archived_at)
        )
      `);
    } catch (err) {
      console.error('Error creating logs table:', err);
    }
    
    // Get all attendance records for this event
    const { rows: attendanceRows } = await pool.query(
      `SELECT 
        ea.*,
        s.first_name,
        s.last_name,
        s.email,
        s.studentid
      FROM event_attendance ea
      INNER JOIN students s ON ea.student_id = s.id
      WHERE ea.event_id = ?`,
      [eventId]
    );
    
    // Insert into logs
    for (const record of attendanceRows) {
      await pool.query(
        `INSERT INTO event_attendance_logs 
         (event_id, student_id, rsvp_status, attended, rsvp_date, student_name, student_email, student_id_number)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          record.event_id,
          record.student_id,
          record.status || 'going',
          record.attended || 0,
          record.created_at,
          `${record.first_name} ${record.last_name}`,
          record.email,
          record.studentid
        ]
      );
    }
    
    // Delete from active attendance table
    await pool.query(
      `DELETE FROM event_attendance WHERE event_id = ?`,
      [eventId]
    );
    
    res.json({
      success: true,
      message: `Attendance archived successfully. ${attendanceRows.length} records moved to logs.`
    });
  } catch (err) {
    console.error("Error archiving attendance:", err);
    res.status(500).json({ error: "Failed to archive attendance: " + err.message });
  }
});

// Get Attendance Logs for an Event
router.get("/calendar/event/:id/attendance-logs", requireOfficer, requirePageAccess('events'), async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;
    const eventId = parseInt(req.params.id);
    
    if (!eventId || isNaN(eventId)) {
      return res.status(400).json({ error: "Invalid event ID" });
    }
    
    // Verify event belongs to the officer's club
    const { rows: eventRows } = await pool.query(
      `SELECT id, name FROM events WHERE id = ? AND club_id = ?`,
      [eventId, clubId]
    );
    
    if (eventRows.length === 0) {
      return res.status(404).json({ error: "Event not found" });
    }
    
    // Get archived attendance logs
    const { rows: logRows } = await pool.query(
      `SELECT 
        id,
        student_id,
        rsvp_status,
        attended,
        rsvp_date,
        archived_at,
        student_name,
        student_email,
        student_id_number
      FROM event_attendance_logs
      WHERE event_id = ?
      ORDER BY archived_at DESC, student_name ASC`,
      [eventId]
    ).catch(() => ({ rows: [] }));
    
    res.json({
      success: true,
      event: eventRows[0],
      logs: logRows,
      total: logRows.length,
      attendedCount: logRows.filter(l => l.attended === 1 || l.attended === true).length
    });
  } catch (err) {
    console.error("Error fetching attendance logs:", err);
    res.status(500).json({ error: "Failed to fetch attendance logs: " + err.message });
  }
});

// Get Event Details (for editing)
router.get("/calendar/event/:id", requireOfficer, requirePageAccess('events'), async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;
    const eventId = parseInt(req.params.id);
    
    if (!eventId || isNaN(eventId)) {
      return res.status(400).json({ error: "Invalid event ID" });
    }
    
    const { rows } = await pool.query(
      `SELECT id, name, date, COALESCE(end_date, date) as end_date, location, description, 
              COALESCE(activity_proposal, '') as activity_proposal,
              COALESCE(letter_of_intent, '') as letter_of_intent,
              COALESCE(budgetary_requirement, '') as budgetary_requirement
       FROM events
       WHERE id = ? AND club_id = ?`,
      [eventId, clubId]
    ).catch(() => ({ rows: [] }));
    
    if (rows.length === 0) {
      return res.status(404).json({ error: "Event not found" });
    }
    
    res.json({ success: true, event: rows[0] });
  } catch (err) {
    console.error("Get event error:", err);
    res.status(500).json({ error: "Failed to fetch event" });
  }
});

// Delete Event (Tier 1 only)
router.post("/calendar/event/:id/delete", requireOfficer, requirePageAccess('events'), requirePermission('delete_events'), writeLimiter, async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;
    const eventId = parseInt(req.params.id);
    const role = (officer.role || '').toLowerCase();
    
    if (!eventId || isNaN(eventId)) {
      return res.status(400).json({ error: "Invalid event ID" });
    }
    
    // Check permissions - only Tier 1 can delete
    if (!hasPermission(role, 'delete_events')) {
      return res.status(403).json({ error: "Only Presidents can delete events" });
    }
    
    // Verify event exists and belongs to club
    const eventCheck = await pool.query(
      `SELECT id FROM events WHERE id = ? AND club_id = ?`,
      [eventId, clubId]
    ).catch(() => ({ rows: [] }));
    
    if (eventCheck.rows.length === 0) {
      return res.status(404).json({ error: "Event not found" });
    }
    
    // Delete event
    await pool.query(
      `DELETE FROM events WHERE id = ? AND club_id = ?`,
      [eventId, clubId]
    );
    
    res.json({ success: true, message: "Event deleted successfully" });
  } catch (err) {
    console.error("Delete event error:", err);
    res.status(500).json({ error: "Failed to delete event: " + err.message });
  }
});

// Post Event to Students (president only, after admin approval)
router.post("/calendar/event/:id/post", requireOfficer, requirePageAccess('events'), requirePermission('create_events'), writeLimiter, async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;
    const eventId = parseInt(req.params.id);
    const role = (officer.role || '').toLowerCase();
    
    if (!eventId || isNaN(eventId)) {
      return res.status(400).json({ error: "Invalid event ID" });
    }
    
    // Only presidents can post events
    if (!role.includes('president')) {
      return res.status(403).json({ error: "Only the president can post events to students" });
    }
    
    // Check if event exists and is approved by admin
    const { rows } = await pool.query(
      `SELECT id, status, posted_to_students FROM events WHERE id = ? AND club_id = ?`,
      [eventId, clubId]
    ).catch(() => ({ rows: [] }));
    
    if (rows.length === 0) {
      return res.status(404).json({ error: "Event not found" });
    }
    
    const event = rows[0];
    
    if (event.status !== 'approved_by_admin') {
      return res.status(400).json({ error: "Event must be approved by admin before posting to students" });
    }
    
    if (event.posted_to_students === 1) {
      return res.status(400).json({ error: "Event is already posted to students" });
    }
    
    // Update event to posted status
    await pool.query(
      `UPDATE events SET posted_to_students = 1, status = 'posted' WHERE id = ? AND club_id = ?`,
      [eventId, clubId]
    );
    
    res.json({ success: true, message: "Event posted to students successfully" });
  } catch (err) {
    console.error("Post event error:", err);
    res.status(500).json({ error: "Failed to post event: " + err.message });
  }
});

// Move/Reschedule Event (president only)
router.post("/calendar/event/:id/move", requireOfficer, requirePageAccess('events'), requirePermission('edit_events'), writeLimiter, async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;
    const eventId = parseInt(req.params.id);
    const role = (officer.role || '').toLowerCase();
    const { date } = req.body;
    
    if (!eventId || isNaN(eventId)) {
      return res.status(400).json({ error: "Invalid event ID" });
    }
    
    if (!date) {
      return res.status(400).json({ error: "New date is required" });
    }
    
    // Only presidents can move/reschedule events
    if (!role.includes('president')) {
      return res.status(403).json({ error: "Only the president can reschedule events" });
    }
    
    // Verify event exists and belongs to club
    const eventCheck = await pool.query(
      `SELECT id, status FROM events WHERE id = ? AND club_id = ?`,
      [eventId, clubId]
    ).catch(() => ({ rows: [] }));
    
    if (eventCheck.rows.length === 0) {
      return res.status(404).json({ error: "Event not found" });
    }
    
    // Update event date
    await pool.query(
      `UPDATE events SET date = ? WHERE id = ? AND club_id = ?`,
      [date, eventId, clubId]
    );
    
    res.json({ success: true, message: "Event rescheduled successfully" });
  } catch (err) {
    console.error("Move event error:", err);
    res.status(500).json({ error: "Failed to reschedule event: " + err.message });
  }
});

router.post("/finance/expense/:id/reject", requireOfficer, requirePageAccess('finance'), requirePermission('approve_expenses'), writeLimiter, async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const expenseId = parseInt(req.params.id);
    const clubId = officer.club_id;
    const { notes } = req.body;
    
    if (!expenseId || isNaN(expenseId)) {
      return res.status(400).json({ error: "Invalid expense ID" });
    }
    
    // Double-check permission
    const role = (officer.role || '').toLowerCase();
    if (!hasPermission(role, 'approve_expenses')) {
      return res.status(403).json({ error: "You don't have permission to reject expenses" });
    }
    
    // Verify expense exists and belongs to club
    const expenseCheck = await pool.query(
      `SELECT id, title, amount FROM expenses WHERE id = ? AND club_id = ? AND status = 'pending'`,
      [expenseId, clubId]
    ).catch(() => ({ rows: [] }));
    
    if (expenseCheck.rows.length === 0) {
      return res.status(404).json({ error: "Expense not found or already processed" });
    }
    
    // Update expense status
    await pool.query(
      `UPDATE expenses 
       SET status = 'rejected', 
           reviewed_by = ?, 
           reviewed_at = NOW(),
           notes = ?
       WHERE id = ? AND club_id = ? AND status = 'pending'`,
      [officer.id, notes || null, expenseId, clubId]
    );
    
    // Log audit action
    await pool.query(
      `INSERT INTO audit_logs (club_id, action_type, entity_type, entity_id, performed_by, description)
       VALUES (?, 'expense_rejected', 'expense', ?, ?, ?)`,
      [clubId, expenseId, officer.id, `Rejected expense: ${expenseCheck.rows[0].title || '#' + expenseId}${notes ? ' - ' + notes : ''}`]
    ).catch(() => {}); // Ignore if table doesn't exist
    
    res.json({ success: true, message: "Expense rejected successfully" });
  } catch (err) {
    console.error("Reject expense error:", err);
    res.status(500).json({ error: "Failed to reject expense: " + err.message });
  }
});

// Create new expense (for treasurers)
router.post("/finance/expense/create", requireOfficer, requirePageAccess('finance'), requirePermission('record_transactions'), writeLimiter, async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;
    const { title, description, amount, category, receipt_url } = req.body;
    
    // Validation
    if (!title || !title.trim()) {
      return res.status(400).json({ error: "Title is required" });
    }
    
    if (!amount || isNaN(parseFloat(amount)) || parseFloat(amount) <= 0) {
      return res.status(400).json({ error: "Valid amount is required" });
    }
    
    // Insert expense
    const result = await pool.query(
      `INSERT INTO expenses (club_id, submitted_by, title, description, amount, category, receipt_url, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')`,
      [clubId, officer.id, title.trim(), description?.trim() || null, parseFloat(amount), category?.trim() || null, receipt_url?.trim() || null]
    );
    
    const expenseId = result.insertId || result.rows[0]?.id;
    
    // Log audit action
    await pool.query(
      `INSERT INTO audit_logs (club_id, action_type, entity_type, entity_id, performed_by, description)
       VALUES (?, 'expense_created', 'expense', ?, ?, ?)`,
      [clubId, expenseId, officer.id, `Created expense: ${title.trim()} (₱${parseFloat(amount).toLocaleString()})`]
    ).catch(() => {}); // Ignore if table doesn't exist
    
    res.json({ success: true, message: "Expense submitted successfully", expenseId });
  } catch (err) {
    console.error("Create expense error:", err);
    res.status(500).json({ error: "Failed to create expense: " + err.message });
  }
});

export default router;

