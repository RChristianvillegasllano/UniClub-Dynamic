import express from "express";
import { body, validationResult } from "express-validator";
import pool from "../config/db.js";
import { requireOfficer } from "./officerAuthRoutes.js";
import { writeLimiter, csrfProtection } from "../middleware/security.js";
import { canAccessPage, getDashboardPagesForRole, hasPermission } from "../config/tierPermissions.js";

const router = express.Router();

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
      const accessiblePages = getDashboardPagesForRole(role);
      
      // Tier 1 (President) has access to all pages
      if (accessiblePages.includes('all')) {
        return next();
      }

      // Check if the officer can access this specific page
      if (!canAccessPage(role, pageId)) {
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
    res.locals.accessiblePages = getAccessiblePagesForOfficer(officer);
    res.locals.officerRole = officer.role || '';
  } else {
    res.locals.accessiblePages = [];
    res.locals.officerRole = '';
  }
  next();
}

// Apply to all officer dashboard routes
router.use(addAccessiblePagesToLocals);

router.get("/", requireOfficer, async (req, res) => {
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
          WHERE club_id = ? AND (date >= CURRENT_DATE OR date IS NULL)
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
    });
  } catch (err) {
    console.error("Officer dashboard error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

// Settings page (GET)
router.get("/settings", requireOfficer, async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    res.render("officer/settings", {
      title: "Settings | UniClub",
      officer,
      submitted: false,
    });
  } catch (err) {
    console.error("Officer settings GET error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

// Settings submit (POST) - placeholder that acknowledges request
router.post("/settings", requireOfficer, writeLimiter, async (req, res) => {
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
router.get("/profile", requireOfficer, async (req, res) => {
  try {
    await ensureOfficerProfileColumns();
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
           photo_url
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
    });
  } catch (err) {
    console.error("Officer profile GET error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

router.post("/profile", 
  requireOfficer, 
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
          photo_url
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
    });
  } catch (err) {
    console.error("Officer member approvals error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

// Attendance page (GET)
router.get("/attendance", requireOfficer, requirePageAccess('attendance'), async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;

    // Get club info
    const { rows: clubs } = await pool.query(
      `SELECT id, name, description, adviser, category, department, program, status
         FROM clubs WHERE id = ?`,
      [clubId]
    ).catch(() => ({ rows: [] }));

    // Get all attendance records
    const attendanceResult = await pool.query(
      `SELECT id, member_name, status, created_at
         FROM attendance
        WHERE club_id = ?
        ORDER BY created_at DESC`,
      [clubId]
    ).catch(() => ({ rows: [] }));

    const attendance = attendanceResult.rows || [];

    // Get stats
    const statsResult = await pool.query(
      `SELECT 
         COUNT(DISTINCT CASE WHEN status = 'Present' THEN id END) as present_count,
         COUNT(DISTINCT CASE WHEN status = 'Absent' THEN id END) as absent_count,
         COUNT(DISTINCT CASE WHEN status = 'Not Marked' OR status IS NULL THEN id END) as not_marked_count,
         COUNT(DISTINCT id) as total_count
       FROM attendance
       WHERE club_id = ?`,
      [clubId]
    ).catch(() => ({ rows: [{ present_count: 0, absent_count: 0, not_marked_count: 0, total_count: 0 }] }));

    const stats = statsResult.rows[0] || { present_count: 0, absent_count: 0, not_marked_count: 0, total_count: 0 };

    const presentCount = Number(stats.present_count) || 0;
    const absentCount = Number(stats.absent_count) || 0;
    const notMarkedCount = Number(stats.not_marked_count) || 0;
    const totalCount = Number(stats.total_count) || 0;

    res.render("officer/attendance", {
      title: "Attendance | UniClub",
      officer,
      club: clubs[0] || null,
      attendance,
      presentCount,
      absentCount,
      notMarkedCount,
      totalCount,
      activePage: "attendance",
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
      
      // Attendance stats
      pool.query(
        `SELECT 
           COUNT(DISTINCT CASE WHEN status = 'Present' THEN id END) as present_count,
           COUNT(DISTINCT CASE WHEN status = 'Absent' THEN id END) as absent_count,
           COUNT(DISTINCT id) as total_attendance
         FROM attendance
         WHERE club_id = ?`,
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
      
      // Events stats
      pool.query(
        `SELECT 
           COUNT(*) as total_events,
           COUNT(CASE WHEN date >= CURRENT_DATE THEN 1 END) as upcoming_events
         FROM events
         WHERE club_id = ?`,
        [clubId]
      ).catch(() => ({ rows: [{ total_events: 0, upcoming_events: 0 }] })),
      
      // Monthly attendance (last 6 months)
      pool.query(
        `SELECT 
           TO_CHAR(created_at, 'YYYY-MM') as month,
           COUNT(CASE WHEN status = 'Present' THEN 1 END) as present,
           COUNT(CASE WHEN status = 'Absent' THEN 1 END) as absent,
           COUNT(*) as total
         FROM attendance
         WHERE club_id = ? 
           AND created_at >= NOW() - INTERVAL '6 months'
         GROUP BY TO_CHAR(created_at, 'YYYY-MM')
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
           TO_CHAR(date, 'YYYY-MM') as month,
           COUNT(*) as events_count
         FROM events
         WHERE club_id = ? 
           AND date >= NOW() - INTERVAL '6 months'
         GROUP BY TO_CHAR(date, 'YYYY-MM')
         ORDER BY month ASC`,
        [clubId]
      ).catch(() => ({ rows: [] }))
    ]);

    const totalMembers = Number(membersResult.rows[0]?.total_members || 0);
    const attendanceStats = attendanceStatsResult.rows[0] || { present_count: 0, absent_count: 0, total_attendance: 0 };
    const appStats = applicationsResult.rows[0] || { pending_count: 0, approved_count: 0, rejected_count: 0, total_applications: 0 };
    const eventStats = eventsResult.rows[0] || { total_events: 0, upcoming_events: 0 };
    
    const monthlyAttendance = monthlyAttendanceResult.rows || [];
    const monthlyMembers = monthlyMembersResult.rows || [];
    const monthlyEvents = monthlyEventsResult.rows || [];

    // Calculate attendance rate
    const totalAttendance = Number(attendanceStats.total_attendance) || 0;
    const presentCount = Number(attendanceStats.present_count) || 0;
    const attendanceRate = totalAttendance > 0 ? Math.round((presentCount / totalAttendance) * 100) : 0;

    // Calculate growth (comparing last month to previous month)
    const lastMonthMembers = monthlyMembers[monthlyMembers.length - 1]?.new_members || 0;
    const prevMonthMembers = monthlyMembers[monthlyMembers.length - 2]?.new_members || 0;
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

    res.render("officer/analytics", {
      title: "Analytics | UniClub",
      officer,
      club: clubs[0] || null,
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
router.get("/messages", requireOfficer, async (req, res) => {
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
router.get("/messages/view/:id", requireOfficer, async (req, res) => {
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

    res.render("officer/communication", {
      title: "Communication Center | UniClub",
      officer,
      club: clubs[0] || null,
      announcements,
      stats,
      audienceOptions: ["All Members", "Officers Only", "New Members"],
    });
  } catch (err) {
    console.error("Officer communication error:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

router.get("/records", requireOfficer, requirePageAccess('members'), async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;
    const role = (officer.role || '').toLowerCase();
    const isAuditor = role.includes('auditor');
    const isTreasurer = role.includes('treasurer') || role.includes('finance');
    const isSecretary = role.includes('secretary');
    
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
    
    // Fetch data
    const [
      { rows: clubs },
      { rows: members },
      { rows: officers },
      { rows: documents },
      { rows: stats }
    ] = await Promise.all([
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
    ]);
    
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
    
    const accessiblePages = getDashboardPagesForRole(role);
    
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

    const [{ rows: clubs }, { rows: officersRaw }] = await Promise.all([
      pool.query(
        `SELECT id, name, description, adviser, category, department, program, status
           FROM clubs WHERE id = ?`,
        [clubId]
      ).catch(() => ({ rows: [] })),
      pool.query(
        `SELECT id, name, studentid, role, department, program, username, permissions, photo_url, updated_at
           FROM officers
          WHERE club_id = ?
          ORDER BY role NULLS LAST, name ASC`,
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
      if (!current.updated_at) return latest;
      return !latest || current.updated_at > latest ? current.updated_at : latest;
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
            `SELECT id, requirement, title, description, priority, status, due_date, created_at, updated_at, club_id
               FROM requirements
              WHERE club_id = ? OR club_id IS NULL
              ORDER BY COALESCE(due_date, created_at) ASC NULLS LAST`,
            [clubId]
          )
          .catch(() => ({ rows: [] })),
        pool
          .query(
            `SELECT id, activity, club, date, location, status, created_at
               FROM activities
              WHERE club IS NULL OR club = (SELECT name FROM clubs WHERE id = ?)
              ORDER BY date DESC NULLS LAST, created_at DESC
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
        description: row.description || "",
        priority: row.priority || null,
        status: rawStatus,
        statusKey: rawStatus ? rawStatus.toLowerCase() : "pending",
        dueDate: row.due_date,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
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
    
    if (!isAuditor && !isTreasurer) {
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
    
    // Get accessible pages for sidebar
    const accessiblePages = getDashboardPagesForRole(role);
    
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
router.post("/finance/expense/:id/approve", requireOfficer, requirePageAccess('finance'), writeLimiter, async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const expenseId = parseInt(req.params.id);
    const clubId = officer.club_id;
    
    if (!expenseId || isNaN(expenseId)) {
      return res.status(400).json({ error: "Invalid expense ID" });
    }
    
    // Check if officer is auditor
    const role = (officer.role || '').toLowerCase();
    const isAuditor = role.includes('auditor');
    
    if (!isAuditor) {
      return res.status(403).json({ error: "Only auditors can approve expenses" });
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
    
    const [{ rows: clubs }, { rows: events }] = await Promise.all([
      pool.query(
        `SELECT id, name, description, adviser, category, department, program, status
         FROM clubs WHERE id = ?`,
        [clubId]
      ).catch(() => ({ rows: [] })),
      pool.query(
        `SELECT id, name, date, location, description, club_id, created_at
         FROM events
         WHERE club_id = ? AND DATE(date) >= ? AND DATE(date) <= ?
         ORDER BY date ASC, name ASC`,
        [clubId, startDateStr, endDateStr]
      ).catch(() => ({ rows: [] }))
    ]);
    
    // Get accessible pages for sidebar
    const accessiblePages = getDashboardPagesForRole(role);
    
    res.render("officer/calendar", {
      title: "Calendar | UniClub",
      officer,
      club: clubs[0] || null,
      accessiblePages,
      csrfToken: req.csrfToken ? req.csrfToken() : res.locals.csrfToken || '',
      events: events || [],
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
router.post("/calendar/event/create", requireOfficer, requirePageAccess('events'), writeLimiter, async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;
    const role = (officer.role || '').toLowerCase();
    
    // Check permissions
    if (!hasPermission(role, 'create_events')) {
      return res.status(403).json({ error: "You don't have permission to create events" });
    }
    
    const { name, date, location, description } = req.body;
    
    // Validation
    if (!name || !name.trim()) {
      return res.status(400).json({ error: "Event name is required" });
    }
    
    if (!date) {
      return res.status(400).json({ error: "Event date is required" });
    }
    
    // Insert event
    const result = await pool.query(
      `INSERT INTO events (club_id, name, date, location, description)
       VALUES (?, ?, ?, ?, ?)`,
      [clubId, name.trim(), date, location?.trim() || null, description?.trim() || null]
    );
    
    const eventId = result.insertId || result.rows[0]?.id;
    
    res.json({ success: true, message: "Event created successfully", eventId });
  } catch (err) {
    console.error("Create event error:", err);
    res.status(500).json({ error: "Failed to create event: " + err.message });
  }
});

// Update Event
router.post("/calendar/event/:id/update", requireOfficer, requirePageAccess('events'), writeLimiter, async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;
    const eventId = parseInt(req.params.id);
    const role = (officer.role || '').toLowerCase();
    
    if (!eventId || isNaN(eventId)) {
      return res.status(400).json({ error: "Invalid event ID" });
    }
    
    // Check permissions
    if (!hasPermission(role, 'edit_events')) {
      return res.status(403).json({ error: "You don't have permission to edit events" });
    }
    
    // Verify event exists and belongs to club
    const eventCheck = await pool.query(
      `SELECT id FROM events WHERE id = ? AND club_id = ?`,
      [eventId, clubId]
    ).catch(() => ({ rows: [] }));
    
    if (eventCheck.rows.length === 0) {
      return res.status(404).json({ error: "Event not found" });
    }
    
    const { name, date, location, description } = req.body;
    
    // Update event
    await pool.query(
      `UPDATE events 
       SET name = ?, date = ?, location = ?, description = ?
       WHERE id = ? AND club_id = ?`,
      [name?.trim() || null, date || null, location?.trim() || null, description?.trim() || null, eventId, clubId]
    );
    
    res.json({ success: true, message: "Event updated successfully" });
  } catch (err) {
    console.error("Update event error:", err);
    res.status(500).json({ error: "Failed to update event: " + err.message });
  }
});

// Cancel Event
router.post("/calendar/event/:id/cancel", requireOfficer, requirePageAccess('events'), writeLimiter, async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const clubId = officer.club_id;
    const eventId = parseInt(req.params.id);
    const role = (officer.role || '').toLowerCase();
    
    if (!eventId || isNaN(eventId)) {
      return res.status(400).json({ error: "Invalid event ID" });
    }
    
    // Check permissions
    if (!hasPermission(role, 'cancel_events')) {
      return res.status(403).json({ error: "You don't have permission to cancel events" });
    }
    
    // Verify event exists and belongs to club
    const eventCheck = await pool.query(
      `SELECT id, name FROM events WHERE id = ? AND club_id = ?`,
      [eventId, clubId]
    ).catch(() => ({ rows: [] }));
    
    if (eventCheck.rows.length === 0) {
      return res.status(404).json({ error: "Event not found" });
    }
    
    // Update event status (assuming we add a status column, or we can delete it)
    // For now, we'll mark it as cancelled by updating the name
    await pool.query(
      `UPDATE events 
       SET name = CONCAT(name, ' [CANCELLED]')
       WHERE id = ? AND club_id = ? AND name NOT LIKE '%[CANCELLED]%'`,
      [eventId, clubId]
    );
    
    res.json({ success: true, message: "Event cancelled successfully" });
  } catch (err) {
    console.error("Cancel event error:", err);
    res.status(500).json({ error: "Failed to cancel event: " + err.message });
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
      `SELECT id, name, date, location, description
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
router.post("/calendar/event/:id/delete", requireOfficer, requirePageAccess('events'), writeLimiter, async (req, res) => {
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

router.post("/finance/expense/:id/reject", requireOfficer, requirePageAccess('finance'), writeLimiter, async (req, res) => {
  try {
    const officer = { ...req.session.officer };
    const expenseId = parseInt(req.params.id);
    const clubId = officer.club_id;
    const { notes } = req.body;
    
    if (!expenseId || isNaN(expenseId)) {
      return res.status(400).json({ error: "Invalid expense ID" });
    }
    
    // Check if officer is auditor
    const role = (officer.role || '').toLowerCase();
    const isAuditor = role.includes('auditor');
    
    if (!isAuditor) {
      return res.status(403).json({ error: "Only auditors can reject expenses" });
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
router.post("/finance/expense/create", requireOfficer, requirePageAccess('finance'), writeLimiter, async (req, res) => {
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

