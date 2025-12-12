// routes/adminRoutes.js
import express from "express";
import bcrypt from "bcryptjs";
import { body, validationResult } from "express-validator";
import pool, { adminPool } from "../config/db.js";
import { loginLimiter, csrfProtection, writeLimiter, csrfMiddleware } from "../middleware/security.js";
import { 
  strictAuthLimiter,
  validatePasswordStrength,
  recordFailedAttempt,
  clearFailedAttempts,
  isAccountLocked,
  getLockoutTimeRemaining,
  logSecurityEvent
} from "../middleware/advancedSecurity.js";
import { uploadClubPhoto, uploadStudentPhoto, uploadEventDocuments } from "../middleware/upload.js";
import { getPermissionsForRole, isPresidentRole } from "../config/tierPermissions.js";
import { updateEventStatuses } from "../utils/eventStatus.js";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import Tokens from "csrf";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Helper function to clean up uploaded student photo on validation errors
const cleanupStudentPhoto = (req) => {
  if (req.file) {
    // Use req.file.path if available (set by multer), otherwise construct path
    const filePath = req.file.path || path.join(__dirname, '../public/img/students', req.file.filename);
    fs.unlink(filePath, (err) => {
      if (err && err.code !== 'ENOENT') {
        console.error('Error deleting uploaded student photo:', err);
      }
    });
  }
};

const router = express.Router();

// Update Event Status (API endpoint for inline updates) - must be before CSRF protection
router.put("/events/:id/status", writeLimiter, async (req, res) => {
  if (!req.session?.admin) {
    return res.status(403).json({ success: false, error: "Admin access required" });
  }

  try {
    // Manual CSRF validation for PUT requests with JSON
    const csrfToken = req.body?._csrf;
    if (!csrfToken) {
      return res.status(403).json({ success: false, error: "CSRF token is required" });
    }

    // Validate CSRF token manually using the csrf library
    // Compare against the stored secret in the session, not by generating a new token
    const tokens = new Tokens();
    const secret = req.session?.csrfSecret;
    
    if (!secret) {
      return res.status(403).json({ success: false, error: "CSRF session not found. Please refresh the page and try again." });
    }
    
    if (!tokens.verify(secret, csrfToken)) {
      return res.status(403).json({ success: false, error: "Invalid security token. Please refresh the page and try again." });
    }

    const { status } = req.body;
    const eventId = parseInt(req.params.id);

    if (!eventId || isNaN(eventId)) {
      return res.status(400).json({ success: false, error: "Invalid event ID" });
    }

    // Validate status
    const validStatuses = ['Scheduled', 'Ongoing', 'Completed', 'Cancelled', 'scheduled', 'ongoing', 'completed', 'cancelled'];
    if (!status || !validStatuses.includes(status)) {
      return res.status(400).json({ success: false, error: "Invalid status. Must be one of: Scheduled, Ongoing, Completed, Cancelled" });
    }

    // Normalize status (capitalize first letter)
    const normalizedStatus = status.charAt(0).toUpperCase() + status.slice(1).toLowerCase();

    // Update event status
    await pool.query(
      "UPDATE events SET status = ? WHERE id = ?",
      [normalizedStatus, eventId]
    );

    res.json({ 
      success: true, 
      message: `Event status updated to ${normalizedStatus}`,
      status: normalizedStatus
    });
  } catch (error) {
    console.error("Error updating event status:", error);
    res.status(500).json({ success: false, error: "Failed to update event status: " + error.message });
  }
});

// Apply CSRF protection to all POST/PUT/DELETE routes in this router
router.use(csrfProtection);

const DEPARTMENT_PROGRAMS = {
  "Department of Accounting Education": [
    "Bachelor of Science in Accountancy",
    "Bachelor of Science in Management Accounting",
  ],
  "Department of Arts and Sciences Education": [
    "Bachelor of Arts Major in English Language",
    "Bachelor of Science in Psychology",
  ],
  "Department of Business Administration Education": [
    "Bachelor of Science in Business Administration - Financial Management",
    "Bachelor of Science in Business Administration - Human Resource Management",
    "Bachelor of Science in Business Administration - Marketing Management",
  ],
  "Department of Computing Education": [
    "Bachelor of Science in Information Technology",
    "Bachelor of Science in Computer Science",
  ],
  "Department of Criminal Justice Education": [
    "Bachelor of Science in Criminology",
  ],
  "Department of Engineering Education": [
    "Bachelor of Science in Computer Engineering",
    "Bachelor of Science in Electrical Engineering",
    "Bachelor of Science in Electronics & Communications Engineering",
  ],
  "Department of Hospitality Education": [
    "Bachelor of Science in Hospitality Management",
    "Bachelor of Science in Tourism Management",
  ],
  "Department of Teacher Education": [
    "Bachelor of Elementary Education",
    "Bachelor of Physical Education",
    "Bachelor of Secondary Education - Major in English",
    "Bachelor of Secondary Education - Major in Filipino",
    "Bachelor of Secondary Education - Major in General Science",
    "Bachelor of Secondary Education - Major in Mathematics",
    "Bachelor of Secondary Education - Major in Social Studies",
  ],
};

const ALL_PROGRAMS = Array.from(
  new Set(Object.values(DEPARTMENT_PROGRAMS).flat())
);

function resolvePrograms(department, program) {
  if (Array.isArray(program)) {
    return program;
  }

  if (program === "__ALL__") {
    if (!department || department === "All Departments") {
      return ALL_PROGRAMS;
    }
    return DEPARTMENT_PROGRAMS[department] || [];
  }

  if (!program) {
    return [];
  }

  return [program];
}

function isAllProgramsSelected(programArray) {
  if (!Array.isArray(programArray)) return false;
  if (programArray.length !== ALL_PROGRAMS.length) return false;
  const set = new Set(programArray);
  return ALL_PROGRAMS.every((p) => set.has(p));
}

function getProgramValue(programArray) {
  if (isAllProgramsSelected(programArray)) return "__ALL__";
  if (Array.isArray(programArray) && programArray.length > 0) {
    return programArray[0];
  }
  return "";
}

// Ensure students.profile_picture exists and can store large paths/base64
async function ensureStudentProfilePictureColumn() {
  try {
    const colCheck = await pool.query(
      `SELECT DATA_TYPE 
         FROM information_schema.COLUMNS 
        WHERE TABLE_SCHEMA = DATABASE() 
          AND TABLE_NAME = 'students' 
          AND COLUMN_NAME = 'profile_picture'`
    );
    if (!colCheck.rows.length) {
      await pool.query(`ALTER TABLE students ADD COLUMN profile_picture MEDIUMTEXT`);
    } else {
      const dataType = (colCheck.rows[0]?.DATA_TYPE || '').toLowerCase();
      if (dataType !== 'mediumtext') {
        await pool.query(`ALTER TABLE students MODIFY COLUMN profile_picture MEDIUMTEXT`);
      }
    }
  } catch (err) {
    console.error("Failed to ensure students.profile_picture column:", err.message);
  }
}

// Name validation helper: only letters, spaces, hyphens, and apostrophes
function validateName(name, fieldName = "Name") {
  if (!name || typeof name !== 'string') {
    return { valid: false, error: `${fieldName} is required` };
  }
  
  const trimmed = name.trim();
  if (trimmed.length === 0) {
    return { valid: false, error: `${fieldName} cannot be empty` };
  }
  
  // Pattern: only letters, spaces, hyphens, and apostrophes
  const namePattern = /^[A-Za-z\s'-]+$/;
  
  // Check for potentially malicious content (excluding apostrophe which is allowed)
  const dangerousPatterns = /[<>\"&;{}[\]()=+*$%#@!`~|\\]/;
  
  if (dangerousPatterns.test(trimmed) || !namePattern.test(trimmed)) {
    return { 
      valid: false, 
      error: `${fieldName} contains invalid characters. Only letters, spaces, hyphens (-), and apostrophes (') are allowed.` 
    };
  }
  
  if (trimmed.length > 100) {
    return { valid: false, error: `${fieldName} must be 100 characters or less` };
  }
  
  return { valid: true, value: trimmed };
}

/* ===============================
   🧠 ADMIN AUTH ROUTES
================================= */

// Admin Login Page
router.get("/login", (req, res) => {
  // Get error from query string if present (e.g., from CSRF failure redirect)
  const error = req.query.error === 'csrf_invalid' 
    ? 'Security token expired. Please try again.' 
    : req.query.error || null;
  
  res.render("admin/login", { 
    title: "Admin Login | UniClub", 
    error: error 
  });
});

// Handle Login
router.post("/login", 
  strictAuthLimiter,
  loginLimiter,
  body('username').trim().notEmpty().withMessage('Username is required'),
  body('password').notEmpty().withMessage('Password is required'),
  async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render("admin/login", { 
      title: "Admin Login | UniClub", 
      error: errors.array()[0].msg 
    });
  }

  const { username, password } = req.body;
  const clientIP = req.ip || req.connection.remoteAddress;

  try {
    // Check if account is locked
    if (isAccountLocked(username, clientIP)) {
      const remainingTime = getLockoutTimeRemaining(username, clientIP);
      logSecurityEvent('LOCKED_ACCOUNT_ACCESS_ATTEMPT', { username, ip: clientIP }, req);
      return res.render("admin/login", { 
        title: "Admin Login | UniClub", 
        error: `Account temporarily locked due to multiple failed attempts. Please try again in ${Math.ceil(remainingTime / 60)} minutes.` 
      });
    }

    const result = await adminPool.query("SELECT * FROM admins WHERE username = ?", [username]);
    if (result.rows.length === 0) {
      recordFailedAttempt(username, clientIP);
      logSecurityEvent('FAILED_LOGIN', { username, reason: 'User not found', ip: clientIP }, req);
      return res.render("admin/login", { title: "Admin Login | UniClub", error: "Invalid username or password" });
    }

    const admin = result.rows[0];
    // Use password_hash if available (new schema), fallback to password (legacy schema)
    const adminPassword = admin.password_hash || admin.password;
    if (!adminPassword) {
      recordFailedAttempt(username, clientIP);
      logSecurityEvent('FAILED_LOGIN', { username, reason: 'No password set', ip: clientIP }, req);
      return res.render("admin/login", { title: "Admin Login | UniClub", error: "Invalid username or password" });
    }
    const isMatch = await bcrypt.compare(password, adminPassword);
    if (!isMatch) {
      recordFailedAttempt(username, clientIP);
      logSecurityEvent('FAILED_LOGIN', { username, reason: 'Invalid password', ip: clientIP }, req);
      return res.render("admin/login", { title: "Admin Login | UniClub", error: "Invalid username or password" });
    }

    // Clear failed attempts on successful login
    clearFailedAttempts(username, clientIP);
    logSecurityEvent('SUCCESSFUL_LOGIN', { username, ip: clientIP }, req);

    // Save session before setting admin to ensure CSRF secret persists
    req.session.save((err) => {
      if (err) {
        console.error("Session save error:", err);
        return res.render("admin/login", { title: "Admin Login | UniClub", error: "Session error. Please try again." });
      }
      
      req.session.admin = admin;
      // Redirect after session is saved
      res.redirect("/admin/dashboard");
    });
  } catch (error) {
    console.error("Login error:", error);
    logSecurityEvent('LOGIN_ERROR', { username, error: error.message, ip: clientIP }, req);
    res.render("admin/login", { title: "Admin Login | UniClub", error: "Server error" });
  }
});
// Edit Officer Form
router.get("/officers/edit/:id", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const id = req.params.id;
    
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
    
    const [officerR, clubsR] = await Promise.all([
      pool.query("SELECT * FROM officers WHERE id = ?", [id]),
      pool.query("SELECT id, name FROM clubs ORDER BY name ASC"),
    ]);
    if (officerR.rows.length === 0) return res.redirect("/admin/officers");
    const officer = officerR.rows[0];
    // Try to derive club_name for select comparison
    const clubName = (await pool.query("SELECT name FROM clubs WHERE id = ?", [officer.club_id]).catch(()=>({rows:[]}))).rows[0]?.name || null;
    
    // Parse permissions from database
    let permissions = null;
    try {
      if (officer.permissions) {
        // If permissions is a string, parse it; if it's already an object, use it
        if (typeof officer.permissions === 'string') {
          const parsed = JSON.parse(officer.permissions);
          // Handle both old format (array) and new format (object with permissions array)
          if (Array.isArray(parsed)) {
            permissions = { permissions: parsed };
          } else if (parsed && typeof parsed === 'object' && parsed.permissions) {
            permissions = parsed;
          } else {
            permissions = { permissions: [] };
          }
        } else if (typeof officer.permissions === 'object') {
          if (Array.isArray(officer.permissions)) {
            permissions = { permissions: officer.permissions };
          } else if (officer.permissions.permissions) {
            permissions = officer.permissions;
          } else {
            permissions = { permissions: [] };
          }
        }
      }
    } catch(err) {
      console.warn("Error parsing permissions:", err);
      permissions = null;
    }
    
    // Get expected permissions for this role
    const rolePermissions = getPermissionsForRole(officer.role || '');
    const isPresident = isPresidentRole(officer.role || '');
    
    // For President and other Tier 1 roles, always ensure all permissions are present
    // This ensures that if permissions were saved before new permissions were added, they get updated
    if (isPresident || rolePermissions.length > 0) {
      if (!permissions || !permissions.permissions || !Array.isArray(permissions.permissions) || permissions.permissions.length === 0) {
        // No permissions exist, use role permissions
        permissions = { permissions: rolePermissions };
        console.log(`[Admin Edit Officer] Auto-loaded ${rolePermissions.length} permissions for role: "${officer.role}"`);
      } else {
        // Permissions exist, but for President/Tier 1, ensure all role permissions are included
        // Merge existing permissions with role permissions to ensure completeness
        const existingPermsSet = new Set(permissions.permissions);
        const rolePermsSet = new Set(rolePermissions);
        
        // Add any missing permissions from the role
        rolePermissions.forEach(perm => {
          if (!existingPermsSet.has(perm)) {
            permissions.permissions.push(perm);
            console.log(`[Admin Edit Officer] Added missing permission "${perm}" for role "${officer.role}"`);
          }
        });
        
        // For President, ensure we have ALL tier permissions (no missing ones)
        if (isPresident && permissions.permissions.length < rolePermissions.length) {
          console.log(`[Admin Edit Officer] Updating permissions for President: had ${permissions.permissions.length}, ensuring all ${rolePermissions.length} are present`);
          permissions = { permissions: rolePermissions };
        } else {
          console.log(`[Admin Edit Officer] Loaded ${permissions.permissions.length} existing permissions from database for role: "${officer.role}"`);
        }
      }
      
      if (rolePermissions.length === 0) {
        console.warn(`[Admin Edit Officer] WARNING: No permissions found for role "${officer.role}" - role may not be recognized`);
      }
    } else {
      // For other roles, use existing permissions or role permissions if empty
      if (!permissions || !permissions.permissions || !Array.isArray(permissions.permissions) || permissions.permissions.length === 0) {
        permissions = { permissions: rolePermissions };
        console.log(`[Admin Edit Officer] Auto-loaded ${rolePermissions.length} permissions for role: "${officer.role}"`);
      } else {
        console.log(`[Admin Edit Officer] Loaded ${permissions.permissions.length} existing permissions from database for role: "${officer.role}"`);
      }
    }
    
    // Fetch activity logs for this officer
    let activityLogs = [];
    try {
      // Try to fetch from audit_logs table if it exists
      const auditLogsResult = await pool.query(
        `SELECT 
          id,
          action_type as type,
          entity_type,
          description as title,
          created_at as timestamp,
          (SELECT CONCAT(first_name, ' ', last_name) FROM officers WHERE id = performed_by) as actor,
          TIMESTAMPDIFF(HOUR, created_at, NOW()) as hours_ago
        FROM audit_logs
        WHERE performed_by = ? OR entity_id = ?
        ORDER BY created_at DESC
        LIMIT 50`,
        [id, id]
      ).catch(() => ({ rows: [] }));
      
      // Format the logs
      activityLogs = auditLogsResult.rows.map(log => {
        const hoursAgo = log.hours_ago || 0;
        let timeAgo = '';
        if (hoursAgo < 1) {
          timeAgo = 'Just now';
        } else if (hoursAgo < 24) {
          timeAgo = `${hoursAgo} hour${hoursAgo > 1 ? 's' : ''} ago`;
        } else {
          const daysAgo = Math.floor(hoursAgo / 24);
          timeAgo = `${daysAgo} day${daysAgo > 1 ? 's' : ''} ago`;
        }
        
        // Determine type based on entity_type or action_type
        let logType = 'system';
        if (log.entity_type) {
          const entity = log.entity_type.toLowerCase();
          if (entity.includes('event')) logType = 'events';
          else if (entity.includes('document')) logType = 'documents';
          else if (entity.includes('financial') || entity.includes('expense') || entity.includes('budget')) logType = 'financial';
          else if (entity.includes('permission') || entity.includes('officer')) logType = 'system';
        }
        
        return {
          type: logType,
          title: log.title || log.action_type || 'Activity',
          actor: log.actor || 'System',
          time_ago: timeAgo,
          timestamp: log.timestamp
        };
      });
    } catch (err) {
      console.warn("Error fetching activity logs:", err);
      activityLogs = [];
    }
    
    res.render("admin/editOfficer", {
      title: "Edit Officer",
      officer: { ...officer, club_name: clubName, permissions },
      clubs: clubsR.rows || [],
      activityLogs,
      currentPath: "/admin/officers",
      messages: [],
      error: null,
      csrfToken: res.locals.csrfToken || req.csrfToken?.() || '',
    });
  } catch (error) {
    console.error("Error loading officer:", error);
    res.status(500).send("Server error");
  }
});

// Handle Edit Officer
router.post("/officers/edit/:id", writeLimiter, async (req, res) => {
  const { first_name, last_name, studentid, email, club_id, role, department, program, permissions, current_password, password, confirm_password } = req.body;
  const id = req.params.id;
  try {
    // Name validation
    const firstNameValidation = validateName(first_name, "First name");
    if (!firstNameValidation.valid) {
      const [officerR, clubsR] = await Promise.all([
        pool.query("SELECT * FROM officers WHERE id = ?", [id]),
        pool.query("SELECT id, name FROM clubs ORDER BY name ASC"),
      ]);
      const officer = officerR.rows[0];
      const clubName = (await pool.query("SELECT name FROM clubs WHERE id = ?", [officer.club_id]).catch(()=>({rows:[]}))).rows[0]?.name || null;
      let perms = null; try { perms = officer.permissions; } catch(_) { perms = null; }
      return res.render("admin/editOfficer", {
        title: "Edit Officer",
        officer: { ...officer, club_name: clubName, permissions: perms },
        clubs: clubsR.rows || [],
        currentPath: "/admin/officers",
        messages: [],
        error: firstNameValidation.error,
      });
    }
    
    const lastNameValidation = validateName(last_name, "Last name");
    if (!lastNameValidation.valid) {
      const [officerR, clubsR] = await Promise.all([
        pool.query("SELECT * FROM officers WHERE id = ?", [id]),
        pool.query("SELECT id, name FROM clubs ORDER BY name ASC"),
      ]);
      const officer = officerR.rows[0];
      const clubName = (await pool.query("SELECT name FROM clubs WHERE id = ?", [officer.club_id]).catch(()=>({rows:[]}))).rows[0]?.name || null;
      let perms = null; try { perms = officer.permissions; } catch(_) { perms = null; }
      return res.render("admin/editOfficer", {
        title: "Edit Officer",
        officer: { ...officer, club_name: clubName, permissions: perms },
        clubs: clubsR.rows || [],
        currentPath: "/admin/officers",
        messages: [],
        error: lastNameValidation.error,
      });
    }
    
    // Student ID validation: exactly 6 digits (required)
    if (!studentid || !/^\d{6}$/.test(studentid)) {
      const [officerR, clubsR] = await Promise.all([
        pool.query("SELECT * FROM officers WHERE id = ?", [id]),
        pool.query("SELECT id, name FROM clubs ORDER BY name ASC"),
      ]);
      const officer = officerR.rows[0];
      const clubName = (await pool.query("SELECT name FROM clubs WHERE id = ?", [officer.club_id]).catch(()=>({rows:[]}))).rows[0]?.name || null;
      let perms = null; try { perms = officer.permissions; } catch(_) { perms = null; }
      return res.render("admin/editOfficer", {
        title: "Edit Officer",
        officer: { ...officer, club_name: clubName, permissions: perms },
        clubs: clubsR.rows || [],
        currentPath: "/admin/officers",
        messages: [],
        error: "Student ID is required and must be exactly 6 digits",
      });
    }

    // Check if student ID already exists (excluding current officer)
    const studentIdCheck = await pool.query(
      "SELECT id FROM officers WHERE studentid = ? AND id != ?",
      [studentid, id]
    );
    if (studentIdCheck.rows.length > 0) {
      const [officerR, clubsR] = await Promise.all([
        pool.query("SELECT * FROM officers WHERE id = ?", [id]),
        pool.query("SELECT id, name FROM clubs ORDER BY name ASC"),
      ]);
      const officer = officerR.rows[0];
      const clubName = (await pool.query("SELECT name FROM clubs WHERE id = ?", [officer.club_id]).catch(()=>({rows:[]}))).rows[0]?.name || null;
      let perms = null; try { perms = officer.permissions; } catch(_) { perms = null; }
      return res.render("admin/editOfficer", {
        title: "Edit Officer",
        officer: { ...officer, club_name: clubName, permissions: perms },
        clubs: clubsR.rows || [],
        currentPath: "/admin/officers",
        messages: [],
        error: "An officer with this Student ID already exists. Student ID must be unique.",
      });
    }

    // Check if first name + last name combination already exists (excluding current officer)
    // Note: This only rejects when BOTH first name AND last name match
    // Examples: "John Doe" + "John Smith" = ACCEPTED (same first, different last)
    //           "John Doe" + "Jane Doe" = ACCEPTED (same last, different first)
    //           "John Doe" + "John Doe" = REJECTED (both match)
    const nameCheck = await pool.query(
      "SELECT id, studentid FROM officers WHERE LOWER(TRIM(first_name)) = LOWER(TRIM(?)) AND LOWER(TRIM(last_name)) = LOWER(TRIM(?)) AND id != ?",
      [firstNameValidation.value, lastNameValidation.value, id]
    );
    if (nameCheck.rows.length > 0) {
      const existingOfficer = nameCheck.rows[0];
      const [officerR, clubsR] = await Promise.all([
        pool.query("SELECT * FROM officers WHERE id = ?", [id]),
        pool.query("SELECT id, name FROM clubs ORDER BY name ASC"),
      ]);
      const officer = officerR.rows[0];
      const clubName = (await pool.query("SELECT name FROM clubs WHERE id = ?", [officer.club_id]).catch(()=>({rows:[]}))).rows[0]?.name || null;
      let perms = null; try { perms = officer.permissions; } catch(_) { perms = null; }
      return res.render("admin/editOfficer", {
        title: "Edit Officer",
        officer: { ...officer, club_name: clubName, permissions: perms },
        clubs: clubsR.rows || [],
        currentPath: "/admin/officers",
        messages: [],
        error: `An officer with the name "${firstNameValidation.value} ${lastNameValidation.value}" already exists (Student ID: ${existingOfficer.studentid || 'N/A'}). Each officer must have a unique name combination.`,
      });
    }

    // MySQL doesn't support IF NOT EXISTS in ALTER TABLE, so we'll try to add it and ignore errors if it exists
    try {
      await pool.query(`ALTER TABLE officers ADD COLUMN permissions JSON DEFAULT ('{}')`);
    } catch (err) {
      // Column might already exist, ignore error
      if (!err.message.includes('Duplicate column name')) {
        throw err;
      }
    }
    // Ensure email column exists
    try {
      await pool.query(`ALTER TABLE officers ADD COLUMN email TEXT`);
    } catch (err) {
      // Column might already exist, ignore error
      if (err.code !== 'ER_DUP_FIELDNAME' && err.errno !== 1060 && !err.message?.includes('Duplicate column name')) {
        throw err;
      }
    }
    await pool.query(`ALTER TABLE officers ADD COLUMN IF NOT EXISTS username TEXT`);
    await pool.query(`ALTER TABLE officers ADD COLUMN IF NOT EXISTS password_hash TEXT`);
    await pool.query(`ALTER TABLE officers ADD COLUMN IF NOT EXISTS photo_url TEXT`);
    const clubId = club_id ? Number(club_id) : null;
    const clubExists = clubId
      ? await pool.query("SELECT id FROM clubs WHERE id = ? LIMIT 1", [clubId])
      : { rows: [] };
    const resolvedClubId = clubExists.rows[0]?.id || null;
    
    // Get current officer to check if role changed
    const currentOfficer = await pool.query("SELECT role, permissions FROM officers WHERE id = ?", [id]);
    const currentRole = currentOfficer.rows[0]?.role || '';
    const roleChanged = currentRole.toLowerCase() !== (role || '').toLowerCase();
    
    let perms = null;
    try { 
      // If permissions are explicitly provided, use them (allows admin override)
      if (permissions && permissions.trim()) {
        const parsed = JSON.parse(permissions);
        // Check if it's the new format { permissions: [...] } or old format
        if (parsed && parsed.permissions && Array.isArray(parsed.permissions)) {
          perms = parsed;
        } else {
          // Old format, convert to new format
          perms = { permissions: [] };
        }
      }
    } catch(_) { 
      perms = null; 
    }
    
    // If no permissions provided OR role changed, automatically assign based on tier system
    if (!perms || !perms.permissions || perms.permissions.length === 0 || roleChanged) {
      const rolePermissions = getPermissionsForRole(role || '');
      perms = { permissions: rolePermissions };
      if (roleChanged) {
        console.log(`[Admin Edit Officer] Role changed from "${currentRole}" to "${role}" - Auto-updated permissions based on tier system`);
      } else {
        console.log(`[Admin Edit Officer] Role: "${role}" - Auto-assigned ${rolePermissions.length} permissions based on tier system`);
      }
    }

    // Validate password change if new password is provided
    if (password && password.trim().length > 0) {
      // Check if officer has an existing password
      const currentOfficerCheck = await pool.query("SELECT password_hash FROM officers WHERE id = ?", [id]);
      if (currentOfficerCheck.rows.length === 0) {
        return res.redirect("/admin/officers");
      }
      
      const hasExistingPassword = currentOfficerCheck.rows[0].password_hash && currentOfficerCheck.rows[0].password_hash.trim().length > 0;
      
      // If officer has an existing password, current password is required
      if (hasExistingPassword) {
        if (!current_password || current_password.trim().length === 0) {
          const [officerR, clubsR] = await Promise.all([
            pool.query("SELECT * FROM officers WHERE id = ?", [id]),
            pool.query("SELECT id, name FROM clubs ORDER BY name ASC"),
          ]);
          const officer = officerR.rows[0];
          const clubName = (await pool.query("SELECT name FROM clubs WHERE id = ?", [officer.club_id]).catch(()=>({rows:[]}))).rows[0]?.name || null;
          let permsExisting = null; try { permsExisting = officer.permissions; } catch(_) { permsExisting = null; }
          return res.render("admin/editOfficer", {
            title: "Edit Officer",
            officer: { ...officer, club_name: clubName, permissions: permsExisting },
            clubs: clubsR.rows || [],
            currentPath: "/admin/officers",
            messages: [],
            error: "Current password is required to change password",
          });
        }

        // Verify current password
        const isValidPassword = await bcrypt.compare(current_password, currentOfficerCheck.rows[0].password_hash);
        if (!isValidPassword) {
          const [officerR, clubsR] = await Promise.all([
            pool.query("SELECT * FROM officers WHERE id = ?", [id]),
            pool.query("SELECT id, name FROM clubs ORDER BY name ASC"),
          ]);
          const officer = officerR.rows[0];
          const clubName = (await pool.query("SELECT name FROM clubs WHERE id = ?", [officer.club_id]).catch(()=>({rows:[]}))).rows[0]?.name || null;
          let permsExisting = null; try { permsExisting = officer.permissions; } catch(_) { permsExisting = null; }
          return res.render("admin/editOfficer", {
            title: "Edit Officer",
            officer: { ...officer, club_name: clubName, permissions: permsExisting },
            clubs: clubsR.rows || [],
            currentPath: "/admin/officers",
            messages: [],
            error: "Current password is incorrect",
          });
        }
      }
      // If officer doesn't have a password, allow setting it without current_password

      // Validate password confirmation
      if (!confirm_password || confirm_password.trim().length === 0) {
        const [officerR, clubsR] = await Promise.all([
          pool.query("SELECT * FROM officers WHERE id = ?", [id]),
          pool.query("SELECT id, name FROM clubs ORDER BY name ASC"),
        ]);
        const officer = officerR.rows[0];
        const clubName = (await pool.query("SELECT name FROM clubs WHERE id = ?", [officer.club_id]).catch(()=>({rows:[]}))).rows[0]?.name || null;
        let permsExisting = null; try { permsExisting = officer.permissions; } catch(_) { permsExisting = null; }
        return res.render("admin/editOfficer", {
          title: "Edit Officer",
          officer: { ...officer, club_name: clubName, permissions: permsExisting },
          clubs: clubsR.rows || [],
          currentPath: "/admin/officers",
          messages: [],
          error: "Please confirm your new password",
        });
      }
      
      if (password !== confirm_password) {
        const [officerR, clubsR] = await Promise.all([
          pool.query("SELECT * FROM officers WHERE id = ?", [id]),
          pool.query("SELECT id, name FROM clubs ORDER BY name ASC"),
        ]);
        const officer = officerR.rows[0];
        const clubName = (await pool.query("SELECT name FROM clubs WHERE id = ?", [officer.club_id]).catch(()=>({rows:[]}))).rows[0]?.name || null;
        let permsExisting = null; try { permsExisting = officer.permissions; } catch(_) { permsExisting = null; }
        return res.render("admin/editOfficer", {
          title: "Edit Officer",
          officer: { ...officer, club_name: clubName, permissions: permsExisting },
          clubs: clubsR.rows || [],
          currentPath: "/admin/officers",
          messages: [],
          error: "New passwords do not match",
        });
      }
    }

    let passwordHash = null;
    if (password && password.trim().length > 0) {
      passwordHash = await bcrypt.hash(password, 10);
    }

    // Build update query - always update password_hash if provided (to allow setting password for accounts without one)
    if (passwordHash) {
      await pool.query(
        `UPDATE officers
            SET first_name=?,
                last_name=?,
                studentid=?,
                email=?,
                club_id=?,
                role=?,
                department=?,
                program=?,
                permissions=?,
                password_hash=?
          WHERE id=?`,
        [
          firstNameValidation.value,
          lastNameValidation.value,
          studentid,
          email ? email.trim().toLowerCase() : null,
          resolvedClubId,
          role,
          department,
          program,
          perms ? JSON.stringify(perms) : null,
          passwordHash,
          id,
        ]
      );
    } else {
      await pool.query(
        `UPDATE officers
            SET first_name=?,
                last_name=?,
                studentid=?,
                email=?,
                club_id=?,
                role=?,
                department=?,
                program=?,
                permissions=?
          WHERE id=?`,
        [
          firstNameValidation.value,
          lastNameValidation.value,
          studentid,
          email ? email.trim().toLowerCase() : null,
          resolvedClubId,
          role,
          department,
          program,
          perms ? JSON.stringify(perms) : null,
          id,
        ]
      );
    }
    res.redirect("/admin/officers");
  } catch (error) {
    console.error("Error updating officer:", error);
    res.status(500).send("Server error");
  }
});

/* ===============================
   🧩 DASHBOARD
================================= */

router.get("/dashboard", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    // Auto-update event statuses before loading dashboard
    await updateEventStatuses();
    
    // Fetch admin's officer profile if they exist as an officer
    let adminOfficer = null;
    try {
      // Ensure profile_picture column exists
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
      
      // Try to find officer by admin username or email
      if (req.session.admin?.username) {
        const officerResult = await pool.query(
          `SELECT id, first_name, last_name, profile_picture, role, email 
           FROM officers 
           WHERE username = ? OR email = ? 
           LIMIT 1`,
          [req.session.admin.username, req.session.admin.username]
        );
        if (officerResult.rows.length > 0) {
          adminOfficer = officerResult.rows[0];
        }
      }
    } catch (err) {
      console.error('Error fetching admin officer profile:', err.message);
    }
    
    // Auto-migrate officer emails (normalize existing emails - safe to run multiple times)
    try {
      const { rows: officersToFix } = await pool.query(
        "SELECT id, email FROM officers WHERE email IS NOT NULL AND email != '' AND (email != LOWER(TRIM(email)) OR email != TRIM(email))"
      );
      
      if (officersToFix.length > 0) {
        let fixed = 0;
        for (const officer of officersToFix) {
          const normalizedEmail = officer.email.trim().toLowerCase();
          // Check for duplicates before updating
          const existingCheck = await pool.query(
            "SELECT id FROM officers WHERE LOWER(TRIM(email)) = ? AND id != ? LIMIT 1",
            [normalizedEmail, officer.id]
          );
          
          if (existingCheck.rows.length === 0) {
            await pool.query("UPDATE officers SET email = ? WHERE id = ?", [normalizedEmail, officer.id]);
            fixed++;
          }
        }
        if (fixed > 0) {
          console.log(`[Auto-Migration] Normalized ${fixed} officer email(s) on dashboard load`);
        }
      }
    } catch (migrationErr) {
      // Don't block dashboard if migration fails
      console.warn("[Auto-Migration] Email normalization warning:", migrationErr.message);
    }

    // Parallel queries
    const studentsQ = pool.query("SELECT COUNT(*) AS count FROM students").catch(() => ({ rows: [{ count: 0 }] }));
    const clubsQ = pool.query("SELECT COUNT(*) AS count FROM clubs").catch(() => ({ rows: [{ count: 0 }] }));
    const eventsQ = pool.query("SELECT COUNT(*) AS count FROM events").catch(() => ({ rows: [{ count: 0 }] }));

    const recentQ = pool.query(`
      SELECT id, CONCAT(first_name, ' ', last_name) AS name, created_at
      FROM students
      ORDER BY created_at DESC
      LIMIT 6
    `).catch(() => ({ rows: [] }));

    const clubsListQ = pool.query(`
      SELECT c.id, c.name, c.department, c.adviser, c.photo,
             COUNT(DISTINCT o.id) as officer_count,
             COUNT(DISTINCT a.id) as activity_count
      FROM clubs c
      LEFT JOIN officers o ON o.club_id = c.id
      LEFT JOIN activities a ON a.club = c.name
      GROUP BY c.id, c.name, c.department, c.adviser
      ORDER BY c.name
      LIMIT 8
    `).catch(() => ({ rows: [] }));

    const officersQ = pool.query("SELECT id, first_name, last_name, CONCAT(first_name, ' ', last_name) AS name, studentid, club_id, role, department, program FROM officers ORDER BY last_name, first_name LIMIT 8").catch(() => ({ rows: [] }));

    const activitiesQ = pool.query("SELECT id, activity, club, date, location, status FROM activities ORDER BY date DESC LIMIT 8").catch(() => ({ rows: [] }));
    
    // Get total activities count (separate from the limited list)
    const totalActivitiesQ = pool.query("SELECT COUNT(*) AS count FROM activities").catch(() => ({ rows: [{ count: 0 }] }));

    const requirementsQ = pool.query(`
      SELECT r.id, r.requirement, COALESCE(c.name, '—') AS club, r.due_date, r.status 
      FROM requirements r
      LEFT JOIN clubs c ON r.club_id = c.id
      ORDER BY r.due_date DESC 
      LIMIT 10
    `).catch(() => ({ rows: [] }));

    const messagesQ = pool.query(`SELECT id, sender_name AS \`from\`, subject, content, created_at, \`read\` FROM messages ORDER BY created_at DESC LIMIT 8`).catch(() => ({ rows: [] }));

    // Get pending officer approvals count
    const pendingOfficersQ = pool.query(`
      SELECT COUNT(*) AS count FROM officers 
      WHERE COALESCE(status, 'Pending') = 'Pending'
    `).catch(() => ({ rows: [{ count: 0 }] }));
    
    // Get pending requirements count (for other approvals)
    const pendingRequirementsQ = pool.query(`
      SELECT COUNT(*) AS count FROM requirements 
      WHERE status = 'pending' OR status IS NULL
    `).catch(() => ({ rows: [{ count: 0 }] }));

    // Announcements table doesn't exist yet, return empty result
    const recentAnnouncementsQ = Promise.resolve({ rows: [] });

    // Calculate top 3 most active departments based on actual activity (events, officers, recent activity)
    // Use category if department is missing
    const departmentActivityQ = pool.query(`
      SELECT 
        COALESCE(
          NULLIF(TRIM(c.department), ''), 
          NULLIF(TRIM(c.category), ''),
          'Unassigned'
        ) AS department,
        COUNT(DISTINCT c.id) AS club_count,
        COUNT(DISTINCT o.id) AS officer_count,
        COUNT(DISTINCT e.id) AS event_count,
        COUNT(DISTINCT CASE WHEN COALESCE(e.date, e.created_at) >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN e.id END) AS recent_events,
        COUNT(DISTINCT r.id) AS requirement_count,
        (COUNT(DISTINCT c.id) * 2 + COUNT(DISTINCT o.id) * 1 + COUNT(DISTINCT e.id) * 3 + 
         COUNT(DISTINCT CASE WHEN COALESCE(e.date, e.created_at) >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN e.id END) * 5 + 
         COUNT(DISTINCT r.id) * 1) AS activity_score
      FROM clubs c
      LEFT JOIN officers o ON o.club_id = c.id
      LEFT JOIN events e ON e.club_id = c.id
      LEFT JOIN requirements r ON r.club_id = c.id
      GROUP BY COALESCE(
        NULLIF(TRIM(c.department), ''), 
        NULLIF(TRIM(c.category), ''),
        'Unassigned'
      )
      HAVING COUNT(DISTINCT c.id) > 0 AND activity_score > 0
      ORDER BY activity_score DESC, event_count DESC, officer_count DESC, club_count DESC
      LIMIT 3
    `).catch(() => ({ rows: [] }));

    const officersPerClubQ = pool.query(`
      SELECT club_id, COUNT(*) as officer_count
      FROM officers
      GROUP BY club_id
    `).catch(() => ({ rows: [] }));

    const [studentsR, clubsR, eventsR, recentR, clubsListR, officersR, activitiesR, requirementsR, messagesR, pendingOfficersR, pendingRequirementsR, recentAnnouncementsR, departmentActivityR, officersPerClubR, totalActivitiesR] =
      await Promise.all([studentsQ, clubsQ, eventsQ, recentQ, clubsListQ, officersQ, activitiesQ, requirementsQ, messagesQ, pendingOfficersQ, pendingRequirementsQ, recentAnnouncementsQ, departmentActivityQ, officersPerClubQ, totalActivitiesQ]);

    // Calculate average officers per club properly
    const totalOfficers = officersR.rows.length;
    const totalClubs = Number(clubsR.rows[0]?.count || 0);
    const avgOfficersPerClub = totalClubs > 0 ? Math.round(totalOfficers / totalClubs) : 0;

    // Get top active departments with activity details
    const topActiveDepartments = departmentActivityR.rows || [];
    const mostActiveDeptData = topActiveDepartments[0] || null;
    const mostActiveDept = mostActiveDeptData?.department || null;
    const mostActiveDeptScore = mostActiveDeptData?.activity_score || 0;
    const mostActiveDeptEvents = mostActiveDeptData?.event_count || 0;
    const mostActiveDeptOfficers = mostActiveDeptData?.officer_count || 0;

    // Safely get pending officer approvals count
    const pendingOfficersCount = pendingOfficersR && pendingOfficersR.rows && pendingOfficersR.rows[0] 
      ? Number(pendingOfficersR.rows[0].count || 0) 
      : 0;
    
    // Safely get pending requirements count
    const pendingRequirementsCount = pendingRequirementsR && pendingRequirementsR.rows && pendingRequirementsR.rows[0] 
      ? Number(pendingRequirementsR.rows[0].count || 0) 
      : 0;

    // Safely get last announcement
    const lastAnnouncement = (recentAnnouncementsR && recentAnnouncementsR.rows && recentAnnouncementsR.rows[0]) 
      ? recentAnnouncementsR.rows[0] 
      : null;

    res.render("admin/dashboard", {
      title: "Admin Dashboard | UniClub",
      admin: req.session.admin,
      adminOfficer: adminOfficer,
      currentPath: "/admin/dashboard",
      studentsCount: Number(studentsR.rows[0]?.count || 0),
      clubsCount: totalClubs,
      eventsCount: Number(eventsR.rows[0]?.count || 0),
      recentActivities: recentR.rows || [],
      clubsList: clubsListR.rows || [],
      officers: officersR.rows || [],
      activities: activitiesR.rows || [],
      requirements: requirementsR.rows || [],
      messages: messagesR.rows || [],
      pending: [],
      announceSuccess: req.query?.sent === '1',
      pendingApprovals: pendingOfficersCount,
      pendingCount: pendingOfficersCount,
      pendingRequirements: pendingRequirementsCount,
      lastAnnouncement: lastAnnouncement,
      analytics: {
        activeClubs: totalClubs,
        avgOfficersPerClub: avgOfficersPerClub,
        totalActivities: Number(totalActivitiesR.rows[0]?.count || 0),
        mostActiveDept: mostActiveDept,
        mostActiveDeptData: mostActiveDeptData,
        mostActiveDeptScore: mostActiveDeptScore,
        mostActiveDeptEvents: mostActiveDeptEvents,
        mostActiveDeptOfficers: mostActiveDeptOfficers,
        topActiveDepartments: topActiveDepartments, // Top 3 departments
        totalOfficers: totalOfficers,
      },
    });
  } catch (error) {
    console.error("Error loading dashboard:", error);
    res.status(500).send("Server error");
  }
});

// Send Announcement
router.post("/announcements", writeLimiter, async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  const { subject, content, audience } = req.body;
  if (!subject || !content) {
    return res.redirect("/admin/dashboard?sent=0");
  }

  try {
    // Ensure announcements table exists
    await pool.query(`
      CREATE TABLE IF NOT EXISTS announcements (
        id SERIAL PRIMARY KEY,
        subject TEXT NOT NULL,
        content TEXT NOT NULL,
        audience VARCHAR(32) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    await pool.query(
      `INSERT INTO announcements (subject, content, audience) VALUES (?, ?, ?)`,
      [subject, content, audience || 'all']
    );

    // Optionally, mirror to messages inbox for record (no specific recipient field available)
    await pool.query(
      `INSERT INTO messages (sender_name, sender_email, subject, content, \`read\`, created_at)
       VALUES (?, ?, ?, ?, false, NOW())`,
      ['Admin', 'admin@uniclub.local', `[Announcement:${audience || 'all'}] ${subject}`, content]
    ).catch(() => {});

    res.redirect("/admin/dashboard?sent=1");
  } catch (error) {
    console.error('Error sending announcement:', error);
    res.redirect("/admin/dashboard?sent=0");
  }
});

/* ===============================
   📊 ANALYTICS
================================= */

// === ANALYTICS ===
router.get("/analytics", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    // Parallel queries with safe fallbacks
    const totalClubsQ = pool
      .query(`SELECT COUNT(*) AS total_clubs FROM clubs`)
      .catch(() => ({ rows: [{ total_clubs: 0 }] }));

    const activeDeptsQ = pool
      .query(`SELECT COUNT(DISTINCT department) AS active_depts FROM clubs WHERE department IS NOT NULL AND department <> ''`)
      .catch(() => ({ rows: [{ active_depts: 0 }] }));

    const uniqueRolesQ = pool
      .query(`SELECT COUNT(DISTINCT role) AS unique_roles FROM officers WHERE role IS NOT NULL AND role <> ''`)
      .catch(() => ({ rows: [{ unique_roles: 0 }] }));

    // Growth rate (month-over-month officers created)
    const growthQ = pool.query(`
      SELECT
        COALESCE((tm.c - NULLIF(lm.c,0)) * 100.0 / NULLIF(lm.c,0), 0.0) AS mom_growth,
        tm.c AS this_month, lm.c AS last_month
      FROM (
        SELECT COUNT(*) AS c
        FROM officers
        WHERE created_at >= DATE_FORMAT(NOW(), '%Y-%m-01')
      ) tm
      CROSS JOIN (
        SELECT COUNT(*) AS c
        FROM officers
        WHERE created_at >= DATE_FORMAT(DATE_SUB(NOW(), INTERVAL 1 MONTH), '%Y-%m-01')
          AND created_at < DATE_FORMAT(NOW(), '%Y-%m-01')
      ) lm;
    `).catch(() => ({ rows: [{ mom_growth: 0, this_month: 0, last_month: 0 }] }));

    // Trend data for KPI cards
    const clubsTrendQ = pool.query(`
      SELECT tm.c AS this_month, lm.c AS last_month,
             (tm.c - COALESCE(lm.c, 0)) AS \`change\`
      FROM (
        SELECT COUNT(*) AS c FROM clubs WHERE created_at >= DATE_FORMAT(NOW(), '%Y-%m-01')
      ) tm
      CROSS JOIN (
        SELECT COUNT(*) AS c FROM clubs 
        WHERE created_at >= DATE_FORMAT(DATE_SUB(NOW(), INTERVAL 1 MONTH), '%Y-%m-01')
          AND created_at < DATE_FORMAT(NOW(), '%Y-%m-01')
      ) lm
    `).catch(() => ({ rows: [{ this_month: 0, last_month: 0, change: 0 }] }));

    const deptsTrendQ = pool.query(`
      SELECT tm.c AS this_month, lm.c AS last_month,
             (tm.c - COALESCE(lm.c, 0)) AS \`change\`
      FROM (
        SELECT COUNT(DISTINCT department) AS c 
        FROM clubs 
        WHERE department IS NOT NULL AND department <> '' 
          AND created_at >= DATE_FORMAT(NOW(), '%Y-%m-01')
      ) tm
      CROSS JOIN (
        SELECT COUNT(DISTINCT department) AS c 
        FROM clubs 
        WHERE department IS NOT NULL AND department <> ''
          AND created_at >= DATE_FORMAT(DATE_SUB(NOW(), INTERVAL 1 MONTH), '%Y-%m-01')
          AND created_at < DATE_FORMAT(NOW(), '%Y-%m-01')
      ) lm
    `).catch(() => ({ rows: [{ this_month: 0, last_month: 0, change: 0 }] }));

    const rolesTrendQ = pool.query(`
      SELECT tm.c AS this_month, lm.c AS last_month,
             (tm.c - COALESCE(lm.c, 0)) AS \`change\`
      FROM (
        SELECT COUNT(DISTINCT role) AS c 
        FROM officers 
        WHERE role IS NOT NULL AND role <> ''
          AND created_at >= DATE_FORMAT(NOW(), '%Y-%m-01')
      ) tm
      CROSS JOIN (
        SELECT COUNT(DISTINCT role) AS c 
        FROM officers 
        WHERE role IS NOT NULL AND role <> ''
          AND created_at >= DATE_FORMAT(DATE_SUB(NOW(), INTERVAL 1 MONTH), '%Y-%m-01')
          AND created_at < DATE_FORMAT(NOW(), '%Y-%m-01')
      ) lm
    `).catch(() => ({ rows: [{ this_month: 0, last_month: 0, change: 0 }] }));

    // Clubs by department (use category if department is missing)
    const clubsByDeptQ = pool.query(`
      SELECT 
        COALESCE(
          NULLIF(TRIM(department), ''), 
          NULLIF(TRIM(category), ''),
          'Unassigned'
        ) AS department, 
        COUNT(*) AS clubs
      FROM clubs
      GROUP BY COALESCE(
        NULLIF(TRIM(department), ''), 
        NULLIF(TRIM(category), ''),
        'Unassigned'
      )
      ORDER BY department;
    `).catch(() => ({ rows: [] }));

    // Roles distribution
    const rolesDistQ = pool.query(`
      SELECT COALESCE(NULLIF(TRIM(role), ''), 'Unassigned') AS role, COUNT(*) AS count
      FROM officers
      GROUP BY COALESCE(NULLIF(TRIM(role), ''), 'Unassigned')
      ORDER BY count DESC, role ASC
      LIMIT 12;
    `).catch(() => ({ rows: [] }));

    // Monthly activity (events), use created_at if date is NULL - last 6 months
    const monthlyActQ = pool.query(`
      SELECT DATE_FORMAT(COALESCE(date, created_at), '%Y-%m') AS ym, COUNT(*) AS count
      FROM events
      WHERE COALESCE(date, created_at) >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
      GROUP BY DATE_FORMAT(COALESCE(date, created_at), '%Y-%m')
      ORDER BY ym DESC
      LIMIT 6
    `).catch(() => ({ rows: [] }));

    // Department analytics: officers & clubs per department (use category if department is missing)
    const deptAggQ = pool.query(`
      SELECT 
        COALESCE(
          NULLIF(TRIM(c.department), ''), 
          NULLIF(TRIM(c.category), ''),
          'Unassigned'
        ) AS department,
        COUNT(DISTINCT c.id) AS active_clubs,
        COUNT(DISTINCT o.id) AS total_officers,
        COALESCE(SUM(CASE WHEN COALESCE(e.date, e.created_at) >= DATE_SUB(NOW(), INTERVAL 30 DAY) THEN 1 ELSE 0 END), 0) AS recent_30,
        COALESCE(SUM(CASE WHEN COALESCE(e.date, e.created_at) >= DATE_SUB(NOW(), INTERVAL 60 DAY)
                 AND COALESCE(e.date, e.created_at) < DATE_SUB(NOW(), INTERVAL 30 DAY) THEN 1 ELSE 0 END), 0) AS prev_30
      FROM clubs c
      LEFT JOIN officers o ON o.club_id = c.id
      LEFT JOIN events e ON e.club_id = c.id
      GROUP BY COALESCE(
        NULLIF(TRIM(c.department), ''), 
        NULLIF(TRIM(c.category), ''),
        'Unassigned'
      )
      ORDER BY active_clubs DESC, department;
    `).catch((err) => {
      console.error("Department analytics query error:", err);
      return { rows: [] };
    });

    const [
      totalClubsR, activeDeptsR, uniqueRolesR,
      growthR, clubsByDeptR, rolesDistR, monthlyActR, deptAggR,
      clubsTrendR, deptsTrendR, rolesTrendR
    ] = await Promise.all([
      totalClubsQ, activeDeptsQ, uniqueRolesQ,
      growthQ, clubsByDeptQ, rolesDistQ, monthlyActQ, deptAggQ,
      clubsTrendQ, deptsTrendQ, rolesTrendQ
    ]);

    // Prepare data for charts
    const clubDeptLabels = clubsByDeptR.rows.map(r => r.department);
    const clubDeptCounts = clubsByDeptR.rows.map(r => r.clubs);

    const roleLabels = rolesDistR.rows.map(r => r.role);
    const roleCounts = rolesDistR.rows.map(r => r.count);

    // Format monthly labels and reverse to show oldest to newest (since we ordered DESC)
    const monthlyLabels = monthlyActR.rows.map(r => {
      // Format as "Jan 2024" style
      const [year, month] = r.ym.split('-');
      const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      return `${monthNames[parseInt(month) - 1]} ${year}`;
    }).reverse();
    const monthlyCounts = monthlyActR.rows.map(r => r.count).reverse();

    // Department analytics + derived "activityScore" & trend string
    const deptAnalytics = (deptAggR.rows || []).map(r => {
      const totalOfficers = Number(r.total_officers) || 0;
      const activeClubs = Number(r.active_clubs) || 0;
      const recent30 = Number(r.recent_30) || 0;
      const prev30 = Number(r.prev_30) || 0;
      const activityScore = totalOfficers * 1 + activeClubs * 2 + recent30 * 3; // simple weighted score
      let trend = 'flat';
      if (prev30 || recent30) {
        const delta = recent30 - prev30;
        trend = delta > 0 ? 'up' : (delta < 0 ? 'down' : 'flat');
      }
      return { 
        department: r.department || 'Unassigned',
        total_officers: totalOfficers,
        active_clubs: activeClubs,
        recent_30: recent30,
        prev_30: prev30,
        activityScore, 
        trend 
      };
    });

    // Calculate trends for KPI cards
    const clubsChange = clubsTrendR.rows[0]?.change || 0;
    const deptsChange = deptsTrendR.rows[0]?.change || 0;
    const rolesChange = rolesTrendR.rows[0]?.change || 0;
    const growthChange = growthR.rows[0]?.mom_growth || 0;

    res.render("admin/analytics", {
      title: "Analytics | UniClub",
      admin: req.session.admin,
      currentPath: "/admin/analytics",
      // top cards
      totalClubs: totalClubsR.rows[0]?.total_clubs || 0,
      activeDepts: activeDeptsR.rows[0]?.active_depts || 0,
      uniqueRoles: uniqueRolesR.rows[0]?.unique_roles || 0,
      growthRate: Number(growthR.rows[0]?.mom_growth || 0).toFixed(0),
      // trends
      clubsChange,
      deptsChange,
      rolesChange,
      growthChange,
      // charts
      clubDeptLabels, clubDeptCounts,
      roleLabels, roleCounts,
      monthlyLabels, monthlyCounts,
      // table
      deptAnalytics
    });
  } catch (error) {
    console.error("Analytics error:", error);
    res.status(500).render("errors/500", { title: "Server Error", error });
  }
});

/* ===============================
   👩‍🎓 STUDENT MANAGEMENT
================================= */

router.get("/students", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const { page = 1, search = "", program = "", year_level = "", department = "", status = "" } = req.query;
    const pageNum = Math.max(Number.parseInt(String(page), 10) || 1, 1);
    const studentsPerPage = 15;

    // Build base query with filters
    const params = [];
    const conditions = [];

    // Search filter
    if (search) {
      const searchParam = `%${search}%`;
      conditions.push(`(LOWER(s.first_name) LIKE LOWER(?) OR LOWER(s.last_name) LIKE LOWER(?) OR LOWER(CONCAT(s.first_name, ' ', s.last_name)) LIKE LOWER(?) OR LOWER(s.email) LIKE LOWER(?) OR LOWER(s.studentid) LIKE LOWER(?))`);
      params.push(searchParam, searchParam, searchParam, searchParam, searchParam);
    }

    // Program filter
    if (program) {
      conditions.push(`s.program = ?`);
      params.push(program);
    }

    // Year level filter
    if (year_level) {
      conditions.push(`s.year_level = ?`);
      params.push(year_level);
    }

    // Department filter
    if (department) {
      conditions.push(`s.department = ?`);
      params.push(department);
    }

    // Status filter - handle NULL statuses as 'Active'
    if (status) {
      if (status === 'Active') {
        // Include both 'Active' status and NULL statuses (which default to Active)
        conditions.push(`(COALESCE(s.status, 'Active') = ? OR s.status IS NULL)`);
        params.push(status);
      } else {
        conditions.push(`COALESCE(s.status, 'Active') = ?`);
        params.push(status);
      }
    }

    // Ensure status column exists
    try {
      await pool.query(`ALTER TABLE students ADD COLUMN status VARCHAR(50) DEFAULT 'Active'`);
    } catch (err) {
      // Column already exists, ignore error
      if (err.code !== 'ER_DUP_FIELDNAME' && err.errno !== 1060) {
        console.error('Error adding status column:', err);
      }
    }
    
    // Update any students with NULL status to 'Active'
    await pool.query(`UPDATE students SET status = 'Active' WHERE status IS NULL OR status = ''`).catch(() => {});

    // Get all students sorted by program, year_level, first_name
    const allStudentsQuery = `
      SELECT 
        s.*,
        CONCAT(s.first_name, ' ', s.last_name) AS name,
        COALESCE(s.status, 'Active') AS status
      FROM students s
      ${conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : ''}
      ORDER BY 
        COALESCE(s.program, '') ASC,
        CASE 
          WHEN s.year_level = '1st Year' THEN 1
          WHEN s.year_level = '2nd Year' THEN 2
          WHEN s.year_level = '3rd Year' THEN 3
          WHEN s.year_level = '4th Year' THEN 4
          ELSE 5
        END ASC,
        s.first_name ASC,
        s.last_name ASC
    `;

    const allStudentsResult = await pool.query(allStudentsQuery, params);
    const allStudents = allStudentsResult.rows || [];

    // Smart pagination: Handle program grouping intelligently
    // Strategy: If a program has fewer students than remaining page space, add them all
    let paginatedStudents = [];
    let currentPageStart = 0;
    let currentPageEnd = studentsPerPage;
    let studentsProcessed = 0;
    let targetPageStart = (pageNum - 1) * studentsPerPage;
    let targetPageEnd = targetPageStart + studentsPerPage;
    
    let i = 0;
    while (i < allStudents.length) {
      const student = allStudents[i];
      const currentProgram = student.program || 'No Program';
      
      // Count all students in this program
      let programStart = i;
      let programEnd = i;
      while (programEnd < allStudents.length && (allStudents[programEnd].program || 'No Program') === currentProgram) {
        programEnd++;
      }
      const programCount = programEnd - programStart;
      
      // Check if this program starts within our target page range
      if (studentsProcessed >= targetPageStart && studentsProcessed < targetPageEnd) {
        // We're in the target page
        const studentsOnPage = paginatedStudents.length;
        const remainingSpace = studentsPerPage - studentsOnPage;
        
        // If this program fits in remaining space (and we already have some students on page), add all
        if (programCount <= remainingSpace && studentsOnPage > 0 && remainingSpace < studentsPerPage) {
          // Add all students from this program
          for (let j = programStart; j < programEnd; j++) {
            paginatedStudents.push(allStudents[j]);
          }
          studentsProcessed += programCount;
          i = programEnd;
          continue;
        } else if (studentsOnPage < studentsPerPage) {
          // Add students one by one until page is full or program ends
          let added = 0;
          while (added < programCount && studentsOnPage + added < studentsPerPage && studentsProcessed < targetPageEnd) {
            paginatedStudents.push(allStudents[programStart + added]);
            added++;
            studentsProcessed++;
          }
          i = programStart + added;
          continue;
        }
      }
      
      // Skip this program if it's before our target page
      if (studentsProcessed + programCount <= targetPageStart) {
        studentsProcessed += programCount;
        i = programEnd;
        continue;
      }
      
      // If we've passed our target page, break
      if (studentsProcessed >= targetPageEnd) {
        break;
      }
      
      i++;
    }

    // Calculate total pages (approximate)
    const totalPages = Math.max(1, Math.ceil(allStudents.length / studentsPerPage));

    // Get unique programs and departments for filters
    const [programsResult, departmentsResult, yearLevelsResult] = await Promise.all([
      pool.query("SELECT DISTINCT program FROM students WHERE program IS NOT NULL AND program != '' ORDER BY program").catch(() => ({ rows: [] })),
      pool.query("SELECT DISTINCT department FROM students WHERE department IS NOT NULL AND department != '' ORDER BY department").catch(() => ({ rows: [] })),
      pool.query("SELECT DISTINCT year_level FROM students WHERE year_level IS NOT NULL AND year_level != '' ORDER BY year_level").catch(() => ({ rows: [] }))
    ]);

    res.render("admin/students", {
      title: "Students | UniClub",
      students: paginatedStudents,
      currentPath: "/admin/students",
      messages: [],
      filters: {
        search: search || "",
        program: program || "",
        year_level: year_level || "",
        department: department || "",
        status: status || ""
      },
      pagination: {
        page: pageNum,
        totalPages: totalPages,
        total: allStudents.length,
        limit: studentsPerPage
      },
      programs: programsResult.rows.map(r => r.program),
      departments: departmentsResult.rows.map(r => r.department),
      yearLevels: yearLevelsResult.rows.map(r => r.year_level)
    });
  } catch (error) {
    console.error("Error loading students:", error);
    res.status(500).send("Server error");
  }
});

router.get("/students/add", (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");
  res.render("admin/addStudent", { title: "Add Student | UniClub", error: null, currentPath: "/admin/students", messages: [] });
});

router.post("/students/add", writeLimiter, (req, res, next) => {
  uploadStudentPhoto.single('photo')(req, res, (err) => {
    if (err) {
      const errorMessage = err.code === 'LIMIT_FILE_SIZE'
        ? "Photo too large (max 5MB)."
        : (err.message || "Failed to upload photo");
      return res.render("admin/addStudent", { title: "Add Student | UniClub", error: errorMessage, currentPath: "/admin/students", messages: [] });
    }
    next();
  });
}, async (req, res) => {
  const { first_name, last_name, email, program, year_level, department, studentid, birthdate, password, confirmPassword } = req.body;
  try {
    // Name validation
    const firstNameValidation = validateName(first_name, "First name");
    if (!firstNameValidation.valid) {
      cleanupStudentPhoto(req);
      return res.render("admin/addStudent", {
        title: "Add Student | UniClub",
        error: firstNameValidation.error,
        currentPath: "/admin/students",
        messages: [],
      });
    }
    
    const lastNameValidation = validateName(last_name, "Last name");
    if (!lastNameValidation.valid) {
      cleanupStudentPhoto(req);
      return res.render("admin/addStudent", {
        title: "Add Student | UniClub",
        error: lastNameValidation.error,
        currentPath: "/admin/students",
        messages: [],
      });
    }
    
    // Email format validation: firstinitial.lastname.6digits.tc@umindanao.edu.ph
    const emailPattern = /^[a-z]\.[a-z]+\.\d{6}\.tc@umindanao\.edu\.ph$/i;
    if (!emailPattern.test(email)) {
      cleanupStudentPhoto(req);
      return res.render("admin/addStudent", {
        title: "Add Student | UniClub",
        error: "Email must follow format: firstinitial.lastname.6digitid.tc@umindanao.edu.ph (e.g., j.delacruz.111222.tc@umindanao.edu.ph or r.llano.141429.tc@umindanao.edu.ph)",
        currentPath: "/admin/students",
        messages: [],
      });
    }

    // Check if email already exists (normalize email for comparison)
    const normalizedEmail = email.trim().toLowerCase();
    const emailCheck = await pool.query(
      "SELECT id, studentid FROM students WHERE LOWER(TRIM(email)) = ?",
      [normalizedEmail]
    );
    if (emailCheck.rows.length > 0) {
      cleanupStudentPhoto(req);
      const existingStudent = emailCheck.rows[0];
      return res.render("admin/addStudent", {
        title: "Add Student | UniClub",
        error: `A student with this email already exists (Student ID: ${existingStudent.studentid || 'N/A'}). Email must be unique.`,
        currentPath: "/admin/students",
        messages: [],
      });
    }

    // Student ID validation: exactly 6 digits (required)
    if (!studentid || !/^\d{6}$/.test(studentid)) {
      cleanupStudentPhoto(req);
      return res.render("admin/addStudent", {
        title: "Add Student | UniClub",
        error: "Student ID is required and must be exactly 6 digits",
        currentPath: "/admin/students",
        messages: [],
      });
    }

    // Check if student ID already exists
    const studentIdCheck = await pool.query(
      "SELECT id FROM students WHERE studentid = ?",
      [studentid]
    );
    if (studentIdCheck.rows.length > 0) {
      cleanupStudentPhoto(req);
      return res.render("admin/addStudent", {
        title: "Add Student | UniClub",
        error: "A student with this Student ID already exists. Student ID must be unique.",
        currentPath: "/admin/students",
        messages: [],
      });
    }

    // Check if first name + last name combination already exists
    // Note: This only rejects when BOTH first name AND last name match
    // Examples: "John Doe" + "John Smith" = ACCEPTED (same first, different last)
    //           "John Doe" + "Jane Doe" = ACCEPTED (same last, different first)
    //           "John Doe" + "John Doe" = REJECTED (both match)
    const nameCheck = await pool.query(
      "SELECT id, studentid FROM students WHERE LOWER(TRIM(first_name)) = LOWER(TRIM(?)) AND LOWER(TRIM(last_name)) = LOWER(TRIM(?))",
      [firstNameValidation.value, lastNameValidation.value]
    );
    if (nameCheck.rows.length > 0) {
      cleanupStudentPhoto(req);
      const existingStudent = nameCheck.rows[0];
      return res.render("admin/addStudent", {
        title: "Add Student | UniClub",
        error: `A student with the name "${firstNameValidation.value} ${lastNameValidation.value}" already exists (Student ID: ${existingStudent.studentid || 'N/A'}). Each student must have a unique name combination.`,
        currentPath: "/admin/students",
        messages: [],
      });
    }

    // Password validation
    if (!password || password.trim().length < 8) {
      cleanupStudentPhoto(req);
      return res.render("admin/addStudent", {
        title: "Add Student | UniClub",
        error: "Password is required and must be at least 8 characters",
        currentPath: "/admin/students",
        messages: [],
      });
    }

    if (!confirmPassword || confirmPassword.trim().length === 0) {
      cleanupStudentPhoto(req);
      return res.render("admin/addStudent", {
        title: "Add Student | UniClub",
        error: "Please confirm your password",
        currentPath: "/admin/students",
        messages: [],
      });
    }

    if (password !== confirmPassword) {
      cleanupStudentPhoto(req);
      return res.render("admin/addStudent", {
        title: "Add Student | UniClub",
        error: "Passwords do not match",
        currentPath: "/admin/students",
        messages: [],
      });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Ensure optional columns exist
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS department VARCHAR(100)`);
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS studentid VARCHAR(50)`);
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS birthdate DATE`);
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS password VARCHAR(255)`);
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'Active'`);

    // Ensure photo column exists and can store larger data
    await ensureStudentProfilePictureColumn();

    // Handle photo
    let photoPath = null;
    if (req.file) {
      photoPath = `/img/students/${req.file.filename}`;
    }

    await pool.query(
      "INSERT INTO students (first_name, last_name, email, program, year_level, department, studentid, birthdate, profile_picture, password, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Active', NOW())",
      [firstNameValidation.value, lastNameValidation.value, normalizedEmail, program, year_level, department || null, studentid || null, birthdate || null, photoPath, passwordHash]
    );
    res.redirect("/admin/students");
  } catch (error) {
    console.error("Error adding student:", error);
    cleanupStudentPhoto(req);
    res.render("admin/addStudent", { title: "Add Student | UniClub", error: "Failed to add student", currentPath: "/admin/students", messages: [] });
  }
});

// ✅ Edit Student Form
router.get("/students/edit/:id", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const result = await pool.query("SELECT * FROM students WHERE id = ?", [req.params.id]);
    if (result.rows.length === 0) return res.redirect("/admin/students");

    res.render("admin/editStudent", {
      title: "Edit Student | UniClub",
      student: result.rows[0],
      error: null,
      currentPath: "/admin/students",
      messages: [],
    });
  } catch (error) {
    console.error("Error loading student for edit:", error);
    res.status(500).send("Server error");
  }
});

// ✅ Handle Edit Student
router.post("/students/edit/:id", writeLimiter, (req, res, next) => {
  uploadStudentPhoto.single('photo')(req, res, (err) => {
    if (err) {
      const errorMessage = err.code === 'LIMIT_FILE_SIZE'
        ? "Photo too large (max 5MB)."
        : (err.message || "Failed to upload photo");
      return res.render("admin/editStudent", { title: "Edit Student | UniClub", student: req.body, error: errorMessage, currentPath: "/admin/students", messages: [] });
    }
    next();
  });
}, async (req, res) => {
  const { first_name, last_name, email, program, year_level, department, studentid, status, birthdate, delete_photo, current_password, password, confirmPassword } = req.body;
  const id = req.params.id;

  try {
    // Name validation
    const firstNameValidation = validateName(first_name, "First name");
    if (!firstNameValidation.valid) {
      cleanupStudentPhoto(req);
      const result = await pool.query("SELECT * FROM students WHERE id = ?", [id]);
      const student = result.rows[0] || {};
      return res.render("admin/editStudent", {
        title: "Edit Student | UniClub",
        student: { id, first_name, last_name, email, program, year_level, department, studentid, status, birthdate },
        error: firstNameValidation.error,
        currentPath: "/admin/students",
        messages: [],
      });
    }
    
    const lastNameValidation = validateName(last_name, "Last name");
    if (!lastNameValidation.valid) {
      cleanupStudentPhoto(req);
      const result = await pool.query("SELECT * FROM students WHERE id = ?", [id]);
      const student = result.rows[0] || {};
      return res.render("admin/editStudent", {
        title: "Edit Student | UniClub",
        student: { id, first_name, last_name, email, program, year_level, department, studentid, status, birthdate },
        error: lastNameValidation.error,
        currentPath: "/admin/students",
        messages: [],
      });
    }
    
    // Email format validation: firstinitial.lastname.6digits.tc@umindanao.edu.ph
    const emailPattern = /^[a-z]\.[a-z]+\.\d{6}\.tc@umindanao\.edu\.ph$/i;
    if (!emailPattern.test(email)) {
      cleanupStudentPhoto(req);
      return res.render("admin/editStudent", {
        title: "Edit Student | UniClub",
        student: { id, first_name, last_name, email, program, year_level, department, studentid, status, birthdate },
        error: "Email must follow format: firstinitial.lastname.6digitid.tc@umindanao.edu.ph (e.g., j.delacruz.111222.tc@umindanao.edu.ph or r.llano.141429.tc@umindanao.edu.ph)",
        currentPath: "/admin/students",
        messages: [],
      });
    }

    // Check if email already exists (excluding current student)
    const normalizedEmail = email.trim().toLowerCase();
    const emailCheck = await pool.query(
      "SELECT id, studentid FROM students WHERE LOWER(TRIM(email)) = ? AND id != ?",
      [normalizedEmail, id]
    );
    if (emailCheck.rows.length > 0) {
      cleanupStudentPhoto(req);
      const existingStudent = emailCheck.rows[0];
      return res.render("admin/editStudent", {
        title: "Edit Student | UniClub",
        student: { id, first_name, last_name, email, program, year_level, department, studentid, status, birthdate },
        error: `A student with this email already exists (Student ID: ${existingStudent.studentid || 'N/A'}). Email must be unique.`,
        currentPath: "/admin/students",
        messages: [],
      });
    }

    // Student ID validation: exactly 6 digits (required)
    if (!studentid || !/^\d{6}$/.test(studentid)) {
      cleanupStudentPhoto(req);
      return res.render("admin/editStudent", {
        title: "Edit Student | UniClub",
        student: { id, first_name, last_name, email, program, year_level, department, studentid, status, birthdate },
        error: "Student ID is required and must be exactly 6 digits",
        currentPath: "/admin/students",
        messages: [],
      });
    }

    // Check if student ID already exists (excluding current student)
    const studentIdCheck = await pool.query(
      "SELECT id FROM students WHERE studentid = ? AND id != ?",
      [studentid, id]
    );
    if (studentIdCheck.rows.length > 0) {
      cleanupStudentPhoto(req);
      return res.render("admin/editStudent", {
        title: "Edit Student | UniClub",
        student: { id, first_name, last_name, email, program, year_level, department, studentid, status, birthdate },
        error: "A student with this Student ID already exists. Student ID must be unique.",
        currentPath: "/admin/students",
        messages: [],
      });
    }

    // Check if first name + last name combination already exists (excluding current student)
    // Note: This only rejects when BOTH first name AND last name match
    // Examples: "John Doe" + "John Smith" = ACCEPTED (same first, different last)
    //           "John Doe" + "Jane Doe" = ACCEPTED (same last, different first)
    //           "John Doe" + "John Doe" = REJECTED (both match)
    const nameCheck = await pool.query(
      "SELECT id, studentid FROM students WHERE LOWER(TRIM(first_name)) = LOWER(TRIM(?)) AND LOWER(TRIM(last_name)) = LOWER(TRIM(?)) AND id != ?",
      [firstNameValidation.value, lastNameValidation.value, id]
    );
    if (nameCheck.rows.length > 0) {
      cleanupStudentPhoto(req);
      const existingStudent = nameCheck.rows[0];
      return res.render("admin/editStudent", {
        title: "Edit Student | UniClub",
        student: { id, first_name, last_name, email, program, year_level, department, studentid, status, birthdate },
        error: `A student with the name "${firstNameValidation.value} ${lastNameValidation.value}" already exists (Student ID: ${existingStudent.studentid || 'N/A'}). Each student must have a unique name combination.`,
        currentPath: "/admin/students",
        messages: [],
      });
    }

    // Handle password change if new password is provided
    let passwordHash = null;
    if (password && password.trim().length > 0) {
      // Check if student has an existing password
      const currentStudent = await pool.query("SELECT password FROM students WHERE id = ?", [id]);
      if (currentStudent.rows.length === 0) {
        return res.redirect("/admin/students");
      }
      
      const hasExistingPassword = currentStudent.rows[0].password && currentStudent.rows[0].password.trim().length > 0;
      
      // If student has an existing password, current password is required
      if (hasExistingPassword) {
        if (!current_password || current_password.trim().length === 0) {
          cleanupStudentPhoto(req);
          const result = await pool.query("SELECT * FROM students WHERE id = ?", [id]);
          const student = result.rows[0] || {};
          return res.render("admin/editStudent", {
            title: "Edit Student | UniClub",
            student: { id, first_name, last_name, email, program, year_level, department, studentid, status, birthdate },
            error: "Current password is required to change password",
            currentPath: "/admin/students",
            messages: [],
          });
        }

        // Verify current password
        const isValidPassword = await bcrypt.compare(current_password, currentStudent.rows[0].password);
        if (!isValidPassword) {
          cleanupStudentPhoto(req);
          const result = await pool.query("SELECT * FROM students WHERE id = ?", [id]);
          const student = result.rows[0] || {};
          return res.render("admin/editStudent", {
            title: "Edit Student | UniClub",
            student: { id, first_name, last_name, email, program, year_level, department, studentid, status, birthdate },
            error: "Current password is incorrect",
            currentPath: "/admin/students",
            messages: [],
          });
        }
      }
      // If student doesn't have a password, allow setting it without current_password

      // Validate password confirmation
      if (!confirmPassword || confirmPassword.trim().length === 0) {
        cleanupStudentPhoto(req);
        const result = await pool.query("SELECT * FROM students WHERE id = ?", [id]);
        const student = result.rows[0] || {};
        return res.render("admin/editStudent", {
          title: "Edit Student | UniClub",
          student: { id, first_name, last_name, email, program, year_level, department, studentid, status, birthdate },
          error: "Please confirm your new password",
          currentPath: "/admin/students",
          messages: [],
        });
      }
      
      if (password !== confirmPassword) {
        cleanupStudentPhoto(req);
        const result = await pool.query("SELECT * FROM students WHERE id = ?", [id]);
        const student = result.rows[0] || {};
        return res.render("admin/editStudent", {
          title: "Edit Student | UniClub",
          student: { id, first_name, last_name, email, program, year_level, department, studentid, status, birthdate },
          error: "New passwords do not match",
          currentPath: "/admin/students",
          messages: [],
        });
      }

      // Trim password before validation and hashing for consistency
      const trimmedPassword = password.trim();
      if (trimmedPassword.length < 8) {
        cleanupStudentPhoto(req);
        const result = await pool.query("SELECT * FROM students WHERE id = ?", [id]);
        const student = result.rows[0] || {};
        return res.render("admin/editStudent", {
          title: "Edit Student | UniClub",
          student: { id, first_name, last_name, email, program, year_level, department, studentid, status, birthdate },
          error: "New password must be at least 8 characters",
          currentPath: "/admin/students",
          messages: [],
        });
      }

      passwordHash = await bcrypt.hash(trimmedPassword, 10);
    }

    // Ensure optional columns exist
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS department VARCHAR(100)`);
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS studentid VARCHAR(50)`);
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'Active'`);
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS birthdate DATE`);
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS password VARCHAR(255)`);
    await ensureStudentProfilePictureColumn();

    // Validate status
    const validStatuses = ["Active", "Graduated", "Inactive"];
    const studentStatus = validStatuses.includes(status) ? status : "Active";

    // Get current photo
    const currentStudent = await pool.query("SELECT profile_picture FROM students WHERE id = ?", [id]);
    const currentPhoto = currentStudent.rows[0]?.profile_picture || null;
    let photoPath = currentPhoto;

    // Delete photo
    if (delete_photo === 'on' || delete_photo === 'true') {
      if (currentPhoto) {
        const filePath = path.join(process.cwd(), 'public', currentPhoto);
        fs.unlink(filePath, (err) => {
          if (err && err.code !== 'ENOENT') console.error('Error deleting old student photo:', err);
        });
      }
      photoPath = null;
    }

    // New upload
    if (req.file) {
      if (currentPhoto) {
        const oldPath = path.join(process.cwd(), 'public', currentPhoto);
        fs.unlink(oldPath, (err) => {
          if (err && err.code !== 'ENOENT') console.error('Error deleting old student photo:', err);
        });
      }
      photoPath = `/img/students/${req.file.filename}`;
    }

    // Build update query - include password only if it's being changed
    if (passwordHash) {
      await pool.query(
        `UPDATE students
         SET first_name = ?, last_name = ?, email = ?, program = ?, year_level = ?, department = ?, studentid = ?, status = ?, birthdate = ?, profile_picture = ?, password = ?
         WHERE id = ?`,
        [firstNameValidation.value, lastNameValidation.value, normalizedEmail, program, year_level, department || null, studentid || null, studentStatus, birthdate || null, photoPath, passwordHash, id]
      );
    } else {
      await pool.query(
        `UPDATE students
         SET first_name = ?, last_name = ?, email = ?, program = ?, year_level = ?, department = ?, studentid = ?, status = ?, birthdate = ?, profile_picture = ?
         WHERE id = ?`,
        [firstNameValidation.value, lastNameValidation.value, normalizedEmail, program, year_level, department || null, studentid || null, studentStatus, birthdate || null, photoPath, id]
      );
    }
    res.redirect("/admin/students");
  } catch (error) {
    console.error("Error updating student:", error);
    cleanupStudentPhoto(req);
    res.render("admin/editStudent", {
      title: "Edit Student | UniClub",
      student: { id, first_name, last_name, email, program, year_level, department, studentid, status, birthdate },
      error: "Failed to update student",
      currentPath: "/admin/students",
      messages: [],
    });
  }
});

// ✅ Delete Student
router.post("/students/delete/:id", writeLimiter, async (req, res) => {
  if (!req.session?.admin) {
    // Check if request expects JSON
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }
    return res.redirect("/admin/login");
  }

  try {
    const studentId = req.params.id;
    
    if (!studentId) {
      const errorMsg = "Student ID is required";
      if (req.headers.accept && req.headers.accept.includes('application/json')) {
        return res.status(400).json({ success: false, error: errorMsg });
      }
      return res.redirect("/admin/students?error=" + encodeURIComponent(errorMsg));
    }

    // Check if student exists
    const checkResult = await pool.query("SELECT id FROM students WHERE id = ?", [studentId]);
    if (checkResult.rows.length === 0) {
      const errorMsg = "Student not found";
      if (req.headers.accept && req.headers.accept.includes('application/json')) {
        return res.status(404).json({ success: false, error: errorMsg });
      }
      return res.redirect("/admin/students?error=" + encodeURIComponent(errorMsg));
    }

    // Delete the student
    await pool.query("DELETE FROM students WHERE id = ?", [studentId]);
    
    // Check if request expects JSON (AJAX/fetch) or HTML (form submission)
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      return res.json({ success: true, message: "Student deleted successfully" });
    }
    
    // Otherwise redirect for form submissions
    res.redirect("/admin/students?deleted=true");
  } catch (error) {
    console.error("Error deleting student:", error);
    
    const errorMsg = "Failed to delete student";
    const errorDetails = process.env.NODE_ENV === 'development' ? error.message : undefined;
    
    // Check if request expects JSON
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      return res.status(500).json({ 
        success: false, 
        error: errorMsg,
        details: errorDetails
      });
    }
    
    // For form submissions, redirect with error
    res.redirect("/admin/students?error=" + encodeURIComponent(errorMsg));
  }
});

// ✅ Bulk Delete Students
router.post("/students/bulk-delete", writeLimiter, async (req, res) => {
  if (!req.session?.admin) return res.status(401).json({ success: false, error: "Unauthorized" });
  
  try {
    const { ids } = req.body;
    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ success: false, error: "No student IDs provided" });
    }
    
    // MySQL doesn't support ANY(array), use IN with array values
    const placeholders = ids.map(() => '?').join(',');
    await pool.query(`DELETE FROM students WHERE id IN (${placeholders})`, ids);
    res.json({ success: true, message: `Deleted ${ids.length} student(s)` });
  } catch (error) {
    console.error("Error bulk deleting students:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ✅ Export Students CSV
router.get("/students/export", async (req, res) => {
  if (!req.session?.admin) return res.status(401).send("Unauthorized");

  try {
    const { search = "", program = "", year_level = "", department = "", status = "" } = req.query;
    
    const params = [];
    let paramCount = 0;
    const conditions = [];

    if (search) {
      const searchParam = `%${search}%`;
      conditions.push(`(LOWER(s.first_name) LIKE LOWER(?) OR LOWER(s.last_name) LIKE LOWER(?) OR LOWER(CONCAT(s.first_name, ' ', s.last_name)) LIKE LOWER(?) OR LOWER(s.email) LIKE LOWER(?) OR LOWER(s.studentid) LIKE LOWER(?))`);
      params.push(searchParam, searchParam, searchParam, searchParam, searchParam);
    }
    if (program) {
      conditions.push(`s.program = ?`);
      params.push(program);
    }
    if (year_level) {
      conditions.push(`s.year_level = ?`);
      params.push(year_level);
    }
    if (department) {
      conditions.push(`s.department = ?`);
      params.push(department);
    }
    if (status) {
      conditions.push(`COALESCE(s.status, 'Active') = ?`);
      params.push(status);
    }

    const query = `
      SELECT 
        s.id,
        s.first_name,
        s.last_name,
        CONCAT(s.first_name, ' ', s.last_name) AS name,
        s.email,
        s.studentid,
        s.program,
        s.year_level,
        s.department,
        COALESCE(s.status, 'Active') AS status,
        s.created_at
      FROM students s
      ${conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : ''}
      ORDER BY s.first_name ASC, s.last_name ASC
    `;

    const result = await pool.query(query, params);
    const students = result.rows || [];

    if (students.length === 0) {
      return res.status(404).send("No data to export");
    }

    const headers = ["ID", "First Name", "Last Name", "Full Name", "Email", "Student ID", "Program", "Year Level", "Department", "Status", "Created At"];
    const csvHeaders = headers.join(",");
    const csvRows = students.map((row) => {
      return [
        row.id || "",
        row.first_name || "",
        row.last_name || "",
        row.name || "",
        row.email || "",
        row.studentid || "",
        row.program || "",
        row.year_level || "",
        row.department || "",
        row.status || "Active",
        row.created_at ? new Date(row.created_at).toISOString().split("T")[0] : ""
      ].map((value) => {
        const stringValue = String(value);
        if (stringValue.includes(",") || stringValue.includes("\n") || stringValue.includes('"')) {
          return `"${stringValue.replace(/"/g, '""')}"`;
        }
        return stringValue;
      }).join(",");
    });

    const csv = [csvHeaders, ...csvRows].join("\n");
    const filename = `students-export-${new Date().toISOString().split("T")[0]}.csv`;

    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.send(csv);
  } catch (error) {
    console.error("Error exporting students:", error);
    res.status(500).send("Error exporting students");
  }
});

// ✅ Update Student Status (for inline editing)
router.put("/students/:id/status", writeLimiter, async (req, res) => {
  if (!req.session?.admin) return res.status(401).json({ success: false, error: "Unauthorized" });
  
  try {
    const { status } = req.body;
    const validStatuses = ["Active", "Graduated", "Inactive"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ success: false, error: "Invalid status" });
    }
    
    await pool.query("UPDATE students SET status = ? WHERE id = ?", [status, req.params.id]);
    res.json({ success: true });
  } catch (error) {
    console.error("Error updating student status:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ✅ Update Student Field (for inline editing)
router.put("/students/:id/field", writeLimiter, async (req, res) => {
  if (!req.session?.admin) return res.status(401).json({ success: false, error: "Unauthorized" });
  
  try {
    const { field, value } = req.body;
    const allowedFields = ["first_name", "last_name", "email", "program", "year_level", "department", "studentid"];
    
    if (!allowedFields.includes(field)) {
      return res.status(400).json({ success: false, error: "Invalid field" });
    }
    
    await pool.query(`UPDATE students SET ${field} = ? WHERE id = ?`, [value, req.params.id]);
    res.json({ success: true });
  } catch (error) {
    console.error("Error updating student field:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

/* ===============================
   👥 OFFICER MANAGEMENT
================================= */

router.get("/officers", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const { page = 1, search = "", club_id = "" } = req.query;
    const pageNum = Math.max(Number.parseInt(String(page), 10) || 1, 1);

    // Ensure optional columns exist
    await pool.query(`ALTER TABLE officers ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'Active'`);

    // Get all clubs with officers, ordered by name
    const clubsWithOfficersQuery = `
      SELECT DISTINCT c.id, c.name, COUNT(o.id) as officer_count
      FROM clubs c
      LEFT JOIN officers o ON c.id = o.club_id
      GROUP BY c.id, c.name
      HAVING COUNT(o.id) > 0
      ORDER BY c.name ASC
    `;
    
    const clubsWithOfficers = await pool.query(clubsWithOfficersQuery);
    const allClubs = clubsWithOfficers.rows || [];

    // If a specific club_id is provided, use it; otherwise paginate by club
    let selectedClubId = null;
    let selectedClub = null;
    let currentPage = pageNum;

    if (club_id) {
      // Direct club filter - ensure it's a single value, not an array
      const clubIdValue = Array.isArray(club_id) ? club_id[0] : club_id;
      selectedClubId = Number.parseInt(String(clubIdValue), 10) || null;
      if (selectedClubId) {
        selectedClub = allClubs.find(c => Number(c.id) === selectedClubId);
        currentPage = 1;
      }
    } else {
      // Paginate by club - each page is one club
      if (allClubs.length > 0 && currentPage <= allClubs.length) {
        selectedClub = allClubs[currentPage - 1];
        if (selectedClub && selectedClub.id) {
          selectedClubId = Number(selectedClub.id);
        }
      }
    }

    // Build query for officers of the selected club
    const params = [];
    let paramCount = 0;
    const conditions = [];

    if (selectedClubId) {
      // Ensure selectedClubId is a single integer, not an array
      let clubIdInt = null;
      if (Array.isArray(selectedClubId)) {
        clubIdInt = Number.parseInt(String(selectedClubId[0]), 10);
      } else {
        clubIdInt = Number.parseInt(String(selectedClubId), 10);
      }
      
      if (!isNaN(clubIdInt) && clubIdInt > 0) {
        conditions.push(`o.club_id = ?`);
        params.push(clubIdInt);
        console.log(`DEBUG: Using club_id = ${clubIdInt} (type: ${typeof clubIdInt})`);
      } else {
        console.log(`DEBUG: Invalid club_id: ${selectedClubId}, showing officers without clubs`);
        conditions.push(`o.club_id IS NULL`);
      }
    } else {
      // If no clubs or invalid page, show officers without clubs
      conditions.push(`o.club_id IS NULL`);
    }

    if (search) {
      const searchParam = `%${search}%`;
      conditions.push(`(LOWER(o.first_name) LIKE LOWER(?) OR LOWER(o.last_name) LIKE LOWER(?) OR LOWER(CONCAT(o.first_name, ' ', o.last_name)) LIKE LOWER(?) OR LOWER(o.studentid) LIKE LOWER(?))`);
      params.push(searchParam, searchParam, searchParam, searchParam);
    }
    
    console.log(`DEBUG: Query params:`, params);
    console.log(`DEBUG: Query conditions:`, conditions);

    // Role priority for sorting (lower number = higher priority, appears first)
    // President MUST be priority 1 (appears first) - check for President first, excluding Vice President
    const roleOrderCase = `
      CASE 
        WHEN LOWER(TRIM(o.role)) = 'president' THEN 1
        WHEN LOWER(TRIM(o.role)) LIKE 'president%' AND LOWER(TRIM(o.role)) NOT LIKE '%vice%' THEN 1
        WHEN LOWER(TRIM(o.role)) = 'chair' THEN 1
        WHEN LOWER(TRIM(o.role)) LIKE 'chair%' AND LOWER(TRIM(o.role)) NOT LIKE '%vice%' THEN 1
        WHEN LOWER(TRIM(o.role)) = 'vice president' THEN 2
        WHEN LOWER(TRIM(o.role)) LIKE '%vice president%' THEN 2
        WHEN LOWER(TRIM(o.role)) = 'vp' THEN 2
        WHEN LOWER(TRIM(o.role)) LIKE '%vp%' AND LOWER(TRIM(o.role)) NOT LIKE '%president%' THEN 2
        WHEN LOWER(TRIM(o.role)) = 'vice chair' THEN 2
        WHEN LOWER(TRIM(o.role)) LIKE '%vice chair%' THEN 2
        WHEN LOWER(TRIM(o.role)) = 'secretary' THEN 3
        WHEN LOWER(TRIM(o.role)) LIKE '%secretary%' THEN 3
        WHEN LOWER(TRIM(o.role)) = 'treasurer' THEN 4
        WHEN LOWER(TRIM(o.role)) LIKE '%treasurer%' THEN 4
        WHEN LOWER(TRIM(o.role)) = 'public relations officer' THEN 5
        WHEN LOWER(TRIM(o.role)) LIKE '%public relations%' THEN 5
        WHEN LOWER(TRIM(o.role)) = 'events coordinator' THEN 6
        WHEN LOWER(TRIM(o.role)) LIKE '%events coordinator%' THEN 6
        WHEN LOWER(TRIM(o.role)) = 'member' THEN 99
        WHEN LOWER(TRIM(o.role)) LIKE '%member%' THEN 99
        ELSE 50
      END
    `;

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

    const listQuery = `
      SELECT 
        o.id, 
        o.first_name,
        o.last_name,
        CONCAT(o.first_name, ' ', o.last_name) AS name,
        o.studentid, 
        COALESCE(NULLIF(c.name, ''), '—') AS club, 
        o.role, 
        o.department, 
        o.program, 
        o.club_id,
        o.profile_picture,
        COALESCE(o.status, 'Active') AS status,
        ${roleOrderCase} as role_priority
      FROM officers o
      LEFT JOIN clubs c ON o.club_id = c.id
      ${conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : ''}
      ORDER BY 
        CASE WHEN role_priority IS NULL THEN 1 ELSE 0 END,
        role_priority ASC,
        CASE 
          WHEN LOWER(TRIM(o.role)) = 'president' THEN 1
          WHEN LOWER(TRIM(o.role)) = 'chair' THEN 1
          ELSE 2
        END ASC,
        o.role ASC, 
        o.last_name ASC,
        o.first_name ASC
    `;

    const [officersR, allClubsList] = await Promise.all([
      pool.query(listQuery, params),
      pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] })),
    ]);

    // Get pending officers for approval
    const pendingOfficersQuery = `
      SELECT 
        o.id, 
        o.first_name,
        o.last_name,
        CONCAT(o.first_name, ' ', o.last_name) AS name,
        o.studentid, 
        o.role, 
        o.department, 
        o.program,
        o.club_id,
        o.profile_picture,
        c.name AS club_name,
        o.created_at,
        COALESCE(o.status, 'Pending') AS status
      FROM officers o
      LEFT JOIN clubs c ON o.club_id = c.id
      WHERE COALESCE(o.status, 'Pending') = 'Pending'
      ORDER BY o.created_at DESC
    `;
    const pendingOfficersR = await pool.query(pendingOfficersQuery).catch(() => ({ rows: [] }));

    const totalPages = Math.max(allClubs.length, 1);
    const statusOptions = ["Active", "Graduated", "Inactive", "Pending", "Rejected"];
    const roleOptions = [
      "President",
      "Vice President",
      "Secretary",
      "Treasurer",
      "Auditor",
      "Public Relations Officer",
      "Events Coordinator",
      "Committee Head",
      "Member"
    ];

    res.render("admin/officers", {
      title: "Manage Officers | UniClub Admin",
      officers: officersR.rows || [],
      pendingOfficers: pendingOfficersR.rows || [],
      currentPath: "/admin/officers",
      messages: [],
      pagination: { page: currentPage, total: allClubs.length, totalPages },
      filters: { search, club_id: selectedClubId || "" },
      clubs: allClubsList.rows || [],
      currentClub: selectedClub,
      allClubs: allClubs,
      statusOptions,
      roleOptions,
    });
  } catch (error) {
    console.error("Error loading officers:", error);
    res.status(500).send("Server error while loading officers.");
  }
});

// ✅ Delete Officer (must come before other /officers/:id routes to match correctly)
router.post("/officers/delete/:id", writeLimiter, async (req, res) => {
  // Ensure we always return JSON
  res.setHeader('Content-Type', 'application/json');
  
  // Check for CSRF token manually if needed
  if (!req.body || !req.body._csrf) {
    return res.status(403).json({ 
      success: false, 
      error: "CSRF token missing. Please refresh the page and try again." 
    });
  }
  
  if (!req.session?.admin) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }

  try {
    const officerId = req.params.id;
    
    if (!officerId) {
      return res.status(400).json({ success: false, error: "Officer ID is required" });
    }
    
    // Check if officer exists
    const checkResult = await pool.query("SELECT id FROM officers WHERE id = ? LIMIT 1", [officerId]);
    if (checkResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Officer not found" });
    }

    // Delete the officer
    await pool.query("DELETE FROM officers WHERE id = ?", [officerId]);
    
    return res.json({ success: true, message: "Officer deleted successfully" });
  } catch (error) {
    console.error("Error deleting officer:", error);
    return res.status(500).json({ 
      success: false, 
      error: "Failed to delete officer",
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ✅ Inline update officer status
router.put("/officers/:id/status", writeLimiter, async (req, res) => {
  if (!req.session?.admin) return res.status(401).json({ success: false, error: "Unauthorized" });

  try {
    const { status } = req.body;
    const validStatuses = ["Active", "Graduated", "Inactive", "Pending", "Rejected"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ success: false, error: "Invalid status" });
    }

    await pool.query("UPDATE officers SET status = ? WHERE id = ?", [status, req.params.id]);
    res.json({ success: true });
  } catch (error) {
    console.error("Error updating officer status:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ✅ Approve pending officer
router.post("/officers/:id/approve", writeLimiter, async (req, res) => {
  // Ensure we always return JSON
  res.setHeader('Content-Type', 'application/json');
  
  if (!req.session?.admin) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }

  try {
    const officerId = req.params.id;
    
    // Check if officer exists
    const checkResult = await pool.query("SELECT id, first_name, last_name, status FROM officers WHERE id = ? LIMIT 1", [officerId]);
    if (checkResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Officer not found" });
    }

    const officer = checkResult.rows[0];
    
    // Update officer status to Active
    await pool.query("UPDATE officers SET status = 'Active' WHERE id = ?", [officerId]);
    
    return res.json({ 
      success: true, 
      message: `Officer ${officer.first_name} ${officer.last_name} has been approved and can now log in to the system.`
    });
  } catch (error) {
    console.error("Error approving officer:", error);
    return res.status(500).json({ 
      success: false, 
      error: "Failed to approve officer",
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ✅ Reject pending officer
router.post("/officers/:id/reject", writeLimiter, async (req, res) => {
  // Ensure we always return JSON
  res.setHeader('Content-Type', 'application/json');
  
  if (!req.session?.admin) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }

  try {
    const officerId = req.params.id;
    
    // Check if officer exists
    const checkResult = await pool.query("SELECT id, first_name, last_name, status FROM officers WHERE id = ? LIMIT 1", [officerId]);
    if (checkResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Officer not found" });
    }

    const officer = checkResult.rows[0];
    
    // Update officer status to Rejected
    await pool.query("UPDATE officers SET status = 'Rejected' WHERE id = ?", [officerId]);
    
    return res.json({ 
      success: true, 
      message: `Officer ${officer.first_name} ${officer.last_name} has been rejected.`
    });
  } catch (error) {
    console.error("Error rejecting officer:", error);
    return res.status(500).json({ 
      success: false, 
      error: "Failed to reject officer",
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ✅ Approvals Page - Show all pending items
router.get("/approvals", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    // Ensure status column exists
    await pool.query(`ALTER TABLE officers ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'Active'`);

    // Get pending officers
    const pendingOfficersQuery = `
      SELECT 
        o.id, 
        o.first_name,
        o.last_name,
        CONCAT(o.first_name, ' ', o.last_name) AS name,
        o.studentid, 
        o.role, 
        o.department, 
        o.program,
        o.club_id,
        o.profile_picture,
        c.name AS club_name,
        o.created_at,
        COALESCE(o.status, 'Pending') AS status
      FROM officers o
      LEFT JOIN clubs c ON o.club_id = c.id
      WHERE COALESCE(o.status, 'Pending') = 'Pending'
      ORDER BY o.created_at DESC
    `;
    const pendingOfficersR = await pool.query(pendingOfficersQuery).catch(() => ({ rows: [] }));

    // Ensure events table has status and approval columns
    const eventColumnsToAdd = [
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
    
    for (const col of eventColumnsToAdd) {
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
          console.warn(`Warning: Could not add column ${col.name} to events table:`, err.message);
        }
      }
    }

    // Update any events with NULL status to 'pending_approval' (for existing events)
    try {
      await pool.query(
        `UPDATE events SET status = 'pending_approval' WHERE status IS NULL OR status = ''`
      );
    } catch (updateErr) {
      // Ignore if status column doesn't exist yet (will be created above)
      if (updateErr.code !== 'ER_BAD_FIELD_ERROR') {
        console.warn("Could not update NULL status events:", updateErr.message);
      }
    }

    // Get pending events
    let pendingEvents = [];
    try {
      const result = await pool.query(
        `SELECT e.id, e.name, e.date, COALESCE(e.end_date, e.date) as end_date, e.location, e.description, e.created_at, e.admin_requirements,
                e.activity_proposal, e.letter_of_intent, e.budgetary_requirement,
                e.club_id, c.name as club_name,
                o.id as created_by_id, CONCAT(o.first_name, ' ', o.last_name) as created_by_name, o.role as created_by_role,
                COALESCE(e.status, 'pending_approval') as status
         FROM events e
         LEFT JOIN clubs c ON e.club_id = c.id
         LEFT JOIN officers o ON e.created_by = o.id
         WHERE COALESCE(e.status, 'pending_approval') = 'pending_approval'
         ORDER BY e.created_at ASC`
      );
      pendingEvents = result.rows || [];
      console.log(`[Approvals] Found ${pendingEvents.length} pending events for approval`);
    } catch (err) {
      console.error("Error fetching pending events:", err);
      // Try a simpler query without status check as fallback
      try {
        const fallbackResult = await pool.query(
          `SELECT e.id, e.name, e.date, COALESCE(e.end_date, e.date) as end_date, e.location, e.description, e.created_at,
                  e.activity_proposal, e.letter_of_intent, e.budgetary_requirement,
                  e.club_id, c.name as club_name,
                  o.id as created_by_id, CONCAT(o.first_name, ' ', o.last_name) as created_by_name, o.role as created_by_role
           FROM events e
           LEFT JOIN clubs c ON e.club_id = c.id
           LEFT JOIN officers o ON e.created_by = o.id
           WHERE e.status IS NULL OR e.status = 'pending_approval' OR e.status = ''
           ORDER BY e.created_at ASC`
        );
        pendingEvents = fallbackResult.rows || [];
        console.log(`[Approvals] Found ${pendingEvents.length} pending events (fallback query)`);
      } catch (fallbackErr) {
        console.error("Fallback query also failed:", fallbackErr);
        pendingEvents = [];
      }
    }

    // Get pending count for dashboard badge (officers + events)
    const pendingCount = (pendingOfficersR.rows?.length || 0) + (pendingEvents?.length || 0);

    res.render("admin/approvals", {
      title: "Approvals | UniClub Admin",
      pendingOfficers: pendingOfficersR.rows || [],
      pendingEvents: pendingEvents || [],
      pendingCount,
      currentPath: "/admin/approvals",
      messages: [],
      csrfToken: res.locals.csrfToken || req.csrfToken?.() || '',
    });
  } catch (error) {
    console.error("Error loading approvals:", error);
    res.status(500).render("errors/500", { title: "Server Error", error });
  }
});

// Approval History
router.get("/approvals/history", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    // Get all officers with their approval history (all statuses except Pending)
    const historyQuery = `
      SELECT 
        o.id, 
        o.first_name,
        o.last_name,
        CONCAT(o.first_name, ' ', o.last_name) AS name,
        o.studentid, 
        o.role, 
        o.department, 
        o.program,
        o.username,
        o.club_id,
        c.name AS club_name,
        o.created_at,
        o.status
      FROM officers o
      LEFT JOIN clubs c ON o.club_id = c.id
      WHERE COALESCE(o.status, 'Pending') != 'Pending'
      ORDER BY o.created_at DESC
    `;
    const historyR = await pool.query(historyQuery).catch(() => ({ rows: [] }));

    // Get statistics
    const statsQuery = `
      SELECT 
        COUNT(*) AS total,
        SUM(CASE WHEN status = 'Active' THEN 1 ELSE 0 END) AS approved,
        SUM(CASE WHEN status = 'Rejected' THEN 1 ELSE 0 END) AS rejected,
        SUM(CASE WHEN status = 'Inactive' THEN 1 ELSE 0 END) AS inactive
      FROM officers
      WHERE COALESCE(status, 'Pending') != 'Pending'
    `;
    const statsR = await pool.query(statsQuery).catch(() => ({ rows: [{ total: 0, approved: 0, rejected: 0, inactive: 0 }] }));

    res.render("admin/approvalHistory", {
      title: "Approval History | UniClub Admin",
      history: historyR.rows || [],
      stats: statsR.rows[0] || { total: 0, approved: 0, rejected: 0, inactive: 0 },
      currentPath: "/admin/approvals",
      messages: [],
    });
  } catch (error) {
    console.error("Error loading approval history:", error);
    res.status(500).render("errors/500", { title: "Server Error", error });
  }
});

// ✅ Inline update officer fields
router.put("/officers/:id/field", writeLimiter, async (req, res) => {
  if (!req.session?.admin) return res.status(401).json({ success: false, error: "Unauthorized" });

  try {
    const { field, value } = req.body;
    const allowedFields = ["role", "department", "program", "studentid"];

    if (!allowedFields.includes(field)) {
      return res.status(400).json({ success: false, error: "Invalid field" });
    }

    // If role is being updated, also update permissions based on tier system
    if (field === "role") {
      const rolePermissions = getPermissionsForRole(value || '');
      const permissionsJson = JSON.stringify({ permissions: rolePermissions });
      
      await pool.query(
        `UPDATE officers SET ${field} = ?, permissions = ? WHERE id = ?`, 
        [value, permissionsJson, req.params.id]
      );
      
      console.log(`[Admin Inline Update] Role updated to "${value}" - Auto-updated permissions based on tier system`);
    } else {
      await pool.query(`UPDATE officers SET ${field} = ? WHERE id = ?`, [value, req.params.id]);
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error("Error updating officer field:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

router.get("/officers/add", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC");
    res.render("admin/addOfficer", {
      title: "Add Officer | UniClub Admin",
      error: null,
      clubs: clubs.rows || [],
      currentPath: "/admin/officers",
      messages: [],
    });
  } catch (error) {
    console.error("Error loading clubs:", error);
    res.status(500).send("Server error.");
  }
});

router.post("/officers/add", writeLimiter, async (req, res) => {
  const { first_name, last_name, studentid, email, club_id, role, department, program, permissions, password, confirm_password } = req.body;

  try {
    // Name validation
    const firstNameValidation = validateName(first_name, "First name");
    if (!firstNameValidation.valid) {
      const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] }));
      return res.render("admin/addOfficer", {
        title: "Add Officer | UniClub Admin",
        error: firstNameValidation.error,
        clubs: clubs.rows || [],
        currentPath: "/admin/officers",
        messages: [],
        formData: req.body,
      });
    }
    
    const lastNameValidation = validateName(last_name, "Last name");
    if (!lastNameValidation.valid) {
      const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] }));
      return res.render("admin/addOfficer", {
        title: "Add Officer | UniClub Admin",
        error: lastNameValidation.error,
        clubs: clubs.rows || [],
        currentPath: "/admin/officers",
        messages: [],
        formData: req.body,
      });
    }
    
    // Student ID validation: exactly 6 digits (required)
    if (!studentid || !/^\d{6}$/.test(studentid)) {
      const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] }));
      return res.render("admin/addOfficer", {
        title: "Add Officer | UniClub Admin",
        error: "Student ID is required and must be exactly 6 digits",
        clubs: clubs.rows || [],
        currentPath: "/admin/officers",
        messages: [],
        formData: req.body,
      });
    }

    // Email format validation: firstinitial.lastname.6digits.tc@umindanao.edu.ph
    if (!email || !email.trim()) {
      const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] }));
      return res.render("admin/addOfficer", {
        title: "Add Officer | UniClub Admin",
        error: "UMindanao email is required",
        clubs: clubs.rows || [],
        currentPath: "/admin/officers",
        messages: [],
        formData: req.body,
      });
    }

    const emailPattern = /^[a-z]\.[a-z]+\.\d{6}\.tc@umindanao\.edu\.ph$/i;
    if (!emailPattern.test(email)) {
      const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] }));
      return res.render("admin/addOfficer", {
        title: "Add Officer | UniClub Admin",
        error: "Email must follow format: firstinitial.lastname.6digitid.tc@umindanao.edu.ph (e.g., j.delacruz.111222.tc@umindanao.edu.ph)",
        clubs: clubs.rows || [],
        currentPath: "/admin/officers",
        messages: [],
        formData: req.body,
      });
    }

    // Check if email already exists (normalize email for comparison)
    const normalizedEmail = email.trim().toLowerCase();
    const emailCheck = await pool.query(
      "SELECT id FROM officers WHERE LOWER(TRIM(email)) = ?",
      [normalizedEmail]
    );
    if (emailCheck.rows.length > 0) {
      const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] }));
      return res.render("admin/addOfficer", {
        title: "Add Officer | UniClub Admin",
        error: "An officer with this email already exists. Email must be unique.",
        clubs: clubs.rows || [],
        currentPath: "/admin/officers",
        messages: [],
        formData: req.body,
      });
    }

    // Check if student ID already exists
    const studentIdCheck = await pool.query(
      "SELECT id FROM officers WHERE studentid = ?",
      [studentid]
    );
    if (studentIdCheck.rows.length > 0) {
      const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] }));
      return res.render("admin/addOfficer", {
        title: "Add Officer | UniClub Admin",
        error: "An officer with this Student ID already exists. Student ID must be unique.",
        clubs: clubs.rows || [],
        currentPath: "/admin/officers",
        messages: [],
        formData: req.body,
      });
    }

    // Check if first name + last name combination already exists
    // Note: This only rejects when BOTH first name AND last name match
    // Examples: "John Doe" + "John Smith" = ACCEPTED (same first, different last)
    //           "John Doe" + "Jane Doe" = ACCEPTED (same last, different first)
    //           "John Doe" + "John Doe" = REJECTED (both match)
    const nameCheck = await pool.query(
      "SELECT id, studentid FROM officers WHERE LOWER(TRIM(first_name)) = LOWER(TRIM(?)) AND LOWER(TRIM(last_name)) = LOWER(TRIM(?))",
      [firstNameValidation.value, lastNameValidation.value]
    );
    if (nameCheck.rows.length > 0) {
      const existingOfficer = nameCheck.rows[0];
      const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] }));
      return res.render("admin/addOfficer", {
        title: "Add Officer | UniClub Admin",
        error: `An officer with the name "${firstNameValidation.value} ${lastNameValidation.value}" already exists (Student ID: ${existingOfficer.studentid || 'N/A'}). Each officer must have a unique name combination.`,
        clubs: clubs.rows || [],
        currentPath: "/admin/officers",
        messages: [],
        formData: req.body,
      });
    }

    // Validate password
    if (!password || password.trim().length < 6) {
      const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] }));
      return res.render("admin/addOfficer", {
        title: "Add Officer | UniClub Admin",
        error: "Password is required and must be at least 6 characters",
        clubs: clubs.rows || [],
        currentPath: "/admin/officers",
        messages: [],
        formData: req.body,
      });
    }

    // Validate password confirmation
    if (!confirm_password || confirm_password.trim().length === 0) {
      const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] }));
      return res.render("admin/addOfficer", {
        title: "Add Officer | UniClub Admin",
        error: "Please confirm your password",
        clubs: clubs.rows || [],
        currentPath: "/admin/officers",
        messages: [],
        formData: req.body,
      });
    }

    if (password !== confirm_password) {
      const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] }));
      return res.render("admin/addOfficer", {
        title: "Add Officer | UniClub Admin",
        error: "Passwords do not match",
        clubs: clubs.rows || [],
        currentPath: "/admin/officers",
        messages: [],
        formData: req.body,
      });
    }

    // Ensure permissions column exists
    // MySQL doesn't support IF NOT EXISTS in ALTER TABLE, so we'll try to add it and ignore errors if it exists
    try {
      await pool.query(`ALTER TABLE officers ADD COLUMN permissions JSON DEFAULT ('{}')`);
    } catch (err) {
      // Column might already exist, ignore error
      if (!err.message.includes('Duplicate column name')) {
        throw err;
      }
    }
    await pool.query(`ALTER TABLE officers ADD COLUMN IF NOT EXISTS password_hash TEXT`);
    await pool.query(`ALTER TABLE officers ADD COLUMN IF NOT EXISTS email VARCHAR(255)`);
    const clubId = club_id ? Number(club_id) : null;
    const clubExists = clubId
      ? await pool.query("SELECT id FROM clubs WHERE id = ? LIMIT 1", [clubId])
      : { rows: [] };
    const resolvedClubId = clubExists.rows[0]?.id || null;

    let perms = null;
    try { 
      // If permissions are explicitly provided, use them (allows admin override)
      if (permissions && permissions.trim()) {
        const parsed = JSON.parse(permissions);
        // Check if it's the new format { permissions: [...] } or old format
        if (parsed && parsed.permissions && Array.isArray(parsed.permissions)) {
          perms = parsed;
        } else {
          // Old format, convert to new format
          perms = { permissions: [] };
        }
      }
    } catch (_) { 
      perms = null; 
    }
    
    // If no permissions provided, automatically assign based on tier system
    if (!perms || !perms.permissions || perms.permissions.length === 0) {
      const rolePermissions = getPermissionsForRole(role || '');
      perms = { permissions: rolePermissions };
      console.log(`[Admin Add Officer] Role: "${role}" - Auto-assigned ${rolePermissions.length} permissions based on tier system`);
    }

    const passwordHash = await bcrypt.hash(password, 10);
    
    // Debug: Log password hash creation (remove in production)
    // normalizedEmail is already declared above for email uniqueness check
    console.log(`[Admin Add Officer] Creating officer with email: ${normalizedEmail}, password_hash length: ${passwordHash ? passwordHash.length : 0}`);

    await pool.query(
      `INSERT INTO officers (first_name, last_name, studentid, email, club_id, role, department, program, permissions, password_hash, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [firstNameValidation.value, lastNameValidation.value, studentid, normalizedEmail, resolvedClubId, role, department, program, JSON.stringify(perms), passwordHash]
    );
    
    // Verify the officer was created with password
    const verifyOfficer = await pool.query(
      "SELECT id, email, password_hash FROM officers WHERE LOWER(TRIM(email)) = ? LIMIT 1",
      [normalizedEmail]
    );
    if (verifyOfficer.rows.length > 0) {
      const createdOfficer = verifyOfficer.rows[0];
      console.log(`[Admin Add Officer] Officer created - ID: ${createdOfficer.id}, Email: ${createdOfficer.email}, Has password_hash: ${createdOfficer.password_hash ? 'Yes' : 'No'}`);
    }
    
    res.redirect("/admin/officers");
  } catch (error) {
    console.error("Error adding officer:", error);
    res.render("admin/addOfficer", {
      title: "Add Officer | UniClub Admin",
      error: "Failed to add officer. Please check the details.",
      clubs: [],
      formData: req.body,
    });
  }
});

/* ===============================
   🏛️ CLUB MANAGEMENT
================================= */

// ✅ View All Clubs
router.get("/clubs", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const { search = "", department = "", category = "", status = "" } = req.query;
    
    // Build query with filters
    const params = [];
    let paramCount = 0;
    const conditions = [];

    // Search filter
    if (search) {
      const searchParam = `%${search}%`;
      conditions.push(`(LOWER(c.name) LIKE LOWER(?) OR LOWER(c.description) LIKE LOWER(?) OR LOWER(c.adviser) LIKE LOWER(?))`);
      params.push(searchParam, searchParam, searchParam);
    }

    // Department filter
    if (department) {
      conditions.push(`COALESCE(c.department, '') = ?`);
      params.push(department);
    }

    // Category filter
    if (category) {
      conditions.push(`COALESCE(c.category, '') = ?`);
      params.push(category);
    }

    // Status filter
    if (status) {
      conditions.push(`COALESCE(c.status, 'Active') = ?`);
      params.push(status);
    }

    // Get unique departments and categories for filter dropdowns
    const departmentsResult = await pool.query(`
      SELECT DISTINCT COALESCE(NULLIF(TRIM(department), ''), 'Unassigned') AS department
      FROM clubs
      WHERE department IS NOT NULL AND TRIM(department) != ''
      ORDER BY department
    `);
    const departments = departmentsResult.rows.map(r => r.department);

    const categoriesResult = await pool.query(`
      SELECT DISTINCT COALESCE(NULLIF(TRIM(category), ''), 'Uncategorized') AS category
      FROM clubs
      WHERE category IS NOT NULL AND TRIM(category) != ''
      ORDER BY category
    `);
    const categories = categoriesResult.rows.map(r => r.category);

    // Build main query with proper aggregation
    // Use subqueries to avoid multiplication issues with multiple LEFT JOINs
    let query = `
      SELECT 
        c.id,
        c.name,
        c.description,
        c.category,
        c.department,
        c.adviser,
        c.program,
        c.status,
        c.photo,
        c.created_at,
        COALESCE(o_counts.officer_count, 0) AS officer_count,
        COALESCE(e_counts.event_count, 0) AS event_count
      FROM clubs c
      LEFT JOIN (
        SELECT club_id, COUNT(*) AS officer_count
        FROM officers
        GROUP BY club_id
      ) o_counts ON o_counts.club_id = c.id
      LEFT JOIN (
        SELECT club_id, COUNT(*) AS event_count
        FROM events
        GROUP BY club_id
      ) e_counts ON e_counts.club_id = c.id
    `;
    
    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(" AND ")}`;
    }
    
    query += ` ORDER BY c.name ASC`;
    
    const result = await pool.query(query, params);
    
    res.render("admin/clubs", {
      title: "Manage Clubs | UniClub Admin",
      clubs: result.rows || [],
      currentPath: "/admin/clubs",
      messages: [],
      _filters: { search, department, category, status },
      _departments: departments,
      _categories: categories,
    });
  } catch (error) {
    console.error("Error loading clubs:", error);
    res.status(500).send("Server error");
  }
});

// ✅ Add Club Form
router.get("/clubs/add", (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");
  res.render("admin/addClub", { 
    title: "Add Club | UniClub Admin", 
    error: null, 
    currentPath: "/admin/clubs", 
    messages: [],
    csrfToken: req.csrfToken?.() || ''
  });
});

// ✅ Handle Add Club
router.post("/clubs/add", writeLimiter, (req, res, next) => {
  // Log request details for debugging
  const contentType = req.headers['content-type'] || '';
  console.log('[Add Club] Request received:', {
    method: req.method,
    path: req.path,
    contentType: contentType,
    hasBody: !!req.body,
    bodyKeys: req.body ? Object.keys(req.body) : [],
    hasFile: !!req.file
  });

  // Check if request is multipart/form-data
  if (!contentType.includes('multipart/form-data')) {
    console.error('[Add Club] Invalid content-type. Expected multipart/form-data, got:', contentType);
    return res.status(400).render("admin/addClub", {
      title: "Add Club | UniClub Admin",
      error: "Invalid request format. Please ensure the form is submitted correctly.",
      currentPath: "/admin/clubs",
      messages: [],
      csrfToken: req.csrfToken?.() || ''
    });
  }

  uploadClubPhoto.single('photo')(req, res, (err) => {
    if (err) {
      // Handle multer errors
      let errorMessage = "Failed to upload photo";
      if (err.code === 'LIMIT_FILE_SIZE') {
        errorMessage = "File size too large. Maximum size is 5MB.";
      } else if (err.message && err.message.includes('Only image files')) {
        errorMessage = "Invalid file type. Only image files (JPEG, JPG, PNG, GIF, WebP) are allowed.";
      } else if (err.message) {
        errorMessage = err.message;
      }
      console.error("Multer error:", err);
      return res.render("admin/addClub", {
        title: "Add Club | UniClub Admin",
        error: errorMessage,
        currentPath: "/admin/clubs",
        messages: [],
        csrfToken: req.csrfToken?.() || ''
      });
    }

    // After multer parses the form, validate CSRF token manually
    // Log body state after multer processing
    console.log('[Add Club] After multer:', {
      hasBody: !!req.body,
      bodyKeys: req.body ? Object.keys(req.body) : [],
      hasCsrf: !!(req.body && req.body._csrf),
      hasFile: !!req.file
    });

    // Check if body was parsed - if not, it might be a content-type issue
    if (!req.body || Object.keys(req.body).length === 0) {
      console.error('[Add Club] Request body is empty after multer processing');
      console.error('[Add Club] Content-Type:', req.headers['content-type']);
      console.error('[Add Club] Request method:', req.method);
      
      // Delete uploaded file if any
      if (req.file) {
        const filePath = path.join(__dirname, '../public/img/clubs', req.file.filename);
        fs.unlink(filePath, (unlinkErr) => {
          if (unlinkErr) console.error('Error deleting uploaded file:', unlinkErr);
        });
      }
      
      return res.status(400).render("admin/addClub", {
        title: "Add Club | UniClub Admin",
        error: "Invalid request format. Please ensure the form is submitted correctly.",
        currentPath: "/admin/clubs",
        messages: [],
        csrfToken: req.csrfToken?.() || ''
      });
    }

    const csrfToken = req.body?._csrf;
    if (!csrfToken) {
      console.error('[Add Club] CSRF token missing from request body');
      console.error('[Add Club] Available body keys:', req.body ? Object.keys(req.body) : 'none');
      
      // Delete uploaded file if CSRF token is missing
      if (req.file) {
        const filePath = path.join(__dirname, '../public/img/clubs', req.file.filename);
        fs.unlink(filePath, (unlinkErr) => {
          if (unlinkErr) console.error('Error deleting uploaded file:', unlinkErr);
        });
      }
      return res.status(403).render("admin/addClub", {
        title: "Add Club | UniClub Admin",
        error: "Invalid security token. Please refresh the page and try again.",
        currentPath: "/admin/clubs",
        messages: [],
        csrfToken: req.csrfToken?.() || ''
      });
    }
    // Validate CSRF token using the same middleware instance
    // The token is already in req.body, so we can validate directly
    csrfMiddleware(req, res, (csrfErr) => {
      if (csrfErr) {
        // Delete uploaded file if CSRF validation fails
        if (req.file) {
          const filePath = path.join(__dirname, '../public/img/clubs', req.file.filename);
          fs.unlink(filePath, (unlinkErr) => {
            if (unlinkErr) console.error('Error deleting uploaded file:', unlinkErr);
          });
        }
        return res.status(403).render('errors/500', {
          title: 'Forbidden',
          error: 'Invalid security token. Please refresh the page and try again.',
        });
      }
      next();
    });
  });
}, async (req, res) => {
  const { name, description, adviser, department, program, status, category } = req.body;

  try {
    const programArray = resolvePrograms(department, program);
    
    // Handle photo upload
    let photoPath = null;
    if (req.file) {
      photoPath = `/img/clubs/${req.file.filename}`;
    }

    await pool.query(
      `INSERT INTO clubs (name, description, adviser, department, program, status, category, photo, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [name, description, adviser, department || null, programArray, status, category, photoPath]
    );
    res.redirect("/admin/clubs");
  } catch (error) {
    console.error("Error adding club:", error);
    // Delete uploaded file if database insert failed
    if (req.file) {
      const filePath = path.join(__dirname, '../public/img/clubs', req.file.filename);
      fs.unlink(filePath, (err) => {
        if (err) console.error('Error deleting uploaded file:', err);
      });
    }
    res.render("admin/addClub", {
      title: "Add Club | UniClub Admin",
      error: error.message || "Failed to add club. Please check your inputs.",
      currentPath: "/admin/clubs",
      messages: [],
      csrfToken: req.csrfToken?.() || '',
    });
  }
});

// ✅ Edit Club Form
router.get("/clubs/edit/:id", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const result = await pool.query("SELECT * FROM clubs WHERE id = ?", [req.params.id]);
    if (result.rows.length === 0) return res.redirect("/admin/clubs");

    const club = result.rows[0];
    club.program_value = getProgramValue(club.program);

    res.render("admin/editClub", {
      title: "Edit Club | UniClub Admin",
      club,
      error: null,
      currentPath: "/admin/clubs",
      messages: [],
      csrfToken: req.csrfToken?.() || ''
    });
  } catch (error) {
    console.error("Error loading club for edit:", error);
    res.status(500).send("Server error");
  }
});

// ✅ Handle Edit Club
router.post("/clubs/edit/:id", writeLimiter, (req, res, next) => {
  uploadClubPhoto.single('photo')(req, res, (err) => {
    if (err) {
      // Handle multer errors
      let errorMessage = "Failed to upload photo";
      if (err.code === 'LIMIT_FILE_SIZE') {
        errorMessage = "File size too large. Maximum size is 5MB.";
      } else if (err.message && err.message.includes('Only image files')) {
        errorMessage = "Invalid file type. Only image files (JPEG, JPG, PNG, GIF, WebP) are allowed.";
      } else if (err.message) {
        errorMessage = err.message;
      }
      console.error("Multer error:", err);
      // Get club data for error display
      return pool.query("SELECT * FROM clubs WHERE id = ?", [req.params.id])
        .then(result => {
          const club = result.rows[0] || {};
          club.program_value = getProgramValue(club.program);
          return res.render("admin/editClub", {
            title: "Edit Club | UniClub Admin",
            club: club,
            error: errorMessage,
            currentPath: "/admin/clubs",
            messages: [],
            csrfToken: req.csrfToken?.() || ''
          });
        })
        .catch(dbErr => {
          console.error("Error fetching club for error display:", dbErr);
          return res.redirect("/admin/clubs");
        });
    }
    // After multer parses the form, validate CSRF token manually
    const csrfToken = req.body?._csrf;
    if (!csrfToken) {
      // Delete uploaded file if CSRF token is missing
      if (req.file) {
        const filePath = path.join(__dirname, '../public/img/clubs', req.file.filename);
        fs.unlink(filePath, (unlinkErr) => {
          if (unlinkErr) console.error('Error deleting uploaded file:', unlinkErr);
        });
      }
      return res.status(403).render('errors/500', {
        title: 'Forbidden',
        error: 'Invalid security token. Please refresh the page and try again.',
      });
    }
    // Validate CSRF token using the same middleware instance
    // The token is already in req.body, so we can validate directly
    csrfMiddleware(req, res, (csrfErr) => {
      if (csrfErr) {
        // Delete uploaded file if CSRF validation fails
        if (req.file) {
          const filePath = path.join(__dirname, '../public/img/clubs', req.file.filename);
          fs.unlink(filePath, (unlinkErr) => {
            if (unlinkErr) console.error('Error deleting uploaded file:', unlinkErr);
          });
        }
        return res.status(403).render('errors/500', {
          title: 'Forbidden',
          error: 'Invalid security token. Please refresh the page and try again.',
        });
      }
      next();
    });
  });
}, async (req, res) => {
  const { name, description, adviser, department, program, status, category, delete_photo } = req.body;
  const id = req.params.id;

  try {
    const programArray = resolvePrograms(department, program);
    
    // Get current club photo
    const currentClub = await pool.query("SELECT photo FROM clubs WHERE id = ?", [id]);
    const currentPhoto = currentClub.rows[0]?.photo || null;
    
    // Determine new photo path
    let photoPath = currentPhoto;
    
    // If delete_photo is checked, remove photo
    if (delete_photo === 'on' || delete_photo === 'true') {
      if (currentPhoto) {
        const filePath = path.join(__dirname, '../public', currentPhoto);
        fs.unlink(filePath, (err) => {
          if (err && err.code !== 'ENOENT') console.error('Error deleting old photo:', err);
        });
      }
      photoPath = null;
    }
    
    // If new photo uploaded, use it
    if (req.file) {
      // Delete old photo if exists
      if (currentPhoto) {
        const oldFilePath = path.join(__dirname, '../public', currentPhoto);
        fs.unlink(oldFilePath, (err) => {
          if (err && err.code !== 'ENOENT') console.error('Error deleting old photo:', err);
        });
      }
      photoPath = `/img/clubs/${req.file.filename}`;
    }

    await pool.query(
      `UPDATE clubs
       SET name = ?, description = ?, adviser = ?,
           department = ?, program = ?, status = ?, category = ?, photo = ?
       WHERE id = ?`,
      [name, description, adviser, department || null, programArray, status, category, photoPath, id]
    );
    res.redirect("/admin/clubs");
  } catch (error) {
    console.error("Error updating club:", error);
    // Delete uploaded file if database update failed
    if (req.file) {
      const filePath = path.join(__dirname, '../public/img/clubs', req.file.filename);
      fs.unlink(filePath, (err) => {
        if (err) console.error('Error deleting uploaded file:', err);
      });
    }
    // Get club data for error display
    const result = await pool.query("SELECT * FROM clubs WHERE id = ?", [id]).catch(() => ({ rows: [] }));
    const club = result.rows[0] || {
      id,
      name,
      description,
      adviser,
      department,
      program: resolvePrograms(department, program),
      program_value: program === "__ALL__" ? "__ALL__" : (Array.isArray(program) ? program[0] || "" : program || ""),
      status,
      category,
      photo: currentPhoto,
    };
    club.program_value = getProgramValue(club.program);
    
    res.render("admin/editClub", {
      title: "Edit Club | UniClub Admin",
      club: club,
      error: error.message || "Failed to update club. Please check your inputs.",
      currentPath: "/admin/clubs",
      messages: [],
      csrfToken: req.csrfToken?.() || '',
    });
  }
});

// ✅ Delete Club
router.post("/clubs/delete/:id", writeLimiter, async (req, res) => {
  // Ensure we always return JSON
  res.setHeader('Content-Type', 'application/json');
  
  if (!req.session?.admin) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }

  try {
    const clubId = req.params.id;
    
    if (!clubId) {
      return res.status(400).json({ success: false, error: "Club ID is required" });
    }
    
    // Check if club exists
    const checkResult = await pool.query("SELECT id FROM clubs WHERE id = ? LIMIT 1", [clubId]);
    if (checkResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Club not found" });
    }

    // Delete the club
    await pool.query("DELETE FROM clubs WHERE id = ?", [clubId]);
    
    return res.json({ success: true, message: "Club deleted successfully" });
  } catch (error) {
    console.error("Error deleting club:", error);
    return res.status(500).json({ 
      success: false, 
      error: "Failed to delete club",
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// ✅ Update Club Status (for inline editing)
router.put("/clubs/:id/status", writeLimiter, async (req, res) => {
  if (!req.session?.admin) return res.status(401).json({ success: false, error: "Unauthorized" });
  
  try {
    const { status } = req.body;
    const validStatuses = ["Active", "Inactive"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ success: false, error: "Invalid status" });
    }
    
    await pool.query("UPDATE clubs SET status = ? WHERE id = ?", [status, req.params.id]);
    res.json({ success: true });
  } catch (error) {
    console.error("Error updating club status:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ✅ Update Club Field (for inline editing)
router.put("/clubs/:id/field", writeLimiter, async (req, res) => {
  if (!req.session?.admin) return res.status(401).json({ success: false, error: "Unauthorized" });
  
  try {
    const { field, value } = req.body;
    const allowedFields = ["name", "adviser", "department", "category"];
    
    if (!allowedFields.includes(field)) {
      return res.status(400).json({ success: false, error: "Invalid field" });
    }
    
    await pool.query(`UPDATE clubs SET ${field} = ? WHERE id = ?`, [value, req.params.id]);
    res.json({ success: true });
  } catch (error) {
    console.error("Error updating club field:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ✅ Export Clubs CSV
router.get("/clubs/export", async (req, res) => {
  if (!req.session?.admin) return res.status(401).send("Unauthorized");

  try {
    const { search = "", department = "", category = "", status = "" } = req.query;
    
    const params = [];
    let paramCount = 0;
    const conditions = [];

    if (search) {
      const searchParam = `%${search}%`;
      conditions.push(`(LOWER(c.name) LIKE LOWER(?) OR LOWER(c.description) LIKE LOWER(?) OR LOWER(c.adviser) LIKE LOWER(?))`);
      params.push(searchParam, searchParam, searchParam);
    }

    if (department) {
      conditions.push(`COALESCE(c.department, '') = ?`);
      params.push(department);
    }

    if (category) {
      conditions.push(`COALESCE(c.category, '') = ?`);
      params.push(category);
    }

    if (status) {
      conditions.push(`COALESCE(c.status, 'Active') = ?`);
      params.push(status);
    }

    let query = `
      SELECT 
        c.id,
        c.name,
        c.category,
        c.department,
        c.adviser,
        COALESCE(c.status, 'Active') AS status,
        c.created_at
      FROM clubs c
    `;
    
    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(" AND ")}`;
    }
    
    query += ` ORDER BY c.name ASC`;
    
    const result = await pool.query(query, params);
    
    const csvRows = [
      ["ID", "Name", "Category", "Department", "Adviser", "Status", "Created At"]
    ];
    
    result.rows.forEach(row => {
      csvRows.push([
        row.id || "",
        row.name || "",
        row.category || "",
        row.department || "",
        row.adviser || "",
        row.status || "Active",
        row.created_at ? new Date(row.created_at).toISOString().split("T")[0] : ""
      ].map((value) => {
        const stringValue = String(value);
        return stringValue.includes(",") || stringValue.includes('"') || stringValue.includes("\n")
          ? `"${stringValue.replace(/"/g, '""')}"`
          : stringValue;
      }));
    });
    
    const csvContent = csvRows.map(row => row.join(",")).join("\n");
    
    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename="clubs_export_${new Date().toISOString().split("T")[0]}.csv"`);
    res.send(csvContent);
  } catch (error) {
    console.error("Error exporting clubs:", error);
    res.status(500).send("Server error");
  }
});

/* ===============================
   📋 REQUIREMENTS MANAGEMENT
================================= */

// View all requirements
router.get("/requirements", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");
  
  // Auto-update event statuses before loading requirements
  await updateEventStatuses();

  try {
    // Officer uploads (requirements) – with club name if club_id exists
    let requirements = [];
    try {
      const r = await pool.query(`
        SELECT r.id, r.requirement, r.due_date, r.status,
               c.name AS club_name
      FROM requirements r
        LEFT JOIN clubs c ON c.id = r.club_id
        ORDER BY r.created_at DESC
      `);
      requirements = r.rows;
    } catch (err) {
      // Fallback #1: table without club_id but with requirement/due_date/status
      if (err.code === "42703") {
        try {
          const r2 = await pool.query(`
            SELECT id, requirement, due_date, status, NULL AS club_name
            FROM requirements
            ORDER BY created_at DESC NULLS LAST, id DESC
          `);
          requirements = r2.rows;
        } catch (err2) {
          // Fallback #2: minimal columns when we can't rely on any optional names
          if (err2.code === "42703") {
            const r3 = await pool.query(`
              SELECT id
              FROM requirements
              ORDER BY id DESC
            `);
            // Map to expected shape with safe defaults
            requirements = (r3.rows || []).map(r => ({
              id: r.id,
              requirement: '',
              due_date: null,
              status: '',
              club_name: null,
            }));
          } else {
            throw err2;
          }
        }
      } else {
        throw err;
      }
    }

    // Activities list (from events). Handle schema differences for name/status columns
    // Exclude pending and rejected events from activities list
    let activitiesRows = [];
    try {
      const activitiesWithStatus = await pool.query(`
        SELECT e.id, e.name AS activity, e.date, e.end_date, e.location, e.description,
               c.name AS club_name,
               CASE 
                 -- Use database status if it's a valid final status
                 WHEN e.status IN ('Ongoing', 'ongoing', 'Completed', 'completed', 'Cancelled', 'cancelled') THEN e.status
                 -- Otherwise, calculate based on current date
                 WHEN e.date IS NULL THEN 'Scheduled'
                 WHEN DATE(e.date) > CURDATE() THEN 'Scheduled'
                 WHEN DATE(e.date) = CURDATE() OR (DATE(e.date) <= CURDATE() AND COALESCE(DATE(e.end_date), DATE(e.date)) >= CURDATE()) THEN 'Ongoing'
                 WHEN COALESCE(DATE(e.end_date), DATE(e.date)) < CURDATE() THEN 'Completed'
                 ELSE COALESCE(e.status, 'Scheduled')
               END AS status
        FROM events e
        LEFT JOIN clubs c ON c.id = e.club_id
        WHERE COALESCE(e.status, 'pending_approval') != 'pending_approval'
          AND COALESCE(e.status, 'pending_approval') != 'rejected'
        ORDER BY e.date ASC, e.created_at DESC
      `);
      activitiesRows = activitiesWithStatus.rows || [];
    } catch (err) {
      if (err.code === "42703") {
        // Fallback A: schema without status
        try {
          const activitiesNoStatus = await pool.query(`
            SELECT e.id, e.name AS activity, e.date, e.location, e.description,
                   c.name AS club_name,
                   'Scheduled' AS status
            FROM events e
            LEFT JOIN clubs c ON c.id = e.club_id
            WHERE COALESCE(e.status, 'pending_approval') != 'pending_approval'
              AND COALESCE(e.status, 'pending_approval') != 'rejected'
            ORDER BY e.date ASC NULLS LAST, e.created_at DESC
          `);
          activitiesRows = activitiesNoStatus.rows || [];
        } catch (err2) {
          if (err2.code === "42703") {
            // Fallback B: schema where primary name column is 'activity'
            try {
              const altName1 = await pool.query(`
                SELECT e.id, e.activity AS activity, e.date, e.location, e.description,
                       c.name AS club_name,
                       'Scheduled' AS status
                FROM events e
                LEFT JOIN clubs c ON c.id = e.club_id
                WHERE COALESCE(e.status, 'pending_approval') != 'pending_approval'
                  AND COALESCE(e.status, 'pending_approval') != 'rejected'
                ORDER BY e.date ASC NULLS LAST, e.created_at DESC
              `);
              activitiesRows = altName1.rows || [];
            } catch (err3) {
              if (err3.code === "42703") {
                // Fallback C: schema where primary name column is 'title'
                try {
                  const altName2 = await pool.query(`
                    SELECT e.id, e.title AS activity, e.date, e.location, e.description,
                           c.name AS club_name,
                           'Scheduled' AS status
                    FROM events e
                    LEFT JOIN clubs c ON c.id = e.club_id
                    WHERE COALESCE(e.status, 'pending_approval') != 'pending_approval'
                      AND COALESCE(e.status, 'pending_approval') != 'rejected'
                    ORDER BY e.date ASC NULLS LAST, e.created_at DESC
                  `);
                  activitiesRows = altName2.rows || [];
                } catch (err4) {
                  if (err4.code === "42703") {
                    // Final fallback: minimal columns (exclude pending/rejected)
                    try {
                      const minimal = await pool.query(`
                        SELECT id FROM events 
                        WHERE COALESCE(status, 'pending_approval') != 'pending_approval'
                          AND COALESCE(status, 'pending_approval') != 'rejected'
                        ORDER BY id DESC
                      `);
                      activitiesRows = (minimal.rows || []).map(ev => ({
                        id: ev.id,
                        activity: `Record #${ev.id}`,
                        date: null,
                        location: '',
                        description: '',
                        club_name: null,
                        status: 'Scheduled',
                      }));
                    } catch (minimalErr) {
                      // If even the minimal query fails, return empty array
                      console.error("Error in minimal fallback query:", minimalErr);
                      activitiesRows = [];
                    }
                  } else {
                    throw err4;
                  }
                }
              } else {
                throw err3;
              }
            }
          } else {
            throw err2;
          }
        }
      } else {
        throw err;
      }
    }

    res.render("admin/requirements", {
      title: "Requirements | UniClub",
      admin: req.session.admin,
      currentPath: "/admin/requirements",
      requirements: requirements || [],
      activities: activitiesRows || [],
      messages: [],
      csrfToken: res.locals.csrfToken || req.csrfToken?.() || '',
    });
  } catch (error) {
    console.error("Error loading requirements:", error);
    res.status(500).send("Server error while loading requirements.");
  }
});

// Add requirement form
router.get("/requirements/add", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC");
    res.render("admin/addRequirement", {
      title: "Add Requirement | UniClub Admin",
      clubs: clubs.rows,
      error: null,
      currentPath: "/admin/requirements",
      messages: [],
    });
  } catch (error) {
    console.error("Error loading add requirement form:", error);
    res.status(500).send("Server error.");
  }
});

// Create Requirement (alias for /add)
router.get("/requirements/create", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC");
    res.render("admin/addRequirement", {
      title: "Create Requirement | UniClub Admin",
      clubs: clubs.rows,
      error: null,
      currentPath: "/admin/requirements",
      messages: [],
    });
  } catch (error) {
    console.error("Error loading create requirement form:", error);
    res.status(500).send("Server error.");
  }
});

// Handle add requirement
router.post("/requirements/add", writeLimiter, async (req, res) => {
  const { requirement, club_id, due_date, status } = req.body;

  try {
    await pool.query(
      `INSERT INTO requirements (requirement, club_id, due_date, status, created_at)
       VALUES (?, ?, ?, ?, NOW())`,
      [requirement, club_id, due_date, status]
    );
    res.redirect("/admin/requirements");
  } catch (error) {
    console.error("Error adding requirement:", error);
    res.status(500).send("Server error while adding requirement.");
  }
});

// Handle create requirement (alias for /add)
router.post("/requirements/create", writeLimiter, async (req, res) => {
  const { requirement, club_id, due_date, status } = req.body;

  try {
    await pool.query(
      `INSERT INTO requirements (requirement, club_id, due_date, status, created_at)
       VALUES (?, ?, ?, ?, NOW())`,
      [requirement, club_id, due_date, status]
    );
    res.redirect("/admin/requirements");
  } catch (error) {
    console.error("Error creating requirement:", error);
    res.status(500).send("Server error while creating requirement.");
  }
});

// Edit requirement form
router.get("/requirements/edit/:id", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const [requirement, clubs] = await Promise.all([
      pool.query("SELECT * FROM requirements WHERE id = ?", [req.params.id]),
      pool.query("SELECT id, name FROM clubs ORDER BY name ASC"),
    ]);

    if (requirement.rows.length === 0) return res.redirect("/admin/requirements");

    res.render("admin/editRequirement", {
      title: "Edit Requirement | UniClub Admin",
      requirement: requirement.rows[0],
      clubs: clubs.rows,
      error: null,
    });
  } catch (error) {
    console.error("Error loading requirement for edit:", error);
    res.status(500).send("Server error.");
  }
});

// Handle edit requirement
router.post("/requirements/edit/:id", writeLimiter, async (req, res) => {
  const { requirement, club_id, due_date, status } = req.body;

  try {
    await pool.query(
      `UPDATE requirements 
       SET requirement = ?, club_id = ?, due_date = ?, status = ? 
       WHERE id = ?`,
      [requirement, club_id, due_date, status, req.params.id]
    );
    res.redirect("/admin/requirements");
  } catch (error) {
    console.error("Error updating requirement:", error);
    res.status(500).send("Server error.");
  }
});

// Delete requirement
router.post("/requirements/delete/:id", writeLimiter, async (req, res) => {
  try {
    await pool.query("DELETE FROM requirements WHERE id = ?", [req.params.id]);
    res.redirect("/admin/requirements");
  } catch (error) {
    console.error("Error deleting requirement:", error);
    res.status(500).send("Server error.");
  }
});

/* ===============================
   💬 MESSAGES MANAGEMENT
================================= */

// View all messages
router.get("/messages", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    // Only show messages that are NOT sent to officers (exclude event approval notifications)
    // Messages with recipient_type = 'officer' are only for officers, not admins
    const result = await pool.query(
      `SELECT id, sender_name, sender_email, subject, content, created_at, \`read\` 
       FROM messages 
       WHERE recipient_type IS NULL OR recipient_type != 'officer'
       ORDER BY created_at DESC`
    );
    
    // Get students and officers for recipient selection
    const [studentsResult, officersResult] = await Promise.all([
      pool.query("SELECT id, CONCAT(first_name, ' ', last_name) AS name, email FROM students ORDER BY first_name, last_name").catch(() => ({ rows: [] })),
      pool.query("SELECT id, CONCAT(first_name, ' ', last_name) AS name, username FROM officers ORDER BY first_name, last_name").catch(() => ({ rows: [] }))
    ]);

    res.render("admin/messages", {
      title: "Messages | UniClub Admin",
      messages: result.rows || [],
      students: studentsResult.rows || [],
      officers: officersResult.rows || [],
      currentPath: "/admin/messages",
      csrfToken: res.locals.csrfToken || req.csrfToken?.() || '',
    });
  } catch (error) {
    console.error("Error loading messages:", error);
    res.status(500).send("Server error");
  }
});

// View a single message
router.get("/messages/view/:id", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const { id } = req.params;
    // Only allow viewing messages that are not officer-only
    const result = await pool.query(
      "SELECT * FROM messages WHERE id = ? AND (recipient_type IS NULL OR recipient_type != 'officer')", 
      [id]
    );

    if (result.rows.length === 0) return res.redirect("/admin/messages");

    // Mark message as read
    await pool.query("UPDATE messages SET `read` = true WHERE id = ?", [id]);

    res.render("admin/viewMessage", {
      title: "View Message | UniClub Admin",
      message: result.rows[0],
      currentPath: "/admin/messages",
      messages: [],
    });
  } catch (error) {
    console.error("Error loading message:", error);
    res.status(500).send("Server error");
  }
});

// Delete a message
router.post("/messages/delete/:id", writeLimiter, async (req, res) => {
  try {
    await pool.query("DELETE FROM messages WHERE id = ?", [req.params.id]);
    res.redirect("/admin/messages");
  } catch (error) {
    console.error("Error deleting message:", error);
    res.status(500).send("Server error");
  }
});

// Send a message to officers or students
router.post("/messages/send", writeLimiter, async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const { recipient_type, recipient_id, subject, content } = req.body;

    if (!subject || !content || !recipient_type) {
      return res.redirect("/admin/messages?error=missing_fields");
    }

    // Ensure messages table has recipient fields (add if not exists)
    // Check if columns exist using INFORMATION_SCHEMA
    try {
      const columnCheck = await pool.query(`
        SELECT COLUMN_NAME 
        FROM INFORMATION_SCHEMA.COLUMNS 
        WHERE TABLE_SCHEMA = DATABASE() 
        AND TABLE_NAME = 'messages' 
        AND COLUMN_NAME = 'recipient_type'
      `);
      
      // If column doesn't exist, add all three columns
      if (columnCheck.rows.length === 0) {
        try {
          await pool.query("ALTER TABLE messages ADD COLUMN recipient_type VARCHAR(50)");
        } catch (err) {
          console.log("recipient_type column may already exist or error:", err.message);
        }
        
        try {
          await pool.query("ALTER TABLE messages ADD COLUMN recipient_id INT");
        } catch (err) {
          console.log("recipient_id column may already exist or error:", err.message);
        }
        
        try {
          await pool.query("ALTER TABLE messages ADD COLUMN recipient_name VARCHAR(200)");
        } catch (err) {
          console.log("recipient_name column may already exist or error:", err.message);
        }
      }
    } catch (err) {
      // If INFORMATION_SCHEMA query fails, try to add columns anyway
      console.log("Column check failed, attempting to add columns:", err.message);
      try {
        await pool.query("ALTER TABLE messages ADD COLUMN recipient_type VARCHAR(50)");
      } catch (alterErr) {
        // Ignore if column already exists
      }
      try {
        await pool.query("ALTER TABLE messages ADD COLUMN recipient_id INT");
      } catch (alterErr) {
        // Ignore if column already exists
      }
      try {
        await pool.query("ALTER TABLE messages ADD COLUMN recipient_name VARCHAR(200)");
      } catch (alterErr) {
        // Ignore if column already exists
      }
    }

    let recipients = [];

    if (recipient_type === 'all_students') {
      const students = await pool.query("SELECT id, CONCAT(first_name, ' ', last_name) AS name, email FROM students");
      recipients = students.rows.map(s => ({ type: 'student', id: s.id, name: s.name, email: s.email }));
    } else if (recipient_type === 'all_officers') {
      // For "all officers", create individual message records for each officer
      const officers = await pool.query("SELECT id, CONCAT(first_name, ' ', last_name) AS name, username FROM officers");
      recipients = officers.rows.map(o => ({ type: 'officer', id: o.id, name: o.name, email: o.username }));
    } else if (recipient_type === 'all_presidents') {
      // Get all presidents across all clubs
      const presidents = await pool.query(`
        SELECT id, CONCAT(first_name, ' ', last_name) AS name, username, role, club_id
        FROM officers
        WHERE LOWER(TRIM(role)) LIKE '%president%'
           OR LOWER(TRIM(role)) LIKE '%supremo%'
           OR LOWER(TRIM(role)) LIKE '%grand peer%'
           OR LOWER(TRIM(role)) LIKE '%head%'
           OR LOWER(TRIM(role)) LIKE '%chairperson%'
           OR LOWER(TRIM(role)) LIKE '%chief executive%'
           OR LOWER(TRIM(role)) LIKE '%executive head%'
      `);
      recipients = presidents.rows.map(o => ({ type: 'officer', id: o.id, name: o.name, email: o.username }));
    } else if (recipient_type === 'all_treasurers') {
      // Get all treasurers across all clubs
      const treasurers = await pool.query(`
        SELECT id, CONCAT(first_name, ' ', last_name) AS name, username, role, club_id
        FROM officers
        WHERE LOWER(TRIM(role)) LIKE '%treasurer%'
           OR LOWER(TRIM(role)) LIKE '%finance%'
           OR LOWER(TRIM(role)) LIKE '%financial officer%'
           OR LOWER(TRIM(role)) LIKE '%business & finance%'
           OR LOWER(TRIM(role)) LIKE '%business and finance%'
      `);
      recipients = treasurers.rows.map(o => ({ type: 'officer', id: o.id, name: o.name, email: o.username }));
    } else if (recipient_type === 'all_secretaries') {
      // Get all secretaries across all clubs
      const secretaries = await pool.query(`
        SELECT id, CONCAT(first_name, ' ', last_name) AS name, username, role, club_id
        FROM officers
        WHERE LOWER(TRIM(role)) LIKE '%secretary%'
      `);
      recipients = secretaries.rows.map(o => ({ type: 'officer', id: o.id, name: o.name, email: o.username }));
    } else if (recipient_type === 'all_vice_presidents') {
      // Get all vice presidents across all clubs
      const vps = await pool.query(`
        SELECT id, CONCAT(first_name, ' ', last_name) AS name, username, role, club_id
        FROM officers
        WHERE LOWER(TRIM(role)) LIKE '%vice president%'
           OR LOWER(TRIM(role)) LIKE '%vice-president%'
           OR LOWER(TRIM(role)) LIKE '%vp%'
           OR LOWER(TRIM(role)) LIKE '%heneral%'
           OR LOWER(TRIM(role)) LIKE '%konsehal%'
      `);
      recipients = vps.rows.map(o => ({ type: 'officer', id: o.id, name: o.name, email: o.username }));
    } else if (recipient_type === 'all_auditors') {
      // Get all auditors across all clubs
      const auditors = await pool.query(`
        SELECT id, CONCAT(first_name, ' ', last_name) AS name, username, role, club_id
        FROM officers
        WHERE LOWER(TRIM(role)) LIKE '%auditor%'
      `);
      recipients = auditors.rows.map(o => ({ type: 'officer', id: o.id, name: o.name, email: o.username }));
    } else if (recipient_type === 'specific_student' && recipient_id) {
      const student = await pool.query("SELECT id, CONCAT(first_name, ' ', last_name) AS name, email FROM students WHERE id = ?", [recipient_id]);
      if (student.rows.length > 0) {
        recipients = [{ type: 'student', id: student.rows[0].id, name: student.rows[0].name, email: student.rows[0].email }];
      }
    } else if (recipient_type === 'specific_officer' && recipient_id) {
      const officer = await pool.query("SELECT id, CONCAT(first_name, ' ', last_name) AS name, username FROM officers WHERE id = ?", [recipient_id]);
      if (officer.rows.length > 0) {
        recipients = [{ type: 'officer', id: officer.rows[0].id, name: officer.rows[0].name, email: officer.rows[0].username }];
      }
    }

    if (recipients.length === 0) {
      return res.redirect("/admin/messages?error=no_recipients");
    }

    // Ensure modern columns exist
    const modernColumns = [
      { name: 'sender_id', def: 'INT' },
      { name: 'receiver_id', def: 'INT' },
      { name: 'sender_type', def: "VARCHAR(20) DEFAULT 'admin'" },
      { name: 'receiver_type', def: "VARCHAR(20)" }
    ];

    for (const col of modernColumns) {
      try {
        await pool.query(`ALTER TABLE messages ADD COLUMN ${col.name} ${col.def}`);
      } catch (err) {
        if (err.code !== 'ER_DUP_FIELDNAME' && err.errno !== 1060) {
          console.warn(`Warning: Could not add column ${col.name}:`, err.message);
        }
      }
    }

    // Insert message for each recipient
    const adminName = req.session.admin.username || 'Admin';
    const adminEmail = 'admin@uniclub.local';
    const adminId = req.session.admin.id || null; // Use admin ID if available

    for (const recipient of recipients) {
      // Use modern structure for students, keep old structure for backward compatibility
      if (recipient.type === 'student') {
        await pool.query(
          `INSERT INTO messages (
            sender_name, sender_email, subject, content, 
            recipient_type, recipient_id, recipient_name,
            sender_id, receiver_id, sender_type, receiver_type,
            \`read\`, created_at
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'admin', 'student', false, NOW())`,
          [
            adminName,
            adminEmail,
            subject,
            content,
            recipient.type,
            recipient.id,
            recipient.name,
            adminId, // sender_id (admin)
            recipient.id, // receiver_id (student)
          ]
        );
      } else {
        // For officers, use old structure (they might not have modern view yet)
        await pool.query(
          `INSERT INTO messages (sender_name, sender_email, subject, content, recipient_type, recipient_id, recipient_name, \`read\`, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, false, NOW())`,
          [
            adminName,
            adminEmail,
            subject,
            content,
            recipient.type,
            recipient.id,
            recipient.name
          ]
        );
      }
    }

    res.redirect("/admin/messages?success=message_sent&count=" + recipients.length);
  } catch (error) {
    console.error("Error sending message:", error);
    res.redirect("/admin/messages?error=server_error");
  }
});

/* ===============================
   🎉 EVENTS MANAGEMENT
================================= */

// View all events (exclude pending approval events)
router.get("/events", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  // Auto-update event statuses before loading events
  await updateEventStatuses();

  try {
    // Ensure status column exists
    const eventColumnsToAdd = [
      { name: 'status', def: "VARCHAR(50) DEFAULT 'pending_approval'" }
    ];
    
    for (const col of eventColumnsToAdd) {
      try {
        await pool.query(`ALTER TABLE events ADD COLUMN ${col.name} ${col.def}`);
      } catch (err) {
        const isDuplicateColumn = 
          err.code === 'ER_DUP_FIELDNAME' || 
          err.errno === 1060 || 
          err.message?.includes('Duplicate column name') || 
          err.sqlMessage?.includes('Duplicate column name');
        if (!isDuplicateColumn) {
          console.warn(`Warning: Could not add column ${col.name} to events table:`, err.message);
        }
      }
    }

    const events = await pool.query(`
      SELECT e.id, e.name, e.date, e.end_date, e.location, e.description, 
             c.name AS club_name,
             -- Use database status if it's a valid final status
             -- Otherwise, calculate based on current date (same logic as requirements page)
             CASE 
               WHEN e.status IN ('Ongoing', 'ongoing', 'Completed', 'completed', 'Cancelled', 'cancelled') THEN e.status
               WHEN e.date IS NULL THEN 'Scheduled'
               WHEN DATE(e.date) > CURDATE() THEN 'Scheduled'
               WHEN DATE(e.date) = CURDATE() OR (DATE(e.date) <= CURDATE() AND COALESCE(DATE(e.end_date), DATE(e.date)) >= CURDATE()) THEN 'Ongoing'
               WHEN COALESCE(DATE(e.end_date), DATE(e.date)) < CURDATE() THEN 'Completed'
               ELSE COALESCE(e.status, 'Scheduled')
             END AS status
      FROM events e
      LEFT JOIN clubs c ON e.club_id = c.id
      WHERE COALESCE(e.status, 'pending_approval') != 'pending_approval'
         AND COALESCE(e.status, 'pending_approval') != 'rejected'
      ORDER BY e.date DESC
    `).catch(() => ({ rows: [] }));
    
    res.render("admin/events", {
      title: "Manage Events | UniClub Admin",
      events: events.rows || [],
      csrfToken: res.locals.csrfToken || req.csrfToken?.() || '',
      currentPath: "/admin/events",
      messages: []
    });
  } catch (error) {
    console.error("Error loading events:", error);
    res.status(500).send("Server error");
  }
});

// Add Event Form
router.get("/events/add", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC");
    res.render("admin/addEvent", {
      title: "Add Event | UniClub Admin",
      error: null,
      clubs: clubs.rows || [],
      csrfToken: req.csrfToken ? req.csrfToken() : res.locals.csrfToken || ''
    });
  } catch (error) {
    console.error("Error loading clubs:", error);
    res.status(500).send("Server error");
  }
});

// Schedule Activity (alias for /add)
router.get("/events/create", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC");
    res.render("admin/addEvent", {
      title: "Schedule Activity | UniClub Admin",
      error: null,
      clubs: clubs.rows || [],
      csrfToken: req.csrfToken ? req.csrfToken() : res.locals.csrfToken || ''
    });
  } catch (error) {
    console.error("Error loading clubs:", error);
    res.status(500).send("Server error");
  }
});

// Handle Add Event
router.post("/events/add", writeLimiter, (req, res, next) => {
  uploadEventDocuments(req, res, (err) => {
    if (err) {
      // Handle multer errors
      let errorMessage = "Failed to upload documents";
      if (err.code === 'LIMIT_FILE_SIZE') {
        errorMessage = "File size too large. Maximum size is 10MB per file.";
      } else if (err.message && err.message.includes('Only document files')) {
        errorMessage = "Invalid file type. Only document files (PDF, DOC, DOCX, TXT, RTF, ODT) are allowed.";
      } else if (err.message) {
        errorMessage = err.message;
      }
      console.error("Multer error in /events/add:", err);
      
      // Fetch clubs for error page
      pool.query("SELECT id, name FROM clubs ORDER BY name ASC")
        .then(result => {
          return res.render("admin/addEvent", {
            title: "Add Event | UniClub Admin",
            error: errorMessage,
            clubs: result.rows || [],
            csrfToken: req.csrfToken?.() || ''
          });
        })
        .catch(() => {
          return res.render("admin/addEvent", {
            title: "Add Event | UniClub Admin",
            error: errorMessage,
            clubs: [],
            csrfToken: req.csrfToken?.() || ''
          });
        });
      return; // Don't call next() on error
    }
    next();
  });
}, async (req, res) => {
  try {
    // Initialize req.body if undefined (multer might cause this)
    if (!req.body) req.body = {};
    
    // Manual CSRF validation (after multer processes the form)
    // Use tokens.verify() since req.csrfToken is undefined for multipart requests
    const csrfToken = req.body._csrf;
    if (!csrfToken) {
      // Clean up uploaded files
      if (req.files) {
        Object.values(req.files).flat().forEach(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          fs.unlink(filePath, () => {});
        });
      }
      return res.status(403).render("admin/addEvent", {
        title: "Add Event | UniClub Admin",
        error: "CSRF token is required. Please refresh the page and try again.",
        clubs: [],
        csrfToken: ''
      });
    }
    
    const tokens = new Tokens();
    const secret = req.session?.csrfSecret;
    if (!secret) {
      // Clean up uploaded files
      if (req.files) {
        Object.values(req.files).flat().forEach(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          fs.unlink(filePath, () => {});
        });
      }
      return res.status(403).render("admin/addEvent", {
        title: "Add Event | UniClub Admin",
        error: "CSRF session not found. Please refresh the page and try again.",
        clubs: [],
        csrfToken: ''
      });
    }
    
    if (!tokens.verify(secret, csrfToken)) {
      // Clean up uploaded files
      if (req.files) {
        Object.values(req.files).flat().forEach(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          fs.unlink(filePath, () => {});
        });
      }
      return res.status(403).render("admin/addEvent", {
        title: "Add Event | UniClub Admin",
        error: "Invalid security token. Please refresh the page and try again.",
        clubs: [],
        csrfToken: ''
      });
    }

    const { name, club_id, date, end_date, location, description } = req.body;
    
    if (!name || !club_id || !date) {
      // Clean up uploaded files
      if (req.files) {
        Object.values(req.files).flat().forEach(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          fs.unlink(filePath, () => {});
        });
      }
      return res.render("admin/addEvent", {
        title: "Add Event | UniClub Admin",
        error: "Event name, club, and date are required.",
        clubs: [],
        csrfToken: req.csrfToken ? req.csrfToken() : ''
      });
    }

    // Validate end_date
    if (end_date && new Date(end_date) < new Date(date)) {
      // Clean up uploaded files
      if (req.files) {
        Object.values(req.files).flat().forEach(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          fs.unlink(filePath, () => {});
        });
      }
      return res.render("admin/addEvent", {
        title: "Add Event | UniClub Admin",
        error: "End date must be on or after start date.",
        clubs: [],
        csrfToken: req.csrfToken ? req.csrfToken() : ''
      });
    }

    // Handle file uploads - validate required files
    const files = req.files || {};
    
    // Validate all required files first, then delete only if validation fails
    let validationError = null;
    if (!files.activity_proposal || files.activity_proposal.length === 0) {
      validationError = "Activity proposal file is required.";
    } else if (!files.letter_of_intent || files.letter_of_intent.length === 0) {
      validationError = "Letter of intent file is required.";
    } else if (!files.budgetary_requirement || files.budgetary_requirement.length === 0) {
      validationError = "Budgetary requirement file is required.";
    }
    
    // Only delete files if validation failed (after all checks)
    if (validationError) {
      if (req.files) {
        // Delete files asynchronously but wait for all deletions to complete
        const deletePromises = Object.values(req.files).flat().map(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          return new Promise((resolve) => {
            fs.unlink(filePath, (err) => {
              if (err && err.code !== 'ENOENT') {
                console.error(`Error deleting uploaded event file ${file.filename}:`, err);
              }
              resolve();
            });
          });
        });
        // Wait for all file deletions to complete before sending response
        await Promise.all(deletePromises);
      }
      // Fetch clubs before returning error so dropdown is populated
      const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] }));
      return res.render("admin/addEvent", {
        title: "Add Event | UniClub Admin",
        error: validationError,
        clubs: clubs.rows || [],
        csrfToken: req.csrfToken ? req.csrfToken() : ''
      });
    }

    const activityProposalPath = `/uploads/events/${files.activity_proposal[0].filename}`;
    const letterOfIntentPath = `/uploads/events/${files.letter_of_intent[0].filename}`;
    const budgetaryRequirementPath = `/uploads/events/${files.budgetary_requirement[0].filename}`;

    // Ensure columns exist
    const columnsToAdd = [
      { name: 'end_date', def: 'DATE' },
      { name: 'activity_proposal', def: 'VARCHAR(500)' },
      { name: 'letter_of_intent', def: 'VARCHAR(500)' },
      { name: 'budgetary_requirement', def: 'VARCHAR(500)' },
      { name: 'status', def: "VARCHAR(50) DEFAULT 'approved'" },
      { name: 'posted_to_students', def: 'TINYINT(1) DEFAULT 1' }
    ];

    for (const col of columnsToAdd) {
      try {
        await pool.query(`ALTER TABLE events ADD COLUMN ${col.name} ${col.def}`);
      } catch (err) {
        // Ignore duplicate column errors
        if (err.code !== 'ER_DUP_FIELDNAME' && err.errno !== 1060) {
          console.warn(`Warning: Could not add column ${col.name}:`, err.message);
        }
      }
    }

    // Insert event
    await pool.query(
      `INSERT INTO events (name, club_id, date, end_date, location, description, activity_proposal, letter_of_intent, budgetary_requirement, status, posted_to_students, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved', 1, NOW())`,
      [name, club_id, date, end_date || date, location || null, description || null, activityProposalPath, letterOfIntentPath, budgetaryRequirementPath]
    );
    
    res.redirect("/admin/events");
  } catch (error) {
    // Clean up uploaded files on error
    if (req.files) {
      Object.values(req.files).flat().forEach(file => {
        const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
        fs.unlink(filePath, () => {});
      });
    }
    console.error("Error adding event:", error);
    const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] }));
    res.render("admin/addEvent", {
      title: "Add Event | UniClub Admin",
      error: "Failed to add event. Please check your inputs.",
      clubs: clubs.rows || [],
      csrfToken: req.csrfToken ? req.csrfToken() : ''
    });
  }
});

// Handle Schedule Activity (alias for /add)
router.post("/events/create", writeLimiter, (req, res, next) => {
  uploadEventDocuments(req, res, (err) => {
    if (err) {
      // Handle multer errors
      let errorMessage = "Failed to upload documents";
      if (err.code === 'LIMIT_FILE_SIZE') {
        errorMessage = "File size too large. Maximum size is 10MB per file.";
      } else if (err.message && err.message.includes('Only document files')) {
        errorMessage = "Invalid file type. Only document files (PDF, DOC, DOCX, TXT, RTF, ODT) are allowed.";
      } else if (err.message) {
        errorMessage = err.message;
      }
      console.error("Multer error in /events/create:", err);
      
      // Fetch clubs for error page
      pool.query("SELECT id, name FROM clubs ORDER BY name ASC")
        .then(result => {
          return res.render("admin/addEvent", {
            title: "Schedule Activity | UniClub Admin",
            error: errorMessage,
            clubs: result.rows || [],
            csrfToken: req.csrfToken?.() || ''
          });
        })
        .catch(() => {
          return res.render("admin/addEvent", {
            title: "Schedule Activity | UniClub Admin",
            error: errorMessage,
            clubs: [],
            csrfToken: req.csrfToken?.() || ''
          });
        });
      return; // Don't call next() on error
    }
    next();
  });
}, async (req, res) => {
  try {
    // Initialize req.body if undefined
    if (!req.body) req.body = {};
    
    // Manual CSRF validation
    // Use tokens.verify() since req.csrfToken is undefined for multipart requests
    const csrfToken = req.body._csrf;
    if (!csrfToken) {
      if (req.files) {
        Object.values(req.files).flat().forEach(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          fs.unlink(filePath, () => {});
        });
      }
      return res.status(403).render("admin/addEvent", {
        title: "Schedule Activity | UniClub Admin",
        error: "CSRF token is required. Please refresh the page and try again.",
        clubs: [],
        csrfToken: ''
      });
    }
    
    const tokens = new Tokens();
    const secret = req.session?.csrfSecret;
    if (!secret) {
      if (req.files) {
        Object.values(req.files).flat().forEach(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          fs.unlink(filePath, () => {});
        });
      }
      return res.status(403).render("admin/addEvent", {
        title: "Schedule Activity | UniClub Admin",
        error: "CSRF session not found. Please refresh the page and try again.",
        clubs: [],
        csrfToken: ''
      });
    }
    
    if (!tokens.verify(secret, csrfToken)) {
      if (req.files) {
        Object.values(req.files).flat().forEach(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          fs.unlink(filePath, () => {});
        });
      }
      return res.status(403).render("admin/addEvent", {
        title: "Schedule Activity | UniClub Admin",
        error: "Invalid security token. Please refresh the page and try again.",
        clubs: [],
        csrfToken: ''
      });
    }

    const { name, club_id, date, end_date, location, description } = req.body;
    
    if (!name || !club_id || !date) {
      if (req.files) {
        Object.values(req.files).flat().forEach(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          fs.unlink(filePath, () => {});
        });
      }
      return res.render("admin/addEvent", {
        title: "Schedule Activity | UniClub Admin",
        error: "Event name, club, and date are required.",
        clubs: [],
        csrfToken: req.csrfToken ? req.csrfToken() : ''
      });
    }

    // Validate end_date
    if (end_date && new Date(end_date) < new Date(date)) {
      if (req.files) {
        Object.values(req.files).flat().forEach(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          fs.unlink(filePath, () => {});
        });
      }
      return res.render("admin/addEvent", {
        title: "Schedule Activity | UniClub Admin",
        error: "End date must be on or after start date.",
        clubs: [],
        csrfToken: req.csrfToken ? req.csrfToken() : ''
      });
    }

    // Handle file uploads - validate required files
    const files = req.files || {};
    
    // Validate all required files first, then delete only if validation fails
    let validationError = null;
    if (!files.activity_proposal || files.activity_proposal.length === 0) {
      validationError = "Activity proposal file is required.";
    } else if (!files.letter_of_intent || files.letter_of_intent.length === 0) {
      validationError = "Letter of intent file is required.";
    } else if (!files.budgetary_requirement || files.budgetary_requirement.length === 0) {
      validationError = "Budgetary requirement file is required.";
    }
    
    // Only delete files if validation failed (after all checks)
    if (validationError) {
      if (req.files) {
        // Delete files asynchronously but wait for all deletions to complete
        const deletePromises = Object.values(req.files).flat().map(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          return new Promise((resolve) => {
            fs.unlink(filePath, (err) => {
              if (err && err.code !== 'ENOENT') {
                console.error(`Error deleting uploaded event file ${file.filename}:`, err);
              }
              resolve();
            });
          });
        });
        // Wait for all file deletions to complete before sending response
        await Promise.all(deletePromises);
      }
      const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] }));
      return res.render("admin/addEvent", {
        title: "Schedule Activity | UniClub Admin",
        error: validationError,
        clubs: clubs.rows || [],
        csrfToken: req.csrfToken ? req.csrfToken() : ''
      });
    }

    const activityProposalPath = `/uploads/events/${files.activity_proposal[0].filename}`;
    const letterOfIntentPath = `/uploads/events/${files.letter_of_intent[0].filename}`;
    const budgetaryRequirementPath = `/uploads/events/${files.budgetary_requirement[0].filename}`;

    // Ensure columns exist
    const columnsToAdd = [
      { name: 'end_date', def: 'DATE' },
      { name: 'activity_proposal', def: 'VARCHAR(500)' },
      { name: 'letter_of_intent', def: 'VARCHAR(500)' },
      { name: 'budgetary_requirement', def: 'VARCHAR(500)' },
      { name: 'status', def: "VARCHAR(50) DEFAULT 'approved'" },
      { name: 'posted_to_students', def: 'TINYINT(1) DEFAULT 1' }
    ];

    for (const col of columnsToAdd) {
      try {
        await pool.query(`ALTER TABLE events ADD COLUMN ${col.name} ${col.def}`);
      } catch (err) {
        if (err.code !== 'ER_DUP_FIELDNAME' && err.errno !== 1060) {
          console.warn(`Warning: Could not add column ${col.name}:`, err.message);
        }
      }
    }

    // Insert event
    await pool.query(
      `INSERT INTO events (name, club_id, date, end_date, location, description, activity_proposal, letter_of_intent, budgetary_requirement, status, posted_to_students, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved', 1, NOW())`,
      [name, club_id, date, end_date || date, location || null, description || null, activityProposalPath, letterOfIntentPath, budgetaryRequirementPath]
    );
    
    res.redirect("/admin/requirements");
  } catch (error) {
    if (req.files) {
      Object.values(req.files).flat().forEach(file => {
        const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
        fs.unlink(filePath, () => {});
      });
    }
    console.error("Error scheduling activity:", error);
    const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] }));
    res.render("admin/addEvent", {
      title: "Schedule Activity | UniClub Admin",
      error: "Failed to schedule activity. Please check your inputs.",
      clubs: clubs.rows || [],
      csrfToken: req.csrfToken ? req.csrfToken() : ''
    });
  }
});

// Edit Event Form
router.get("/events/edit/:id", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  // Auto-update event statuses before loading event for editing
  await updateEventStatuses();

  try {
    const [event, clubs] = await Promise.all([
      pool.query(`
        SELECT *, 
               COALESCE(end_date, date) as end_date,
               -- Use database status if it's a valid final status, otherwise calculate based on dates
               CASE 
                 WHEN status IN ('Ongoing', 'ongoing', 'Completed', 'completed', 'Cancelled', 'cancelled') THEN status
                 WHEN date IS NULL THEN 'Scheduled'
                 WHEN DATE(date) > CURDATE() THEN 'Scheduled'
                 WHEN DATE(date) = CURDATE() OR (DATE(date) <= CURDATE() AND COALESCE(DATE(end_date), DATE(date)) >= CURDATE()) THEN 'Ongoing'
                 WHEN COALESCE(DATE(end_date), DATE(date)) < CURDATE() THEN 'Completed'
                 ELSE COALESCE(status, 'Scheduled')
               END AS status
        FROM events 
        WHERE id = ?
      `, [req.params.id]),
      pool.query("SELECT id, name FROM clubs ORDER BY name ASC"),
    ]);

    if (event.rows.length === 0) return res.redirect("/admin/events");

    // Normalize status to ensure it's capitalized properly
    const eventData = event.rows[0];
    if (eventData.status) {
      eventData.status = eventData.status.charAt(0).toUpperCase() + eventData.status.slice(1).toLowerCase();
    } else {
      eventData.status = 'Scheduled';
    }

    res.render("admin/editEvent", {
      title: "Edit Event | UniClub Admin",
      event: eventData,
      clubs: clubs.rows,
      error: null,
      csrfToken: req.csrfToken ? req.csrfToken() : res.locals.csrfToken || '',
      currentPath: "/admin/events",
      messages: []
    });
  } catch (error) {
    console.error("Error loading event for edit:", error);
    res.status(500).send("Server error");
  }
});

// Handle Edit Event
router.post("/events/edit/:id", writeLimiter, (req, res, next) => {
  uploadEventDocuments(req, res, async (err) => {
    if (err) {
      // Handle multer errors
      let errorMessage = "Failed to upload documents";
      if (err.code === 'LIMIT_FILE_SIZE') {
        errorMessage = "File size too large. Maximum size is 10MB per file.";
      } else if (err.message && err.message.includes('Only document files')) {
        errorMessage = "Invalid file type. Only document files (PDF, DOC, DOCX, TXT, RTF, ODT) are allowed.";
      } else if (err.message) {
        errorMessage = err.message;
      }
      console.error("Multer error in /events/edit:", err);
      
      // Fetch event and clubs for error page
      const eventId = parseInt(req.params.id);
      try {
        const [eventResult, clubsResult] = await Promise.all([
          pool.query("SELECT * FROM events WHERE id = ?", [eventId]).catch(() => ({ rows: [] })),
          pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] }))
        ]);
        
        return res.render("admin/editEvent", {
          title: "Edit Event | UniClub Admin",
          error: errorMessage,
          event: eventResult.rows[0] || {},
          clubs: clubsResult.rows || [],
          csrfToken: req.csrfToken?.() || ''
        });
      } catch (fetchError) {
        console.error("Error fetching event/clubs for error page:", fetchError);
        return res.render("admin/editEvent", {
          title: "Edit Event | UniClub Admin",
          error: errorMessage,
          event: {},
          clubs: [],
          csrfToken: req.csrfToken?.() || ''
        });
      }
    }
    next();
  });
}, async (req, res) => {
  try {
    // Initialize req.body if undefined
    if (!req.body) req.body = {};
    
    // Manual CSRF validation
    // Use tokens.verify() since req.csrfToken is undefined for multipart requests
    const csrfToken = req.body._csrf;
    if (!csrfToken) {
      if (req.files) {
        Object.values(req.files).flat().forEach(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          fs.unlink(filePath, () => {});
        });
      }
      return res.status(403).render("admin/editEvent", {
        title: "Edit Event | UniClub Admin",
        error: "CSRF token is required. Please refresh the page and try again.",
        event: {},
        clubs: [],
        csrfToken: ''
      });
    }
    
    const tokens = new Tokens();
    const secret = req.session?.csrfSecret;
    if (!secret) {
      if (req.files) {
        Object.values(req.files).flat().forEach(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          fs.unlink(filePath, () => {});
        });
      }
      return res.status(403).render("admin/editEvent", {
        title: "Edit Event | UniClub Admin",
        error: "CSRF session not found. Please refresh the page and try again.",
        event: {},
        clubs: [],
        csrfToken: ''
      });
    }
    
    if (!tokens.verify(secret, csrfToken)) {
      if (req.files) {
        Object.values(req.files).flat().forEach(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          fs.unlink(filePath, () => {});
        });
      }
      return res.status(403).render("admin/editEvent", {
        title: "Edit Event | UniClub Admin",
        error: "Invalid security token. Please refresh the page and try again.",
        event: {},
        clubs: [],
        csrfToken: ''
      });
    }

    const { name, club_id, date, end_date, location, description, status } = req.body;
    const eventId = parseInt(req.params.id);
    
    if (!eventId || isNaN(eventId)) {
      if (req.files) {
        Object.values(req.files).flat().forEach(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          fs.unlink(filePath, () => {});
        });
      }
      return res.redirect("/admin/events");
    }

    // Validate name is provided
    if (!name || !name.trim()) {
      if (req.files) {
        Object.values(req.files).flat().forEach(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          fs.unlink(filePath, () => {});
        });
      }
      const [event, clubs] = await Promise.all([
        pool.query("SELECT * FROM events WHERE id = ?", [eventId]),
        pool.query("SELECT id, name FROM clubs ORDER BY name ASC"),
      ]);
      return res.render("admin/editEvent", {
        title: "Edit Event | UniClub Admin",
        event: event.rows[0] || {},
        clubs: clubs.rows || [],
        error: "Event name is required.",
        csrfToken: req.csrfToken ? req.csrfToken() : ''
      });
    }

    // Validate end_date
    if (end_date && date && new Date(end_date) < new Date(date)) {
      if (req.files) {
        Object.values(req.files).flat().forEach(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          fs.unlink(filePath, () => {});
        });
      }
      const [event, clubs] = await Promise.all([
        pool.query("SELECT * FROM events WHERE id = ?", [eventId]),
        pool.query("SELECT id, name FROM clubs ORDER BY name ASC"),
      ]);
      return res.render("admin/editEvent", {
        title: "Edit Event | UniClub Admin",
        event: event.rows[0] || {},
        clubs: clubs.rows || [],
        error: "End date must be on or after start date.",
        csrfToken: req.csrfToken ? req.csrfToken() : ''
      });
    }

    // Get existing event data
    const { rows: eventRows } = await pool.query(
      `SELECT id, activity_proposal, letter_of_intent, budgetary_requirement FROM events WHERE id = ?`,
      [eventId]
    ).catch(() => ({ rows: [] }));

    if (eventRows.length === 0) {
      if (req.files) {
        Object.values(req.files).flat().forEach(file => {
          const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
          fs.unlink(filePath, () => {});
        });
      }
      return res.redirect("/admin/events");
    }

    const existingEvent = eventRows[0];
    const files = req.files || {};

    // Prepare file paths - keep existing if new ones aren't uploaded
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

    // Ensure columns exist
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
        if (err.code !== 'ER_DUP_FIELDNAME' && err.errno !== 1060) {
          console.warn(`Warning: Could not add column ${col.name}:`, err.message);
        }
      }
    }

    // Update event
    await pool.query(
      `UPDATE events 
       SET name = ?, club_id = ?, date = ?, end_date = ?, location = ?, description = ?,
           activity_proposal = ?, letter_of_intent = ?, budgetary_requirement = ?,
           status = ?
       WHERE id = ?`,
      [
        name, 
        club_id, 
        date, 
        end_date || date, 
        location || null, 
        description || null,
        activityProposalPath,
        letterOfIntentPath,
        budgetaryRequirementPath,
        status || 'Scheduled',
        eventId
      ]
    );
    
    res.redirect("/admin/events");
  } catch (error) {
    // Clean up uploaded files on error
    if (req.files) {
      Object.values(req.files).flat().forEach(file => {
        const filePath = path.join(__dirname, '../public/uploads/events', file.filename);
        fs.unlink(filePath, () => {});
      });
    }
    console.error("Error updating event:", error);
    const [event, clubs] = await Promise.all([
      pool.query("SELECT *, COALESCE(end_date, date) as end_date FROM events WHERE id = ?", [req.params.id]).catch(() => ({ rows: [] })),
      pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] }))
    ]);
    res.render("admin/editEvent", {
      title: "Edit Event | UniClub Admin",
      event: event.rows[0] || {},
      clubs: clubs.rows || [],
      error: "Failed to update event. Please check your inputs.",
      csrfToken: req.csrfToken ? req.csrfToken() : ''
    });
  }
});

// Delete Event
router.post("/events/delete/:id", writeLimiter, async (req, res) => {
  try {
    await pool.query("DELETE FROM events WHERE id = ?", [req.params.id]);
    res.redirect("/admin/events");
  } catch (error) {
    console.error("Error deleting event:", error);
    res.status(500).send("Server error");
  }
});

/* ===============================
   📄 REPORTS
================================= */

// View Reports Page
router.get("/reports", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const { type = "students", startDate, endDate, club_id, status } = req.query;

    let reportData = {};
    let reportTitle = "Reports";

    // Get available clubs for filtering
    const clubsResult = await pool.query("SELECT id, name FROM clubs ORDER BY name").catch(() => ({ rows: [] }));

    // Students Report
    if (type === "students") {
      // Build students query and include clubs the student has joined (approved memberships)
      let query = `
        SELECT 
          s.*,
          (
            SELECT GROUP_CONCAT(c.name SEPARATOR ', ')
            FROM membership_applications ma
            JOIN clubs c ON c.id = ma.club_id
            WHERE ma.student_id = s.id
              AND (ma.status = 'approved' OR ma.status = 'Approved')
          ) AS clubs_joined
        FROM students s
        WHERE 1=1
      `;
      const params = [];

      if (startDate) {
        query += " AND s.created_at >= ?";
        params.push(startDate);
      }
      if (endDate) {
        query += " AND s.created_at <= ?";
        params.push(endDate + " 23:59:59");
      }

      query += " ORDER BY s.created_at DESC";
      const result = await pool.query(query, params);
      reportData = result.rows;
      reportTitle = "Students Report";
    }

    // Clubs Report
    if (type === "clubs") {
      let query = `
        SELECT c.*, 
               COUNT(DISTINCT o.id) AS officer_count,
               COUNT(DISTINCT e.id) AS event_count
        FROM clubs c
        LEFT JOIN officers o ON o.club_id = c.id
        LEFT JOIN events e ON e.club_id = c.id
        WHERE 1=1
      `;
      const params = [];

      if (club_id) {
        query += ` AND c.id = ?`;
        params.push(club_id);
      }
      if (startDate) {
        query += ` AND c.created_at >= ?`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND c.created_at <= ?`;
        params.push(endDate + " 23:59:59");
      }

      query += " GROUP BY c.id ORDER BY c.name ASC";
      const result = await pool.query(query, params);
      reportData = result.rows;
      reportTitle = "Clubs Report";
    }

    // Events Report
    if (type === "events") {
      let query = `
        SELECT e.*, c.name AS club_name
        FROM events e
        LEFT JOIN clubs c ON c.id = e.club_id
        WHERE 1=1
      `;
      const params = [];

      if (club_id) {
        query += ` AND e.club_id = ?`;
        params.push(club_id);
      }
      if (status) {
        // Events table doesn't have status column, use date-based logic
        if (status === 'Upcoming') {
          query += ` AND (e.date >= CURDATE() OR e.date IS NULL)`;
        } else if (status === 'Past') {
          query += ` AND e.date < CURDATE() AND e.date IS NOT NULL`;
        } else if (status === 'Scheduled') {
          query += ` AND e.date IS NULL`;
        }
      }
      if (startDate) {
        query += ` AND COALESCE(e.date, e.created_at) >= ?`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND COALESCE(e.date, e.created_at) <= ?`;
        params.push(endDate + " 23:59:59");
      }

      query += " ORDER BY COALESCE(e.date, e.created_at) DESC";
      const result = await pool.query(query, params);
      reportData = result.rows;
      reportTitle = "Events Report";
    }

    // Officers Report
    if (type === "officers") {
      let query = `
        SELECT o.*, c.name AS club_name
        FROM officers o
        LEFT JOIN clubs c ON c.id = o.club_id
        WHERE 1=1
      `;
      const params = [];

      if (club_id) {
        query += ` AND o.club_id = ?`;
        params.push(club_id);
      }
      if (startDate) {
        query += ` AND o.created_at >= ?`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND o.created_at <= ?`;
        params.push(endDate + " 23:59:59");
      }

      query += " ORDER BY o.last_name ASC, o.first_name ASC";
      const result = await pool.query(query, params);
      reportData = result.rows;
      reportTitle = "Officers Report";
    }

    // Requirements Report
    if (type === "requirements") {
      let query = `
        SELECT r.*, c.name AS club_name
        FROM requirements r
        LEFT JOIN clubs c ON c.id = r.club_id
        WHERE 1=1
      `;
      const params = [];

      if (club_id) {
        query += ` AND r.club_id = ?`;
        params.push(club_id);
      }
      if (status) {
        query += ` AND r.status = ?`;
        params.push(status);
      }
      if (startDate) {
        query += ` AND r.created_at >= ?`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND r.created_at <= ?`;
        params.push(endDate + " 23:59:59");
      }

      query += " ORDER BY r.due_date DESC NULLS LAST, r.created_at DESC";
      const result = await pool.query(query, params);
      reportData = result.rows;
      reportTitle = "Requirements Report";
    }

    // Activities Report
    if (type === "activities") {
      let query = "SELECT * FROM activities WHERE 1=1";
      const params = [];

      if (status) {
        query += ` AND status = ?`;
        params.push(status);
      }
      if (startDate) {
        query += ` AND COALESCE(date, created_at) >= ?`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND COALESCE(date, created_at) <= ?`;
        params.push(endDate + " 23:59:59");
      }

      query += " ORDER BY COALESCE(date, created_at) DESC";
      const result = await pool.query(query, params);
      reportData = result.rows;
      reportTitle = "Activities Report";
    }

    // Messages Report
    if (type === "messages") {
      let query = 'SELECT * FROM messages WHERE 1=1';
      const params = [];

      if (startDate) {
        query += ` AND created_at >= ?`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND created_at <= ?`;
        params.push(endDate + " 23:59:59");
      }

      query += " ORDER BY created_at DESC";
      const result = await pool.query(query, params);
      reportData = result.rows;
      reportTitle = "Messages Report";
    }

    res.render("admin/reports", {
      title: "Reports | UniClub",
      admin: req.session.admin,
      currentPath: "/admin/reports",
      reportType: type || "overview",
      reportData: Array.isArray(reportData) ? reportData : reportData,
      reportTitle,
      clubs: clubsResult.rows || [],
      filters: {
        startDate: startDate || "",
        endDate: endDate || "",
        club_id: club_id || "",
        status: status || "",
      },
      messages: [],
    });
  } catch (error) {
    console.error("Error loading reports:", error);
    res.status(500).render("errors/500", { title: "Server Error", error });
  }
});

// Export Report as CSV
router.get("/reports/export", async (req, res) => {
  if (!req.session?.admin) return res.status(401).send("Unauthorized");

  try {
    const { type, startDate, endDate, club_id, status } = req.query;

    let reportData = [];
    let filename = "report.csv";

    // Students Export
    if (type === "students") {
      let query = "SELECT * FROM students WHERE 1=1";
      const params = [];

      if (startDate) {
        query += ` AND created_at >= ?`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND created_at <= ?`;
        params.push(endDate + " 23:59:59");
      }

      query += " ORDER BY created_at DESC";
      const result = await pool.query(query, params);
      reportData = result.rows;
      filename = `students-report-${new Date().toISOString().split("T")[0]}.csv`;
    }

    // Clubs Export
    if (type === "clubs") {
      let query = `
        SELECT c.*, 
               COUNT(DISTINCT o.id) AS officer_count,
               COUNT(DISTINCT e.id) AS event_count
        FROM clubs c
        LEFT JOIN officers o ON o.club_id = c.id
        LEFT JOIN events e ON e.club_id = c.id
        WHERE 1=1
      `;
      const params = [];

      if (club_id) {
        query += ` AND c.id = ?`;
        params.push(club_id);
      }
      if (startDate) {
        query += ` AND c.created_at >= ?`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND c.created_at <= ?`;
        params.push(endDate + " 23:59:59");
      }

      query += " GROUP BY c.id ORDER BY c.name ASC";
      const result = await pool.query(query, params);
      reportData = result.rows;
      filename = `clubs-report-${new Date().toISOString().split("T")[0]}.csv`;
    }

    // Events Export
    if (type === "events") {
      let query = `
        SELECT e.*, c.name AS club_name
        FROM events e
        LEFT JOIN clubs c ON c.id = e.club_id
        WHERE 1=1
      `;
      const params = [];

      if (club_id) {
        query += ` AND e.club_id = ?`;
        params.push(club_id);
      }
      if (status) {
        // Events table doesn't have status column, use date-based logic
        if (status === 'Upcoming') {
          query += ` AND (e.date >= CURDATE() OR e.date IS NULL)`;
        } else if (status === 'Past') {
          query += ` AND e.date < CURDATE() AND e.date IS NOT NULL`;
        } else if (status === 'Scheduled') {
          query += ` AND e.date IS NULL`;
        }
      }
      if (startDate) {
        query += ` AND COALESCE(e.date, e.created_at) >= ?`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND COALESCE(e.date, e.created_at) <= ?`;
        params.push(endDate + " 23:59:59");
      }

      query += " ORDER BY COALESCE(e.date, e.created_at) DESC";
      const result = await pool.query(query, params);
      reportData = result.rows;
      filename = `events-report-${new Date().toISOString().split("T")[0]}.csv`;
    }

    // Officers Export
    if (type === "officers") {
      let query = `
        SELECT o.*, c.name AS club_name
        FROM officers o
        LEFT JOIN clubs c ON c.id = o.club_id
        WHERE 1=1
      `;
      const params = [];

      if (club_id) {
        query += ` AND o.club_id = ?`;
        params.push(club_id);
      }
      if (startDate) {
        query += ` AND o.created_at >= ?`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND o.created_at <= ?`;
        params.push(endDate + " 23:59:59");
      }

      query += " ORDER BY o.last_name ASC, o.first_name ASC";
      const result = await pool.query(query, params);
      reportData = result.rows;
      filename = `officers-report-${new Date().toISOString().split("T")[0]}.csv`;
    }

    // Requirements Export
    if (type === "requirements") {
      let query = `
        SELECT r.*, c.name AS club_name
        FROM requirements r
        LEFT JOIN clubs c ON c.id = r.club_id
        WHERE 1=1
      `;
      const params = [];

      if (club_id) {
        query += ` AND r.club_id = ?`;
        params.push(club_id);
      }
      if (status) {
        query += ` AND r.status = ?`;
        params.push(status);
      }
      if (startDate) {
        query += ` AND r.created_at >= ?`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND r.created_at <= ?`;
        params.push(endDate + " 23:59:59");
      }

      query += " ORDER BY r.due_date DESC NULLS LAST, r.created_at DESC";
      const result = await pool.query(query, params);
      reportData = result.rows;
      filename = `requirements-report-${new Date().toISOString().split("T")[0]}.csv`;
    }

    // Convert to CSV
    if (reportData.length === 0) {
      return res.status(404).send("No data to export");
    }

    const headers = Object.keys(reportData[0]);
    const csvHeaders = headers.join(",");
    const csvRows = reportData.map((row) => {
      return headers
        .map((header) => {
          const value = row[header];
          if (value === null || value === undefined) return "";
          const stringValue = String(value);
          // Escape quotes and wrap in quotes if contains comma, newline, or quote
          if (stringValue.includes(",") || stringValue.includes("\n") || stringValue.includes('"')) {
            return `"${stringValue.replace(/"/g, '""')}"`;
          }
          return stringValue;
        })
        .join(",");
    });

    const csv = [csvHeaders, ...csvRows].join("\n");

    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.send(csv);
  } catch (error) {
    console.error("Error exporting report:", error);
    res.status(500).send("Error exporting report");
  }
});

/* ===============================
   🚪 LOGOUT
================================= */

router.post("/logout", (req, res) => {
  // Properly destroy session server-side
  const sessionId = req.sessionID;
  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        console.error("Error destroying admin session:", err);
      } else {
        console.log(`[LOGOUT] Admin session ${sessionId} destroyed`);
      }
      // Clear cookie
      res.clearCookie('sessionId');
      res.redirect("/admin/login");
    });
  } else {
    res.clearCookie('sessionId');
    res.redirect("/admin/login");
  }
});

// Event Approvals - View Pending Events
router.get("/event-approvals", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");
  
  try {
    const { rows: pendingEvents } = await pool.query(
      `SELECT e.id, e.name, e.date, e.location, e.description, e.created_at, e.admin_requirements,
              e.activity_proposal, e.letter_of_intent, e.budgetary_requirement,
              e.club_id, c.name as club_name,
              o.id as created_by_id, CONCAT(o.first_name, ' ', o.last_name) as created_by_name, o.role as created_by_role
       FROM events e
       LEFT JOIN clubs c ON e.club_id = c.id
       LEFT JOIN officers o ON e.created_by = o.id
       WHERE COALESCE(e.status, 'pending_approval') = 'pending_approval'
       ORDER BY e.created_at ASC`
    ).catch(() => ({ rows: [] }));
    
    res.render("admin/eventApprovals", {
      title: "Event Approvals | UniClub Admin",
      currentPath: "/admin/event-approvals",
      pendingEvents: pendingEvents || [],
      messages: []
    });
  } catch (err) {
    console.error("Error fetching pending events:", err);
    res.status(500).render("errors/500", { title: "Server Error", error: err });
  }
});

// Approve Event with Requirements
router.post("/event-approvals/:id/approve", writeLimiter, async (req, res) => {
  if (!req.session?.admin) return res.status(403).json({ error: "Unauthorized" });
  
  try {
    const eventId = parseInt(req.params.id);
    const { requirements } = req.body;
    const adminId = req.session.admin.id;
    
    if (!eventId || isNaN(eventId)) {
      return res.status(400).json({ error: "Invalid event ID" });
    }
    
    // Update event status to approved_by_admin (not posted yet - needs president approval)
    await pool.query(
      `UPDATE events 
       SET status = 'approved_by_admin', 
           admin_requirements = ?,
           approved_by = ?,
           approved_at = NOW()
       WHERE id = ?`,
      [requirements?.trim() || null, adminId, eventId]
    );
    
    // Get event details for notification
    const { rows: eventRows } = await pool.query(
      `SELECT e.id, e.name, e.club_id, e.created_by,
              CONCAT(o.first_name, ' ', o.last_name) as officer_name, o.email as officer_email
       FROM events e
       LEFT JOIN clubs c ON e.club_id = c.id
       LEFT JOIN officers o ON e.created_by = o.id
       WHERE e.id = ?`,
      [eventId]
    );
    
    if (eventRows.length > 0) {
      const event = eventRows[0];
      
      // Find president of the club
      const { rows: presidentRows } = await pool.query(
        `SELECT id, CONCAT(first_name, ' ', last_name) as president_name, email
         FROM officers
         WHERE club_id = ? AND LOWER(role) LIKE '%president%'
         LIMIT 1`,
        [event.club_id]
      ).catch(() => ({ rows: [] }));
      
      // Notify president (if found) and officer
      if (presidentRows.length > 0) {
        const president = presidentRows[0];
        try {
          await pool.query(
            `INSERT INTO messages (sender_name, sender_email, subject, content, recipient_type, recipient_id, recipient_name, \`read\`)
             VALUES (?, ?, ?, ?, 'officer', ?, ?, 0)`,
            [
              'Admin',
              'admin@uniclub.edu',
              `Event Approved - Action Required: ${event.name}`,
              `An event "${event.name}" has been approved by the administrator and requires your review.\n\nPlease review and post the event from the Calendar page if you approve it.${requirements ? '\n\nAdmin Requirements:\n' + requirements : ''}`,
              president.id,
              president.president_name || 'President'
            ]
          );
        } catch (msgErr) {
          console.error("Error creating notification for president:", msgErr);
        }
      }
      
      // Also notify the officer who created it
      try {
        await pool.query(
          `INSERT INTO messages (sender_name, sender_email, subject, content, recipient_type, recipient_id, recipient_name, \`read\`)
           VALUES (?, ?, ?, ?, 'officer', ?, ?, 0)`,
          [
            'Admin',
            'admin@uniclub.edu',
            `Event Approved: ${event.name}`,
            `Your event "${event.name}" has been approved by the administrator.${requirements ? '\n\nRequirements:\n' + requirements : ''}\n\nThe president will review and post it to students.`,
            event.created_by,
            event.officer_name || 'Officer'
          ]
        );
      } catch (msgErr) {
        console.error("Error creating notification for officer:", msgErr);
      }
    }
    
    res.json({ success: true, message: "Event approved successfully" });
  } catch (err) {
    console.error("Error approving event:", err);
    res.status(500).json({ error: "Failed to approve event: " + err.message });
  }
});

// Reject Event
router.post("/event-approvals/:id/reject", writeLimiter, async (req, res) => {
  if (!req.session?.admin) return res.status(403).json({ error: "Unauthorized" });
  
  try {
    const eventId = parseInt(req.params.id);
    const { reason } = req.body;
    const adminId = req.session.admin.id;
    
    if (!eventId || isNaN(eventId)) {
      return res.status(400).json({ error: "Invalid event ID" });
    }
    
    // Update event status to rejected
    await pool.query(
      `UPDATE events 
       SET status = 'rejected', 
           admin_requirements = ?,
           approved_by = ?,
           approved_at = NOW()
       WHERE id = ?`,
      [reason?.trim() || 'Event rejected by administrator', adminId, eventId]
    );
    
    // Get event details for notification
    const { rows: eventRows } = await pool.query(
      `SELECT e.id, e.name, e.club_id, e.created_by,
              CONCAT(o.first_name, ' ', o.last_name) as officer_name
       FROM events e
       LEFT JOIN officers o ON e.created_by = o.id
       WHERE e.id = ?`,
      [eventId]
    );
    
    if (eventRows.length > 0) {
      const event = eventRows[0];
      
      // Create notification message for the officer
      try {
        await pool.query(
          `INSERT INTO messages (sender_name, sender_email, subject, content, recipient_type, recipient_id, recipient_name, \`read\`)
           VALUES (?, ?, ?, ?, 'officer', ?, ?, 0)`,
          [
            'Admin',
            'admin@uniclub.edu',
            `Event Rejected: ${event.name}`,
            `Your event "${event.name}" has been rejected by the administrator.${reason ? '\n\nReason: ' + reason : ''}`,
            event.created_by,
            event.officer_name || 'Officer'
          ]
        );
      } catch (msgErr) {
        console.error("Error creating notification:", msgErr);
      }
    }
    
    res.json({ success: true, message: "Event rejected successfully" });
  } catch (err) {
    console.error("Error rejecting event:", err);
    res.status(500).json({ error: "Failed to reject event: " + err.message });
  }
});

// Migration: Normalize all officer emails (trim and lowercase)
// This fixes existing officers created before email normalization was implemented
router.post("/migrate/officer-emails", writeLimiter, async (req, res) => {
  if (!req.session?.admin) {
    return res.status(403).json({ success: false, error: "Admin access required" });
  }

  try {
    // Get all officers with emails
    const { rows: officers } = await pool.query(
      "SELECT id, email FROM officers WHERE email IS NOT NULL AND email != ''"
    );

    let updated = 0;
    let errors = 0;

    for (const officer of officers) {
      if (!officer.email) continue;

      // Normalize email: trim and lowercase
      const normalizedEmail = officer.email.trim().toLowerCase();

      // Only update if email changed
      if (normalizedEmail !== officer.email) {
        try {
          // Check if normalized email already exists (duplicate check)
          const existingCheck = await pool.query(
            "SELECT id FROM officers WHERE LOWER(TRIM(email)) = ? AND id != ? LIMIT 1",
            [normalizedEmail, officer.id]
          );

          if (existingCheck.rows.length > 0) {
            console.warn(`[Email Migration] Skipping officer ${officer.id}: normalized email "${normalizedEmail}" already exists for another officer`);
            errors++;
            continue;
          }

          // Update email
          await pool.query(
            "UPDATE officers SET email = ? WHERE id = ?",
            [normalizedEmail, officer.id]
          );
          updated++;
          console.log(`[Email Migration] Updated officer ${officer.id}: "${officer.email}" -> "${normalizedEmail}"`);
        } catch (err) {
          console.error(`[Email Migration] Error updating officer ${officer.id}:`, err.message);
          errors++;
        }
      }
    }

    res.json({
      success: true,
      message: `Email migration completed. Updated: ${updated}, Errors: ${errors}, Total checked: ${officers.length}`
    });
  } catch (err) {
    console.error("Email migration error:", err);
    res.status(500).json({ success: false, error: "Migration failed: " + err.message });
  }
});

export default router;