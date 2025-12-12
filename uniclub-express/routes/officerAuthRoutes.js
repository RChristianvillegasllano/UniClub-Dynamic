// routes/officerAuthRoutes.js
import express from "express";
import bcrypt from "bcryptjs";
import { body, validationResult } from "express-validator";
import pool from "../config/db.js";
import { sendOTPEmail } from "../config/email.js";
import { generateOTP, storeOTP, verifyOTP } from "../config/otpStore.js";
import { loginLimiter, passwordResetLimiter, csrfProtection } from "../middleware/security.js";
import { 
  strictAuthLimiter,
  validatePasswordStrength,
  recordFailedAttempt,
  clearFailedAttempts,
  isAccountLocked,
  getLockoutTimeRemaining,
  logSecurityEvent
} from "../middleware/advancedSecurity.js";
import { getPermissionsForRole } from "../config/tierPermissions.js";
import crypto from "crypto";

const router = express.Router();

// Apply CSRF protection to all POST/PUT/DELETE routes in this router
router.use(csrfProtection);

/** Middleware guards */
export function requireOfficer(req, res, next) {
  if (!req.session?.officer) return res.redirect("/officer/login");
  next();
}
export function requireAdmin(req, res, next) {
  if (!req.session?.admin) return res.redirect("/admin/login");
  next();
}

router.get("/login", (req, res) => {
  if (req.session?.officer) return res.redirect("/officer");
  const passwordReset = req.query.passwordReset;
  res.render("officer/login", { error: null, passwordReset });
});

router.post("/login", 
  strictAuthLimiter,
  loginLimiter,
  body('email').trim().isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('password').notEmpty().withMessage('Password is required'),
  async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(401).render("officer/login", { 
      error: errors.array()[0].msg 
    });
  }

  const { email, password } = req.body;
  try {
    // Use normalized email from express-validator (already normalized by normalizeEmail())
    const normalizedEmail = email ? email.trim().toLowerCase() : '';
    
    // MySQL doesn't support IF NOT EXISTS in ALTER TABLE, so we'll try to add columns and ignore errors if they exist
    const columnsToAdd = [
      { name: 'username', def: 'TEXT' },
      { name: 'password_hash', def: 'TEXT' },
      { name: 'profile_picture', def: 'MEDIUMTEXT' },
      { name: 'permissions', def: "JSON DEFAULT ('{}')" },
      { name: 'email', def: 'TEXT' },
      { name: 'facebook', def: 'TEXT' },
      { name: 'bio', def: 'TEXT' }
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
    
    // columns added in Step 6 (SQL migrations)
    // First try exact match with normalized email
    let { rows } = await pool.query(
      `SELECT 
         id,
         first_name,
         last_name,
         CONCAT(first_name, ' ', last_name) AS name,
         role,
         username,
         password_hash,
         club_id,
         permissions,
         profile_picture,
         email,
         facebook,
         bio,
         department,
         program,
         COALESCE(status, 'Active') AS status
       FROM officers 
       WHERE LOWER(TRIM(email)) = ? 
       LIMIT 1`,
      [normalizedEmail]
    );
    
    // If no match, try case-insensitive search without trim (for existing records)
    if (rows.length === 0) {
      console.log(`[Officer Login] No exact match for normalized email: ${normalizedEmail}, trying case-insensitive search...`);
      const result = await pool.query(
        `SELECT 
           id,
           first_name,
           last_name,
           CONCAT(first_name, ' ', last_name) AS name,
           role,
           username,
           password_hash,
           club_id,
           permissions,
           profile_picture,
           email,
           facebook,
           bio,
           department,
           program,
           COALESCE(status, 'Active') AS status
         FROM officers 
         WHERE LOWER(email) = ? 
         LIMIT 1`,
        [normalizedEmail]
      );
      rows = result.rows;
      
      // If found with case-insensitive, update the email to normalized version
      if (rows.length > 0) {
        const foundOfficer = rows[0];
        console.log(`[Officer Login] Found officer with case-insensitive match. Current email: "${foundOfficer.email}", normalizing to: "${normalizedEmail}"`);
        try {
          await pool.query(
            "UPDATE officers SET email = ? WHERE id = ?",
            [normalizedEmail, foundOfficer.id]
          );
          console.log(`[Officer Login] Updated email for officer ${foundOfficer.id} to normalized format`);
        } catch (updateErr) {
          console.warn(`[Officer Login] Could not update email for officer ${foundOfficer.id}:`, updateErr.message);
        }
      }
    }
    
    let officer = rows[0];
    if (!officer) {
      // Debug: Check what emails exist in database (first 5 for debugging)
      const debugEmails = await pool.query(
        "SELECT id, email, LOWER(TRIM(email)) as normalized FROM officers WHERE email IS NOT NULL LIMIT 5"
      ).catch(() => ({ rows: [] }));
      
      // Also check if this specific email exists with any variation
      const specificCheck = await pool.query(
        "SELECT id, email, LOWER(TRIM(email)) as normalized FROM officers WHERE email LIKE ? OR LOWER(email) LIKE ? LIMIT 5",
        [`%${normalizedEmail.split('@')[0]}%`, `%${normalizedEmail.split('@')[0]}%`]
      ).catch(() => ({ rows: [] }));
      
      // Extract student ID from email format: firstinitial.lastname.6digits.tc@umindanao.edu.ph
      const emailParts = normalizedEmail.match(/^[a-z]\.([a-z]+)\.(\d{6})\.tc@umindanao\.edu\.ph$/);
      if (emailParts) {
        const studentIdFromEmail = emailParts[2];
        console.log(`[Officer Login] Extracted student ID from email: ${studentIdFromEmail}`);
        
        // Check if officer exists with this student ID
        const studentIdCheck = await pool.query(
          "SELECT id, first_name, last_name, email, studentid FROM officers WHERE studentid = ? LIMIT 1",
          [studentIdFromEmail]
        ).catch(() => ({ rows: [] }));
        
        if (studentIdCheck.rows.length > 0) {
          const officerByStudentId = studentIdCheck.rows[0];
          console.log(`[Officer Login] Found officer by student ID ${studentIdFromEmail}:`, {
            id: officerByStudentId.id,
            name: `${officerByStudentId.first_name} ${officerByStudentId.last_name}`,
            currentEmail: officerByStudentId.email,
            studentId: officerByStudentId.studentid
          });
          
          // If officer has no email or different email, update it
          if (!officerByStudentId.email || officerByStudentId.email.trim().toLowerCase() !== normalizedEmail) {
            try {
              await pool.query(
                "UPDATE officers SET email = ? WHERE id = ?",
                [normalizedEmail, officerByStudentId.id]
              );
              console.log(`[Officer Login] Updated email for officer ${officerByStudentId.id} from "${officerByStudentId.email || 'NULL'}" to "${normalizedEmail}"`);
            } catch (updateErr) {
              console.error(`[Officer Login] Could not update email for officer ${officerByStudentId.id}:`, updateErr.message);
            }
          }
          
          // Fetch the full officer record
          const fullOfficerResult = await pool.query(
            `SELECT 
               id,
               first_name,
               last_name,
               CONCAT(first_name, ' ', last_name) AS name,
               role,
               username,
               password_hash,
               club_id,
               permissions,
               profile_picture,
               email,
               facebook,
               bio,
               department,
               program,
               COALESCE(status, 'Active') AS status
             FROM officers 
             WHERE id = ? 
             LIMIT 1`,
            [officerByStudentId.id]
          );
          
          if (fullOfficerResult.rows.length > 0) {
            officer = fullOfficerResult.rows[0];
            console.log(`[Officer Login] Using officer found by student ID: ${officer.id}`);
          }
        } else {
          console.log(`[Officer Login] No officer found with student ID ${studentIdFromEmail} either`);
        }
      }
      
      if (!officer) {
        const clientIP = req.ip || req.connection.remoteAddress;
        recordFailedAttempt(normalizedEmail, clientIP);
        logSecurityEvent('FAILED_LOGIN', { email: normalizedEmail, reason: 'User not found', ip: clientIP }, req);
        console.log(`[Officer Login] No officer found with email: ${normalizedEmail}`);
        console.log(`[Officer Login] Sample emails in database:`, debugEmails.rows.map(r => ({ id: r.id, email: r.email, normalized: r.normalized })));
        if (specificCheck.rows.length > 0) {
          console.log(`[Officer Login] Found similar emails:`, specificCheck.rows.map(r => ({ id: r.id, email: r.email, normalized: r.normalized })));
        }
        return res.status(401).render("officer/login", { error: "Invalid credentials" });
      }
    }
    
    const clientIP = req.ip || req.connection.remoteAddress;
    
    // Check if account is locked
    if (isAccountLocked(normalizedEmail, clientIP)) {
      const remainingTime = getLockoutTimeRemaining(normalizedEmail, clientIP);
      logSecurityEvent('LOCKED_ACCOUNT_ACCESS_ATTEMPT', { email: normalizedEmail, ip: clientIP }, req);
      return res.status(401).render("officer/login", { 
        error: `Account temporarily locked due to multiple failed attempts. Please try again in ${Math.ceil(remainingTime / 60)} minutes.` 
      });
    }

    // Debug: Log officer found
    console.log(`[Officer Login] Officer found - ID: ${officer.id}, Email: ${officer.email}, Has password_hash: ${officer.password_hash ? 'Yes (' + officer.password_hash.length + ' chars)' : 'No'}`);

    // Check if officer account is pending approval
    // Only block if status is explicitly 'Pending' or 'Rejected', allow 'Active' or null/undefined
    const officerStatus = officer.status || 'Active';
    if (officerStatus === 'Pending') {
      return res.status(401).render("officer/login", { 
        error: "Your account is pending admin approval. Please wait for approval before logging in." 
      });
    }
    if (officerStatus === 'Rejected') {
      return res.status(401).render("officer/login", { 
        error: "Your account has been rejected. Please contact an administrator." 
      });
    }

    // Check if password exists (for accounts created before password was added)
    if (!officer.password_hash || officer.password_hash.trim().length === 0) {
      console.log(`[Officer Login] Officer ${officer.id} has no password_hash`);
      return res.status(401).render("officer/login", { 
        error: "Account not set up. Please contact support or have an administrator set your password." 
      });
    }

    const ok = await bcrypt.compare(password, officer.password_hash);
    if (!ok) {
      recordFailedAttempt(normalizedEmail, clientIP);
      logSecurityEvent('FAILED_LOGIN', { email: normalizedEmail, reason: 'Invalid password', ip: clientIP }, req);
      console.log(`[Officer Login] Password mismatch for officer ${officer.id} (email: ${officer.email})`);
      return res.status(401).render("officer/login", { error: "Invalid credentials" });
    }
    
    // Clear failed attempts on successful login
    clearFailedAttempts(normalizedEmail, clientIP);
    logSecurityEvent('SUCCESSFUL_LOGIN', { email: normalizedEmail, officerId: officer.id, ip: clientIP }, req);
    console.log(`[Officer Login] Successful login for officer ${officer.id} (email: ${officer.email})`);

    // minimal profile in session
    req.session.officer = {
      id: officer.id,
      name: officer.name,
      role: officer.role,
      club_id: officer.club_id,
      username: officer.username,
      profile_picture: officer.profile_picture,
      permissions: officer.permissions, // JSON (parsed later)
      email: officer.email,
      facebook: officer.facebook,
      bio: officer.bio,
      department: officer.department,
      program: officer.program,
    };
    res.redirect("/officer");
  } catch (err) {
    console.error("Officer login error:", err);
    res.status(500).render("officer/login", { error: "Server error" });
  }
});

router.post("/logout", (req, res) => {
  // Properly destroy session server-side
  const sessionId = req.sessionID;
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying officer session:", err);
    } else {
      console.log(`[LOGOUT] Officer session ${sessionId} destroyed`);
    }
    // Clear cookie
    res.clearCookie('sessionId');
    res.redirect("/officer/login");
  });
});

// Officer Sign Up
router.get("/signup", async (req, res) => {
  if (req.session?.officer) return res.redirect("/officer");
  const success = req.query.success;
  
  // Fetch clubs for the dropdown
  let clubs = [];
  try {
    console.log("[Officer Signup] Attempting to fetch clubs...");
    const result = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC");
    // The wrapper returns { rows, fields }, so we need to access result.rows
    clubs = result.rows || [];
    console.log(`[Officer Signup] Query result type:`, typeof result);
    console.log(`[Officer Signup] Query result keys:`, Object.keys(result));
    console.log(`[Officer Signup] Result.rows type:`, typeof result.rows);
    console.log(`[Officer Signup] Result.rows is array:`, Array.isArray(result.rows));
    console.log(`[Officer Signup] Fetched ${clubs.length} clubs from database`);
    
    if (clubs.length > 0) {
      console.log("[Officer Signup] Club names:", clubs.map(c => `${c.id}: ${c.name}`));
      console.log("[Officer Signup] First club sample:", JSON.stringify(clubs[0]));
    } else {
      console.warn("[Officer Signup] WARNING: No clubs found in database!");
      // Try to see if clubs table exists and has any data
      try {
        const countResult = await pool.query("SELECT COUNT(*) as count FROM clubs");
        const count = countResult.rows?.[0]?.count || countResult.rows?.[0]?.['COUNT(*)'] || 0;
        console.log("[Officer Signup] Total clubs in database (COUNT query):", count);
      } catch (countErr) {
        console.error("[Officer Signup] Error counting clubs:", countErr.message);
      }
    }
  } catch (err) {
    console.error("[Officer Signup] ERROR fetching clubs:", err);
    console.error("[Officer Signup] Error code:", err.code);
    console.error("[Officer Signup] Error message:", err.message);
    if (err.sql) console.error("[Officer Signup] SQL:", err.sql);
  }
  
  console.log("[Officer Signup] Final clubs array to render:", clubs);
  console.log("[Officer Signup] Clubs array length:", clubs.length);
  console.log("[Officer Signup] Clubs is array:", Array.isArray(clubs));
  
  res.render("officer/signup", { error: null, success, clubs });
});

router.post("/signup", async (req, res) => {
  const { first_name, last_name, studentid, department, program, role, club_id, email, password, confirmPassword, terms } = req.body;

  // Helper function to fetch clubs for error rendering
  const fetchClubs = async () => {
    try {
      const { rows } = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC");
      return rows || [];
    } catch (err) {
      console.error("Error fetching clubs:", err);
      return [];
    }
  };

  try {
    // Validate first name
    if (!first_name || !first_name.trim()) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "First name is required",
        clubs,
      });
    }
    
    const firstNameTrimmed = first_name.trim();
    if (firstNameTrimmed.length < 2) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "First name must be at least 2 characters",
        clubs,
      });
    }
    
    if (firstNameTrimmed.length > 50) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "First name must be less than 50 characters",
        clubs,
      });
    }
    
    // Validate first name format (letters, spaces, hyphens, apostrophes only)
    if (!/^[a-zA-Z\s'-]+$/.test(firstNameTrimmed)) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "First name can only contain letters, spaces, hyphens, and apostrophes",
        clubs,
      });
    }

    // Validate last name
    if (!last_name || !last_name.trim()) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Last name is required",
        clubs,
      });
    }
    
    const lastNameTrimmed = last_name.trim();
    if (lastNameTrimmed.length < 2) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Last name must be at least 2 characters",
        clubs,
      });
    }
    
    if (lastNameTrimmed.length > 50) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Last name must be less than 50 characters",
        clubs,
      });
    }
    
    // Validate last name format
    if (!/^[a-zA-Z\s'-]+$/.test(lastNameTrimmed)) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Last name can only contain letters, spaces, hyphens, and apostrophes",
        clubs,
      });
    }

    // Validate student ID: exactly 6 digits
    if (!studentid || !/^\d{6}$/.test(studentid)) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Student ID is required and must be exactly 6 digits",
        clubs,
      });
    }

    // Validate email - UMindanao format required (same as admin)
    if (!email || !email.trim()) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Email is required",
        clubs,
      });
    }
    
    const emailTrimmed = email.trim().toLowerCase();
    
    // UMindanao email format: firstinitial.lastname.6digits.tc@umindanao.edu.ph
    // Example: j.delacruz.111222.tc@umindanao.edu.ph
    const umindanaoPattern = /^[a-z]\.[a-z]+\.\d{6}\.tc@umindanao\.edu\.ph$/i;
    if (!umindanaoPattern.test(emailTrimmed)) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Email must follow format: firstinitial.lastname.6digitid.tc@umindanao.edu.ph (e.g., j.delacruz.111222.tc@umindanao.edu.ph)",
        clubs,
      });
    }

    // Validate password
    if (!password) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Password is required",
        clubs,
      });
    }
    
    if (password.length < 6) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Password must be at least 6 characters",
        clubs,
      });
    }
    
    if (password.length > 100) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Password must be less than 100 characters",
        clubs,
      });
    }
    
    // Password strength validation (at least one letter and one number)
    if (!/(?=.*[a-zA-Z])(?=.*\d)/.test(password)) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Password must contain at least one letter and one number",
        clubs,
      });
    }

    // Validate password match
    if (password !== confirmPassword) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Passwords do not match",
        clubs,
      });
    }

    // Validate department
    if (!department || department.trim() === '') {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Department is required",
        clubs,
      });
    }
    
    const departmentTrimmed = department.trim();
    if (departmentTrimmed.length > 100) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Department name is too long",
        clubs,
      });
    }

    // Validate program
    if (!program || program.trim() === '') {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Program is required",
        clubs,
      });
    }
    
    const programTrimmed = program.trim();
    if (programTrimmed.length > 100) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Program name is too long",
        clubs,
      });
    }

    // Validate club/organization
    if (!club_id || club_id.trim() === '') {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Club/Organization is required",
        clubs,
      });
    }
    
    // Validate club exists in database
    const clubIdNum = parseInt(club_id, 10);
    if (isNaN(clubIdNum)) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Invalid club selection",
        clubs,
      });
    }
    
    const clubCheck = await pool.query("SELECT id FROM clubs WHERE id = ? LIMIT 1", [clubIdNum]);
    if (clubCheck.rows.length === 0) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Selected club does not exist",
        clubs,
      });
    }

    // Validate role/position
    if (!role || role.trim() === '') {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Position/Role is required",
        clubs,
      });
    }
    
    const roleTrimmed = role.trim();
    if (roleTrimmed.length < 2) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Position/Role must be at least 2 characters",
        clubs,
      });
    }
    
    if (roleTrimmed.length > 100) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Position/Role must be less than 100 characters",
        clubs,
      });
    }
    
    // Validate role format (letters, numbers, spaces, hyphens, apostrophes, and common punctuation)
    if (!/^[a-zA-Z0-9\s'-.,()]+$/.test(roleTrimmed)) {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "Position/Role contains invalid characters",
        clubs,
      });
    }
    
    // Validate terms and conditions
    if (!terms || terms !== 'on') {
      const clubs = await fetchClubs();
      return res.render("officer/signup", {
        error: "You must accept the terms and conditions to continue",
        clubs,
      });
    }

    // Check if email already exists (normalize email for comparison)
    const existingUser = await pool.query(
      "SELECT id FROM officers WHERE LOWER(TRIM(email)) = ? LIMIT 1",
      [emailTrimmed]
    );
    if (existingUser.rows.length > 0) {
      return res.render("officer/signup", {
        error: "An account with this email already exists. Please use a different email or contact support.",
      });
    }

    // Check if student ID already exists
    const existingStudentId = await pool.query(
      "SELECT id FROM officers WHERE studentid = ? LIMIT 1",
      [studentid]
    );
    if (existingStudentId.rows.length > 0) {
      return res.render("officer/signup", {
        error: "An account with this Student ID already exists.",
      });
    }

    // Check if first name + last name combination already exists
    // Note: This only rejects when BOTH first name AND last name match
    // Examples: "John Doe" + "John Smith" = ACCEPTED (same first, different last)
    //           "John Doe" + "Jane Doe" = ACCEPTED (same last, different first)
    //           "John Doe" + "John Doe" = REJECTED (both match)
    const nameCheck = await pool.query(
      "SELECT id, studentid FROM officers WHERE LOWER(TRIM(first_name)) = LOWER(TRIM(?)) AND LOWER(TRIM(last_name)) = LOWER(TRIM(?))",
      [firstNameTrimmed, lastNameTrimmed]
    );
    if (nameCheck.rows.length > 0) {
      const existingOfficer = nameCheck.rows[0];
      return res.render("officer/signup", {
        error: `An officer with the name "${firstNameTrimmed} ${lastNameTrimmed}" already exists (Student ID: ${existingOfficer.studentid || 'N/A'}). Each officer must have a unique name combination.`,
      });
    }

    // Hash password
    const password_hash = await bcrypt.hash(password, 10);

    // Ensure columns exist
    const columnsToAdd = [
      { name: 'username', def: 'TEXT' },
      { name: 'password_hash', def: 'TEXT' },
      { name: 'email', def: 'TEXT' },
      { name: 'facebook', def: 'TEXT' },
      { name: 'bio', def: 'TEXT' },
      { name: 'department', def: 'TEXT' },
      { name: 'program', def: 'TEXT' },
      { name: 'status', def: "VARCHAR(50) DEFAULT 'Pending'" }
    ];
    
    for (const col of columnsToAdd) {
      try {
        await pool.query(`ALTER TABLE officers ADD COLUMN ${col.name} ${col.def}`);
      } catch (err) {
        // Silently ignore duplicate column errors
        if (err.code !== 'ER_DUP_FIELDNAME' && err.errno !== 1060) {
          console.warn(`Warning: Could not add column ${col.name}:`, err.message);
        }
      }
    }

    // Automatically assign permissions based on role/tier
    const rolePermissions = getPermissionsForRole(roleTrimmed);
    const permissionsJson = JSON.stringify({ permissions: rolePermissions });
    
    console.log(`[Officer Signup] Role: "${roleTrimmed}" - Assigned ${rolePermissions.length} permissions based on tier system`);

    // Insert new officer with Pending status (using validated/trimmed values)
    const result = await pool.query(
      `INSERT INTO officers (first_name, last_name, studentid, email, password_hash, department, program, role, club_id, status, permissions)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', ?)`,
      [
        firstNameTrimmed,
        lastNameTrimmed,
        studentid,
        emailTrimmed,
        password_hash,
        departmentTrimmed,
        programTrimmed,
        roleTrimmed,
        clubIdNum,
        permissionsJson
      ]
    );

    // Redirect to success page instead of auto-login
    res.redirect("/officer/signup?success=pending");
  } catch (err) {
    console.error("Officer signup error:", err);
    if (err.code === 'ER_DUP_ENTRY' || err.errno === 1062) {
      if (err.sqlMessage && err.sqlMessage.includes('username')) {
        return res.render("officer/signup", {
          error: "Username already exists. Please choose a different username.",
        });
      }
      if (err.sqlMessage && err.sqlMessage.includes('studentid')) {
        return res.render("officer/signup", {
          error: "An account with this Student ID already exists.",
        });
      }
    }
    res.render("officer/signup", {
      error: "An error occurred during registration. Please try again later.",
    });
  }
});

/* ===============================
   🔐 FORGOT PASSWORD FLOW
================================= */

// Store reset tokens temporarily (in production, use Redis or database)
const resetTokens = new Map();

// Generate email from studentid if email doesn't exist
function getOfficerEmail(officer) {
  // If officer has email field, use it
  if (officer.email && officer.email.endsWith('@umindanao.edu.ph')) {
    return officer.email;
  }
  // Otherwise, generate from studentid
  if (officer.studentid) {
    return `${officer.studentid}@umindanao.edu.ph`;
  }
  return null;
}

// GET Forgot Password Page
router.get("/forgot-password", (req, res) => {
  if (req.session?.officer) return res.redirect("/officer");
  res.render("officer/forgotPassword", { error: null, success: false });
});

// POST Forgot Password - Send OTP
router.post("/forgot-password", passwordResetLimiter, async (req, res) => {
  if (req.session?.officer) return res.redirect("/officer");
  
  const { identifier } = req.body;
  
  if (!identifier) {
    return res.render("officer/forgotPassword", {
      error: "Please enter your username or email",
      success: false,
    });
  }

  try {
    // Ensure email column exists
    await pool.query(`ALTER TABLE officers ADD COLUMN IF NOT EXISTS email TEXT`).catch(() => {});
    
    // Try to find officer by username or email
    let query = `
      SELECT id, first_name, last_name, CONCAT(first_name, ' ', last_name) AS name, 
             username, studentid, email
      FROM officers 
      WHERE username = ? OR email = ? OR studentid = ?
      LIMIT 1
    `;
    
    const { rows } = await pool.query(query, [identifier, identifier, identifier]);
    const officer = rows[0];
    
    if (!officer) {
      return res.render("officer/forgotPassword", {
        error: "No account found with that username or email",
        success: false,
      });
    }

    // Get or generate email
    const email = getOfficerEmail(officer);
    
    if (!email) {
      return res.render("officer/forgotPassword", {
        error: "Unable to determine email address. Please contact administrator.",
        success: false,
      });
    }

    // Generate and store OTP
    const otp = generateOTP();
    storeOTP(identifier.toLowerCase(), otp, officer.id);

    // Send OTP email
    try {
      await sendOTPEmail(email, otp, officer.username || officer.name);
      
      // Store identifier in session for verification step
      req.session.forgotPasswordIdentifier = identifier.toLowerCase();
      
      res.render("officer/verifyOTP", {
        identifier: identifier,
        error: null,
      });
    } catch (emailError) {
      console.error("Error sending OTP email:", emailError);
      return res.render("officer/forgotPassword", {
        error: "Failed to send OTP email. Please check email configuration or contact administrator.",
        success: false,
      });
    }
  } catch (err) {
    console.error("Forgot password error:", err);
    res.render("officer/forgotPassword", {
      error: "An error occurred. Please try again later.",
      success: false,
    });
  }
});

// GET Verify OTP Page
router.get("/verify-otp", (req, res) => {
  if (req.session?.officer) return res.redirect("/officer");
  if (!req.session?.forgotPasswordIdentifier) {
    return res.redirect("/officer/forgot-password");
  }
  
  res.render("officer/verifyOTP", {
    identifier: req.session.forgotPasswordIdentifier,
    error: null,
  });
});

// POST Verify OTP
router.post("/verify-otp", passwordResetLimiter, async (req, res) => {
  if (req.session?.officer) return res.redirect("/officer");
  
  const { identifier, otp } = req.body;
  
  if (!identifier || !otp) {
    return res.render("officer/verifyOTP", {
      identifier: identifier || req.session?.forgotPasswordIdentifier || '',
      error: "Please enter the OTP code",
    });
  }

  try {
    // Verify OTP
    const verification = verifyOTP(identifier.toLowerCase(), otp);
    
    if (!verification.valid) {
      return res.render("officer/verifyOTP", {
        identifier: identifier,
        error: verification.error || "Invalid or expired OTP code",
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    resetTokens.set(resetToken, {
      officerId: verification.officerId,
      expiresAt: Date.now() + 30 * 60 * 1000, // 30 minutes
    });

    // Clean up session
    delete req.session.forgotPasswordIdentifier;

    // Redirect to reset password page
    res.redirect(`/officer/reset-password?token=${resetToken}`);
  } catch (err) {
    console.error("Verify OTP error:", err);
    res.render("officer/verifyOTP", {
      identifier: identifier,
      error: "An error occurred. Please try again.",
    });
  }
});

// GET Reset Password Page
router.get("/reset-password", (req, res) => {
  if (req.session?.officer) return res.redirect("/officer");
  
  const { token } = req.query;
  
  if (!token) {
    return res.redirect("/officer/forgot-password");
  }

  const tokenData = resetTokens.get(token);
  
  if (!tokenData || Date.now() > tokenData.expiresAt) {
    resetTokens.delete(token);
    return res.render("officer/resetPassword", {
      officerId: null,
      token: null,
      error: "Invalid or expired reset token. Please request a new password reset.",
    });
  }

  res.render("officer/resetPassword", {
    officerId: tokenData.officerId,
    token: token,
    error: null,
  });
});

// POST Reset Password
router.post("/reset-password", passwordResetLimiter, async (req, res) => {
  if (req.session?.officer) return res.redirect("/officer");
  
  const { officerId, token, password, confirmPassword } = req.body;
  
  if (!officerId || !token || !password || !confirmPassword) {
    return res.render("officer/resetPassword", {
      officerId: officerId || null,
      token: token || null,
      error: "All fields are required",
    });
  }

  // Verify token
  const tokenData = resetTokens.get(token);
  
  if (!tokenData || Date.now() > tokenData.expiresAt || tokenData.officerId !== parseInt(officerId)) {
    resetTokens.delete(token);
    return res.render("officer/resetPassword", {
      officerId: null,
      token: null,
      error: "Invalid or expired reset token. Please request a new password reset.",
    });
  }

  // Validate passwords
  if (password !== confirmPassword) {
    return res.render("officer/resetPassword", {
      officerId: officerId,
      token: token,
      error: "Passwords do not match",
    });
  }

  if (password.length < 8) {
    return res.render("officer/resetPassword", {
      officerId: officerId,
      token: token,
      error: "Password must be at least 8 characters long",
    });
  }

  try {
    // Hash new password
    const passwordHash = await bcrypt.hash(password, 10);
    
    // Update password in database
    await pool.query(
      "UPDATE officers SET password_hash = ? WHERE id = ?",
      [passwordHash, officerId]
    );

    // Remove token
    resetTokens.delete(token);

    // Redirect to login with success message
    res.redirect("/officer/login?passwordReset=success");
  } catch (err) {
    console.error("Reset password error:", err);
    res.render("officer/resetPassword", {
      officerId: officerId,
      token: token,
      error: "An error occurred while resetting your password. Please try again.",
    });
  }
});

export default router;
