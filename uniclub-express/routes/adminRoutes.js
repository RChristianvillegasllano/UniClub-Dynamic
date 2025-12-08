// routes/adminRoutes.js
import express from "express";
import bcrypt from "bcryptjs";
import { body, validationResult } from "express-validator";
import pool, { adminPool } from "../config/db.js";
import { loginLimiter, csrfProtection, writeLimiter, csrfMiddleware } from "../middleware/security.js";
import { uploadClubPhoto } from "../middleware/upload.js";
import { getPermissionsForRole } from "../config/tierPermissions.js";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const router = express.Router();

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

  try {
    const result = await adminPool.query("SELECT * FROM admins WHERE username = ?", [username]);
    if (result.rows.length === 0)
      return res.render("admin/login", { title: "Admin Login | UniClub", error: "Invalid username or password" });

    const admin = result.rows[0];
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch)
      return res.render("admin/login", { title: "Admin Login | UniClub", error: "Invalid username or password" });

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
    res.render("admin/login", { title: "Admin Login | UniClub", error: "Server error" });
  }
});
// Edit Officer Form
router.get("/officers/edit/:id", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const [officerR, clubsR] = await Promise.all([
      pool.query("SELECT * FROM officers WHERE id = ?", [req.params.id]),
      pool.query("SELECT id, name FROM clubs ORDER BY name ASC"),
    ]);
    if (officerR.rows.length === 0) return res.redirect("/admin/officers");
    const officer = officerR.rows[0];
    // Try to derive club_name for select comparison
    const clubName = (await pool.query("SELECT name FROM clubs WHERE id = ?", [officer.club_id]).catch(()=>({rows:[]}))).rows[0]?.name || null;
    let permissions = null; try { permissions = officer.permissions; } catch(_) { permissions = null; }
    res.render("admin/editOfficer", {
      title: "Edit Officer",
      officer: { ...officer, club_name: clubName, permissions },
      clubs: clubsR.rows || [],
      currentPath: "/admin/officers",
      messages: [],
      error: null,
    });
  } catch (error) {
    console.error("Error loading officer:", error);
    res.status(500).send("Server error");
  }
});

// Handle Edit Officer
router.post("/officers/edit/:id", writeLimiter, async (req, res) => {
  const { first_name, last_name, studentid, email, club_id, role, department, program, permissions, username, password, photo_url } = req.body;
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

    if (!username || !username.trim()) {
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
        error: "Username is required",
      });
    }

    let passwordHash = null;
    if (password && password.trim().length > 0) {
      passwordHash = await bcrypt.hash(password, 10);
    }

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
              username=?,
              photo_url=?,
              password_hash = COALESCE(?, password_hash)
        WHERE id=?`,
      [
        firstNameValidation.value,
        lastNameValidation.value,
        studentid,
        email ? email.trim() : null,
        resolvedClubId,
        role,
        department,
        program,
        perms ? JSON.stringify(perms) : null,
        username.trim(),
        photo_url || null,
        passwordHash,
        id,
      ]
    );
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
      .query(`SELECT COUNT(*)::int AS total_clubs FROM clubs`)
      .catch(() => ({ rows: [{ total_clubs: 0 }] }));

    const activeDeptsQ = pool
      .query(`SELECT COUNT(DISTINCT department)::int AS active_depts FROM clubs WHERE department IS NOT NULL AND department <> ''`)
      .catch(() => ({ rows: [{ active_depts: 0 }] }));

    const uniqueRolesQ = pool
      .query(`SELECT COUNT(DISTINCT role)::int AS unique_roles FROM officers WHERE role IS NOT NULL AND role <> ''`)
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
      ) lm;
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
      ) lm;
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
      ) lm;
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

    // Monthly activity (events), use created_at if date is NULL
    const monthlyActQ = pool.query(`
      SELECT DATE_FORMAT(COALESCE(date, created_at), '%Y-%m') AS ym, COUNT(*) AS count
      FROM events
      GROUP BY DATE_FORMAT(COALESCE(date, created_at), '%Y-%m')
      ORDER BY ym
      LIMIT 24;
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

    const monthlyLabels = monthlyActR.rows.map(r => r.ym);
    const monthlyCounts = monthlyActR.rows.map(r => r.count);

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
    let paramCount = 0;
    const conditions = [];

    // Search filter
    if (search) {
      const searchParam = `%${search}%`;
      conditions.push(`(s.first_name ILIKE $${++paramCount} OR s.last_name ILIKE $${++paramCount} OR CONCAT(s.first_name, ' ', s.last_name) ILIKE $${++paramCount} OR s.email ILIKE $${++paramCount} OR s.studentid ILIKE $${++paramCount})`);
      params.push(searchParam, searchParam, searchParam, searchParam, searchParam);
    }

    // Program filter
    if (program) {
      conditions.push(`s.program = $${++paramCount}`);
      params.push(program);
    }

    // Year level filter
    if (year_level) {
      conditions.push(`s.year_level = $${++paramCount}`);
      params.push(year_level);
    }

    // Department filter
    if (department) {
      conditions.push(`s.department = $${++paramCount}`);
      params.push(department);
    }

    // Status filter
    if (status) {
      conditions.push(`COALESCE(s.status, 'Active') = $${++paramCount}`);
      params.push(status);
    }

    // Ensure status column exists
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'Active'`);

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

router.post("/students/add", writeLimiter, async (req, res) => {
  const { first_name, last_name, email, program, year_level, department, studentid, birthdate } = req.body;
  try {
    // Name validation
    const firstNameValidation = validateName(first_name, "First name");
    if (!firstNameValidation.valid) {
      return res.render("admin/addStudent", {
        title: "Add Student | UniClub",
        error: firstNameValidation.error,
        currentPath: "/admin/students",
        messages: [],
      });
    }
    
    const lastNameValidation = validateName(last_name, "Last name");
    if (!lastNameValidation.valid) {
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
      return res.render("admin/addStudent", {
        title: "Add Student | UniClub",
        error: "Email must follow format: firstinitial.lastname.6digitid.tc@umindanao.edu.ph (e.g., j.delacruz.111222.tc@umindanao.edu.ph or r.llano.141429.tc@umindanao.edu.ph)",
        currentPath: "/admin/students",
        messages: [],
      });
    }

    // Student ID validation: exactly 6 digits (required)
    if (!studentid || !/^\d{6}$/.test(studentid)) {
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
      const existingStudent = nameCheck.rows[0];
      return res.render("admin/addStudent", {
        title: "Add Student | UniClub",
        error: `A student with the name "${firstNameValidation.value} ${lastNameValidation.value}" already exists (Student ID: ${existingStudent.studentid || 'N/A'}). Each student must have a unique name combination.`,
        currentPath: "/admin/students",
        messages: [],
      });
    }

    // Ensure optional columns exist
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS department VARCHAR(100)`);
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS studentid VARCHAR(50)`);
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS birthdate DATE`);

    await pool.query(
      "INSERT INTO students (first_name, last_name, email, program, year_level, department, studentid, birthdate, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())",
      [firstNameValidation.value, lastNameValidation.value, email, program, year_level, department || null, studentid || null, birthdate || null]
    );
    res.redirect("/admin/students");
  } catch (error) {
    console.error("Error adding student:", error);
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
router.post("/students/edit/:id", writeLimiter, async (req, res) => {
  const { first_name, last_name, email, program, year_level, department, studentid, status, birthdate } = req.body;
  const id = req.params.id;

  try {
    // Name validation
    const firstNameValidation = validateName(first_name, "First name");
    if (!firstNameValidation.valid) {
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
      return res.render("admin/editStudent", {
        title: "Edit Student | UniClub",
        student: { id, first_name, last_name, email, program, year_level, department, studentid, status, birthdate },
        error: "Email must follow format: firstinitial.lastname.6digitid.tc@umindanao.edu.ph (e.g., j.delacruz.111222.tc@umindanao.edu.ph or r.llano.141429.tc@umindanao.edu.ph)",
        currentPath: "/admin/students",
        messages: [],
      });
    }

    // Student ID validation: exactly 6 digits (required)
    if (!studentid || !/^\d{6}$/.test(studentid)) {
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
      const existingStudent = nameCheck.rows[0];
      return res.render("admin/editStudent", {
        title: "Edit Student | UniClub",
        student: { id, first_name, last_name, email, program, year_level, department, studentid, status, birthdate },
        error: `A student with the name "${firstNameValidation.value} ${lastNameValidation.value}" already exists (Student ID: ${existingStudent.studentid || 'N/A'}). Each student must have a unique name combination.`,
        currentPath: "/admin/students",
        messages: [],
      });
    }

    // Ensure optional columns exist
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS department VARCHAR(100)`);
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS studentid VARCHAR(50)`);
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'Active'`);
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS birthdate DATE`);

    // Validate status
    const validStatuses = ["Active", "Graduated", "Inactive"];
    const studentStatus = validStatuses.includes(status) ? status : "Active";

    await pool.query(
      `UPDATE students
       SET first_name = ?, last_name = ?, email = ?, program = ?, year_level = ?, department = ?, studentid = ?, status = ?, birthdate = ?
       WHERE id = ?`,
      [firstNameValidation.value, lastNameValidation.value, email, program, year_level, department || null, studentid || null, studentStatus, birthdate || null, id]
    );
    res.redirect("/admin/students");
  } catch (error) {
    console.error("Error updating student:", error);
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
    const [checkResult] = await pool.query("SELECT id FROM students WHERE id = ?", [studentId]);
    if (checkResult.length === 0) {
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
      conditions.push(`(s.first_name ILIKE $${++paramCount} OR s.last_name ILIKE $${++paramCount} OR CONCAT(s.first_name, ' ', s.last_name) ILIKE $${++paramCount} OR s.email ILIKE $${++paramCount} OR s.studentid ILIKE $${++paramCount})`);
      params.push(searchParam, searchParam, searchParam, searchParam, searchParam);
    }
    if (program) {
      conditions.push(`s.program = $${++paramCount}`);
      params.push(program);
    }
    if (year_level) {
      conditions.push(`s.year_level = $${++paramCount}`);
      params.push(year_level);
    }
    if (department) {
      conditions.push(`s.department = $${++paramCount}`);
      params.push(department);
    }
    if (status) {
      conditions.push(`COALESCE(s.status, 'Active') = $${++paramCount}`);
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
        conditions.push(`o.club_id = $${++paramCount}`);
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
      conditions.push(`(o.first_name ILIKE $${++paramCount} OR o.last_name ILIKE $${++paramCount} OR CONCAT(o.first_name, ' ', o.last_name) ILIKE $${++paramCount} OR o.studentid ILIKE $${++paramCount})`);
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
        o.username,
        o.club_id,
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
        o.username,
        o.club_id,
        c.name AS club_name,
        o.created_at,
        COALESCE(o.status, 'Pending') AS status
      FROM officers o
      LEFT JOIN clubs c ON o.club_id = c.id
      WHERE COALESCE(o.status, 'Pending') = 'Pending'
      ORDER BY o.created_at DESC
    `;
    const pendingOfficersR = await pool.query(pendingOfficersQuery).catch(() => ({ rows: [] }));

    // Get pending count for dashboard badge
    const pendingCount = pendingOfficersR.rows?.length || 0;

    res.render("admin/approvals", {
      title: "Approvals | UniClub Admin",
      pendingOfficers: pendingOfficersR.rows || [],
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
  const { first_name, last_name, studentid, club_id, role, department, program, permissions, username, password, photo_url } = req.body;

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

    if (!username || !username.trim()) {
      const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] }));
      return res.render("admin/addOfficer", {
        title: "Add Officer | UniClub Admin",
        error: "Username is required",
        clubs: clubs.rows || [],
        currentPath: "/admin/officers",
        messages: [],
        formData: req.body,
      });
    }

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
    await pool.query(`ALTER TABLE officers ADD COLUMN IF NOT EXISTS username TEXT`);
    await pool.query(`ALTER TABLE officers ADD COLUMN IF NOT EXISTS password_hash TEXT`);
    await pool.query(`ALTER TABLE officers ADD COLUMN IF NOT EXISTS photo_url TEXT`);
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

    await pool.query(
      `INSERT INTO officers (first_name, last_name, studentid, club_id, role, department, program, permissions, username, password_hash, photo_url, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [firstNameValidation.value, lastNameValidation.value, studentid, resolvedClubId, role, department, program, JSON.stringify(perms), username.trim(), passwordHash, photo_url || null]
    );
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
      conditions.push(`(c.name ILIKE $${++paramCount} OR c.description ILIKE $${++paramCount} OR c.adviser ILIKE $${++paramCount})`);
      params.push(searchParam, searchParam, searchParam);
    }

    // Department filter
    if (department) {
      conditions.push(`COALESCE(c.department, '') = $${++paramCount}`);
      params.push(department);
    }

    // Category filter
    if (category) {
      conditions.push(`COALESCE(c.category, '') = $${++paramCount}`);
      params.push(category);
    }

    // Status filter
    if (status) {
      conditions.push(`COALESCE(c.status, 'Active') = $${++paramCount}`);
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
        COALESCE(o_counts.officer_count, 0)::int AS officer_count,
        COALESCE(e_counts.event_count, 0)::int AS event_count
      FROM clubs c
      LEFT JOIN (
        SELECT club_id, COUNT(*)::int AS officer_count
        FROM officers
        GROUP BY club_id
      ) o_counts ON o_counts.club_id = c.id
      LEFT JOIN (
        SELECT club_id, COUNT(*)::int AS event_count
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
      conditions.push(`(c.name ILIKE $${++paramCount} OR c.description ILIKE $${++paramCount} OR c.adviser ILIKE $${++paramCount})`);
      params.push(searchParam, searchParam, searchParam);
    }

    if (department) {
      conditions.push(`COALESCE(c.department, '') = $${++paramCount}`);
      params.push(department);
    }

    if (category) {
      conditions.push(`COALESCE(c.category, '') = $${++paramCount}`);
      params.push(category);
    }

    if (status) {
      conditions.push(`COALESCE(c.status, 'Active') = $${++paramCount}`);
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
    let activitiesRows = [];
    try {
      const activitiesWithStatus = await pool.query(`
        SELECT e.id, e.name AS activity, e.date, e.location, e.description,
               c.name AS club_name,
               CASE 
                 WHEN e.date IS NULL THEN 'Scheduled'
                 WHEN e.date >= CURDATE() THEN 'Upcoming'
                 ELSE 'Past'
               END AS status
        FROM events e
        LEFT JOIN clubs c ON c.id = e.club_id
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
                    ORDER BY e.date ASC NULLS LAST, e.created_at DESC
                  `);
                  activitiesRows = altName2.rows || [];
                } catch (err4) {
                  if (err4.code === "42703") {
                    // Final fallback: minimal columns
                    const minimal = await pool.query(`
                      SELECT id FROM events ORDER BY id DESC
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
    const result = await pool.query(
      "SELECT id, sender_name, sender_email, subject, content, created_at, `read` FROM messages ORDER BY created_at DESC"
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
    const result = await pool.query("SELECT * FROM messages WHERE id = ?", [id]);

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

    // Insert message for each recipient
    const adminName = req.session.admin.username || 'Admin';
    const adminEmail = 'admin@uniclub.local';

    for (const recipient of recipients) {
      await pool.query(
        `INSERT INTO messages (sender_name, sender_email, subject, content, recipient_type, recipient_id, recipient_name, \`read\`, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, false, NOW())`,
        [
          adminName,
          adminEmail,
          subject,
          content,
          recipient.type,
          recipient.id, // Individual recipient ID (set for each recipient)
          recipient.name
        ]
      );
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

// View all events
router.get("/events", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const events = await pool.query(`
      SELECT e.id, e.name, e.date, e.location, e.description, c.name AS club_name
      FROM events e
      LEFT JOIN clubs c ON e.club_id = c.id
      ORDER BY e.date DESC
    `);
    res.render("admin/events", {
      title: "Manage Events | UniClub Admin",
      events: events.rows || [],
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
    });
  } catch (error) {
    console.error("Error loading clubs:", error);
    res.status(500).send("Server error");
  }
});

// Handle Add Event
router.post("/events/add", writeLimiter, async (req, res) => {
  const { name, club_id, date, location, description } = req.body;

  try {
    await pool.query(
      `INSERT INTO events (name, club_id, date, location, description, created_at)
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [name, club_id, date, location, description]
    );
    res.redirect("/admin/events");
  } catch (error) {
    console.error("Error adding event:", error);
    res.render("admin/addEvent", {
      title: "Add Event | UniClub Admin",
      error: "Failed to add event. Please check your inputs.",
      clubs: [],
    });
  }
});

// Handle Schedule Activity (alias for /add)
router.post("/events/create", writeLimiter, async (req, res) => {
  const { name, club_id, date, location, description } = req.body;

  try {
    await pool.query(
      `INSERT INTO events (name, club_id, date, location, description, created_at)
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [name, club_id, date, location, description]
    );
    res.redirect("/admin/requirements");
  } catch (error) {
    console.error("Error scheduling activity:", error);
    const clubs = await pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] }));
    res.render("admin/addEvent", {
      title: "Schedule Activity | UniClub Admin",
      error: "Failed to schedule activity. Please check your inputs.",
      clubs: clubs.rows || [],
    });
  }
});

// Edit Event Form
router.get("/events/edit/:id", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const [event, clubs] = await Promise.all([
      pool.query("SELECT * FROM events WHERE id = ?", [req.params.id]),
      pool.query("SELECT id, name FROM clubs ORDER BY name ASC"),
    ]);

    if (event.rows.length === 0) return res.redirect("/admin/events");

    res.render("admin/editEvent", {
      title: "Edit Event | UniClub Admin",
      event: event.rows[0],
      clubs: clubs.rows,
    });
  } catch (error) {
    console.error("Error loading event for edit:", error);
    res.status(500).send("Server error");
  }
});

// Handle Edit Event
router.post("/events/edit/:id", writeLimiter, async (req, res) => {
  const { name, club_id, date, location, description } = req.body;

  try {
    await pool.query(
      `UPDATE events 
       SET name = ?, club_id = ?, date = ?, location = ?, description = ? 
       WHERE id = ?`,
      [name, club_id, date, location, description, req.params.id]
    );
    res.redirect("/admin/events");
  } catch (error) {
    console.error("Error updating event:", error);
    res.status(500).send("Server error");
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
      let query = "SELECT * FROM students WHERE 1=1";
      const params = [];
      let paramCount = 0;

      if (startDate) {
        query += ` AND created_at >= $${++paramCount}`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND created_at <= $${++paramCount}`;
        params.push(endDate + " 23:59:59");
      }

      query += " ORDER BY created_at DESC";
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
      let paramCount = 0;

      if (club_id) {
        query += ` AND c.id = $${++paramCount}`;
        params.push(club_id);
      }
      if (startDate) {
        query += ` AND c.created_at >= $${++paramCount}`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND c.created_at <= $${++paramCount}`;
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
      let paramCount = 0;

      if (club_id) {
        query += ` AND e.club_id = $${++paramCount}`;
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
        query += ` AND COALESCE(e.date, e.created_at) >= $${++paramCount}`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND COALESCE(e.date, e.created_at) <= $${++paramCount}`;
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
      let paramCount = 0;

      if (club_id) {
        query += ` AND o.club_id = $${++paramCount}`;
        params.push(club_id);
      }
      if (startDate) {
        query += ` AND o.created_at >= $${++paramCount}`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND o.created_at <= $${++paramCount}`;
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
      let paramCount = 0;

      if (club_id) {
        query += ` AND r.club_id = $${++paramCount}`;
        params.push(club_id);
      }
      if (status) {
        query += ` AND r.status = $${++paramCount}`;
        params.push(status);
      }
      if (startDate) {
        query += ` AND r.created_at >= $${++paramCount}`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND r.created_at <= $${++paramCount}`;
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
      let paramCount = 0;

      if (status) {
        query += ` AND status = $${++paramCount}`;
        params.push(status);
      }
      if (startDate) {
        query += ` AND COALESCE(date, created_at) >= $${++paramCount}`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND COALESCE(date, created_at) <= $${++paramCount}`;
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
      let paramCount = 0;

      if (startDate) {
        query += ` AND created_at >= $${++paramCount}`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND created_at <= $${++paramCount}`;
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
      let paramCount = 0;

      if (startDate) {
        query += ` AND created_at >= $${++paramCount}`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND created_at <= $${++paramCount}`;
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
      let paramCount = 0;

      if (club_id) {
        query += ` AND c.id = $${++paramCount}`;
        params.push(club_id);
      }
      if (startDate) {
        query += ` AND c.created_at >= $${++paramCount}`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND c.created_at <= $${++paramCount}`;
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
      let paramCount = 0;

      if (club_id) {
        query += ` AND e.club_id = $${++paramCount}`;
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
        query += ` AND COALESCE(e.date, e.created_at) >= $${++paramCount}`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND COALESCE(e.date, e.created_at) <= $${++paramCount}`;
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
      let paramCount = 0;

      if (club_id) {
        query += ` AND o.club_id = $${++paramCount}`;
        params.push(club_id);
      }
      if (startDate) {
        query += ` AND o.created_at >= $${++paramCount}`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND o.created_at <= $${++paramCount}`;
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
      let paramCount = 0;

      if (club_id) {
        query += ` AND r.club_id = $${++paramCount}`;
        params.push(club_id);
      }
      if (status) {
        query += ` AND r.status = $${++paramCount}`;
        params.push(status);
      }
      if (startDate) {
        query += ` AND r.created_at >= $${++paramCount}`;
        params.push(startDate);
      }
      if (endDate) {
        query += ` AND r.created_at <= $${++paramCount}`;
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
  if (req.session) {
    req.session.destroy((err) => {
      if (err) console.error("Session destroy error:", err);
      res.redirect("/admin/login");
    });
  } else {
    res.redirect("/admin/login");
  }
});

export default router;
