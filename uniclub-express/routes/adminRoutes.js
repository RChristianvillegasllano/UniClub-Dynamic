// routes/adminRoutes.js
import express from "express";
import bcrypt from "bcryptjs";
import pool from "../config/db.js";

const router = express.Router();

/* ===============================
   🧠 ADMIN AUTH ROUTES
================================= */

// Admin Login Page
router.get("/login", (req, res) => {
  res.render("admin/login", { title: "Admin Login | UniClub", error: null });
});

// Handle Login
router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query("SELECT * FROM admins WHERE username = $1", [username]);
    if (result.rows.length === 0)
      return res.render("admin/login", { title: "Admin Login | UniClub", error: "Invalid username or password" });

    const admin = result.rows[0];
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch)
      return res.render("admin/login", { title: "Admin Login | UniClub", error: "Invalid username or password" });

    req.session.admin = admin;
    res.redirect("/admin/dashboard");
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
      pool.query("SELECT * FROM officers WHERE id = $1", [req.params.id]),
      pool.query("SELECT id, name FROM clubs ORDER BY name ASC"),
    ]);
    if (officerR.rows.length === 0) return res.redirect("/admin/officers");
    const officer = officerR.rows[0];
    // Try to derive club_name for select comparison
    const clubName = (await pool.query("SELECT name FROM clubs WHERE id = $1", [officer.club_id]).catch(()=>({rows:[]}))).rows[0]?.name || null;
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
router.post("/officers/edit/:id", async (req, res) => {
  const { name, studentid, club, role, department, program, permissions } = req.body;
  const id = req.params.id;
  try {
    await pool.query(`ALTER TABLE officers ADD COLUMN IF NOT EXISTS permissions JSONB`);
    const clubResult = await pool.query("SELECT id FROM clubs WHERE name = $1 LIMIT 1", [club]);
    const club_id = clubResult.rows[0]?.id || null;
    let perms = null; try { perms = permissions ? JSON.parse(permissions) : null; } catch(_) { perms = null; }
    await pool.query(
      `UPDATE officers SET name=$1, studentid=$2, club_id=$3, role=$4, department=$5, program=$6, permissions=$7 WHERE id=$8`,
      [name, studentid, club_id, role, department, program, perms ? JSON.stringify(perms) : null, id]
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
      SELECT id, name, created_at
      FROM students
      ORDER BY created_at DESC
      LIMIT 6
    `).catch(() => ({ rows: [] }));

    const clubsListQ = pool.query("SELECT id, name, department, adviser FROM clubs ORDER BY name LIMIT 8").catch(() => ({ rows: [] }));

    const officersQ = pool.query("SELECT id, name, studentid, club_id, role, department, program FROM officers ORDER BY name LIMIT 8").catch(() => ({ rows: [] }));

    const activitiesQ = pool.query("SELECT id, activity, club, date, location, status FROM activities ORDER BY date DESC LIMIT 8").catch(() => ({ rows: [] }));

    const requirementsQ = pool.query("SELECT id, requirement, club, due_date, status FROM requirements ORDER BY due_date DESC LIMIT 10").catch(() => ({ rows: [] }));

    const messagesQ = pool.query(`SELECT id, "from", subject, content, created_at, read FROM messages ORDER BY created_at DESC LIMIT 8`).catch(() => ({ rows: [] }));

    const [studentsR, clubsR, eventsR, recentR, clubsListR, officersR, activitiesR, requirementsR, messagesR] =
      await Promise.all([studentsQ, clubsQ, eventsQ, recentQ, clubsListQ, officersQ, activitiesQ, requirementsQ, messagesQ]);

    res.render("admin/dashboard", {
      title: "Admin Dashboard | UniClub",
      admin: req.session.admin,
  currentPath: "/admin/dashboard",  // ✅ important
      studentsCount: Number(studentsR.rows[0]?.count || 0),
      clubsCount: Number(clubsR.rows[0]?.count || 0),
      eventsCount: Number(eventsR.rows[0]?.count || 0),
      recentActivities: recentR.rows || [],
      clubsList: clubsListR.rows || [],
      officers: officersR.rows || [],
      activities: activitiesR.rows || [],
      requirements: requirementsR.rows || [],
      messages: messagesR.rows || [],
      pending: [],
      announceSuccess: req.query?.sent === '1',
      analytics: {
        activeClubs: Number(clubsR.rows[0]?.count || 0),
        avgOfficersPerClub:
          Number(clubsR.rows[0]?.count || 0) > 0
            ? Math.round(officersR.rows.length / Number(clubsR.rows[0]?.count || 0))
            : 0,
        totalActivities: activitiesR.rows.length,
      },
    });
  } catch (error) {
    console.error("Error loading dashboard:", error);
    res.status(500).send("Server error");
  }
});

// Send Announcement
router.post("/announcements", async (req, res) => {
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
      `INSERT INTO announcements (subject, content, audience) VALUES ($1, $2, $3)`,
      [subject, content, audience || 'all']
    );

    // Optionally, mirror to messages inbox for record (no specific recipient field available)
    await pool.query(
      `INSERT INTO messages (sender_name, sender_email, subject, content, read, created_at)
       VALUES ($1, $2, $3, $4, false, NOW())`,
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
      WITH this_month AS (
        SELECT COUNT(*)::int AS c
        FROM officers
        WHERE (created_at >= date_trunc('month', now()))
      ),
      last_month AS (
        SELECT COUNT(*)::int AS c
        FROM officers
        WHERE (created_at >= date_trunc('month', now()) - INTERVAL '1 month')
          AND (created_at <  date_trunc('month', now()))
      )
      SELECT
        COALESCE((tm.c - NULLIF(lm.c,0)) * 100.0 / NULLIF(lm.c,0), 0.0) AS mom_growth,
        tm.c AS this_month, lm.c AS last_month
      FROM this_month tm CROSS JOIN last_month lm;
    `).catch(() => ({ rows: [{ mom_growth: 0, this_month: 0, last_month: 0 }] }));

    // Clubs by department
    const clubsByDeptQ = pool.query(`
      SELECT COALESCE(department, 'Unassigned') AS department, COUNT(*)::int AS clubs
      FROM clubs
      GROUP BY 1
      ORDER BY 1;
    `).catch(() => ({ rows: [] }));

    // Roles distribution
    const rolesDistQ = pool.query(`
      SELECT COALESCE(role, 'Unassigned') AS role, COUNT(*)::int AS count
      FROM officers
      GROUP BY 1
      ORDER BY count DESC, role ASC
      LIMIT 12;
    `).catch(() => ({ rows: [] }));

    // Monthly activity (events), use created_at if date is NULL
    const monthlyActQ = pool.query(`
      SELECT to_char(COALESCE(date, created_at), 'YYYY-MM') AS ym, COUNT(*)::int AS count
      FROM events
      GROUP BY 1
      ORDER BY 1
      LIMIT 24;
    `).catch(() => ({ rows: [] }));

    // Department analytics: officers & clubs per department
    const deptAggQ = pool.query(`
      WITH base AS (
        SELECT COALESCE(c.department, 'Unassigned') AS department,
               COUNT(DISTINCT c.id)::int AS active_clubs,
               COUNT(o.id)::int AS total_officers
        FROM clubs c
        LEFT JOIN officers o ON o.club_id = c.id
        GROUP BY 1
      ),
      trend AS (
        SELECT COALESCE(c.department, 'Unassigned') AS department,
               COUNT(e.id)::int FILTER (WHERE COALESCE(e.date, e.created_at) >= now() - INTERVAL '30 days') AS recent_30,
               COUNT(e.id)::int FILTER (WHERE COALESCE(e.date, e.created_at) >= now() - INTERVAL '60 days'
                                    AND COALESCE(e.date, e.created_at) <  now() - INTERVAL '30 days') AS prev_30
        FROM clubs c
        LEFT JOIN events e ON e.club_id = c.id
        GROUP BY 1
      )
      SELECT b.department, b.total_officers, b.active_clubs,
             COALESCE(t.recent_30,0) AS recent_30, COALESCE(t.prev_30,0) AS prev_30
      FROM base b
      LEFT JOIN trend t USING (department)
      ORDER BY b.total_officers DESC, b.department;
    `).catch(() => ({ rows: [] }));

    const [
      totalClubsR, activeDeptsR, uniqueRolesR,
      growthR, clubsByDeptR, rolesDistR, monthlyActR, deptAggR
    ] = await Promise.all([
      totalClubsQ, activeDeptsQ, uniqueRolesQ,
      growthQ, clubsByDeptQ, rolesDistQ, monthlyActQ, deptAggQ
    ]);

    // Prepare data for charts
    const clubDeptLabels = clubsByDeptR.rows.map(r => r.department);
    const clubDeptCounts = clubsByDeptR.rows.map(r => r.clubs);

    const roleLabels = rolesDistR.rows.map(r => r.role);
    const roleCounts = rolesDistR.rows.map(r => r.count);

    const monthlyLabels = monthlyActR.rows.map(r => r.ym);
    const monthlyCounts = monthlyActR.rows.map(r => r.count);

    // Department analytics + derived “activityScore” & trend string
    const deptAnalytics = (deptAggR.rows || []).map(r => {
      const activityScore = r.total_officers * 1 + r.active_clubs * 2 + r.recent_30 * 3; // simple weighted score
      let trend = '—';
      if (r.prev_30 || r.recent_30) {
        const delta = r.recent_30 - r.prev_30;
        trend = delta > 0 ? 'up' : (delta < 0 ? 'down' : 'flat');
      }
      return { ...r, activityScore, trend };
    });

    res.render("admin/analytics", {
      title: "Analytics | UniClub",
      admin: req.session.admin,
      currentPath: "/admin/analytics",
      // top cards
      totalClubs: totalClubsR.rows[0]?.total_clubs || 0,
      activeDepts: activeDeptsR.rows[0]?.active_depts || 0,
      uniqueRoles: uniqueRolesR.rows[0]?.unique_roles || 0,
      growthRate: Number(growthR.rows[0]?.mom_growth || 0).toFixed(0),
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
    const result = await pool.query("SELECT * FROM students ORDER BY created_at DESC");
    res.render("admin/students", {
      title: "Students | UniClub",
      students: result.rows,
      currentPath: "/admin/students",
      messages: [],
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

router.post("/students/add", async (req, res) => {
  const { name, email, program, year_level, department, studentid } = req.body;
  try {
    // Email domain validation
    const emailAllowed = typeof email === 'string' && /@umindanao\.edu\.ph$/i.test(email);
    if (!emailAllowed) {
      return res.render("admin/addStudent", {
        title: "Add Student | UniClub",
        error: "Email must be a valid @umindanao.edu.ph address",
        currentPath: "/admin/students",
        messages: [],
      });
    }

    // Ensure optional columns exist
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS department VARCHAR(100)`);
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS studentid VARCHAR(50)`);

    await pool.query(
      "INSERT INTO students (name, email, program, year_level, department, studentid, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW())",
      [name, email, program, year_level, department || null, studentid || null]
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
    const result = await pool.query("SELECT * FROM students WHERE id = $1", [req.params.id]);
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
router.post("/students/edit/:id", async (req, res) => {
  const { name, email, program, year_level, department, studentid } = req.body;
  const id = req.params.id;

  try {
    // Email domain validation
    const emailAllowed = typeof email === 'string' && /@umindanao\.edu\.ph$/i.test(email);
    if (!emailAllowed) {
      return res.render("admin/editStudent", {
        title: "Edit Student | UniClub",
        student: { id, name, email, program, year_level, department },
        error: "Email must be a valid @umindanao.edu.ph address",
        currentPath: "/admin/students",
        messages: [],
      });
    }

    // Ensure optional columns exist
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS department VARCHAR(100)`);
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS studentid VARCHAR(50)`);

    await pool.query(
      `UPDATE students
       SET name = $1, email = $2, program = $3, year_level = $4, department = $5, studentid = $6
       WHERE id = $7`,
      [name, email, program, year_level, department || null, studentid || null, id]
    );
    res.redirect("/admin/students");
  } catch (error) {
    console.error("Error updating student:", error);
    res.render("admin/editStudent", {
      title: "Edit Student | UniClub",
      student: { id, name, email, program, year_level, department, studentid },
      error: "Failed to update student",
      currentPath: "/admin/students",
      messages: [],
    });
  }
});

// ✅ Delete Student
router.post("/students/delete/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM students WHERE id = $1", [req.params.id]);
    res.redirect("/admin/students");
  } catch (error) {
    console.error("Error deleting student:", error);
    res.status(500).send("Server error");
  }
});

/* ===============================
   👥 OFFICER MANAGEMENT
================================= */

router.get("/officers", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const { page = 1, limit = 20, search = "", club_id = "" } = req.query;
    const pageNum = Math.max(Number.parseInt(String(page), 10) || 1, 1);
    const pageSize = Math.min(Math.max(Number.parseInt(String(limit), 10) || 20, 5), 100);
    const offset = (pageNum - 1) * pageSize;

    // Filters
    const params = [];
    let paramCount = 0;
    const conditions = [];

    if (search) {
      conditions.push(`(o.name ILIKE $${++paramCount} OR o.studentid ILIKE $${paramCount})`);
      params.push(`%${search}%`);
    }
    if (club_id) {
      conditions.push(`o.club_id = $${++paramCount}`);
      params.push(club_id);
    }

    let baseQuery = `
      FROM officers o
      LEFT JOIN clubs c ON o.club_id = c.id
    `;
    if (conditions.length > 0) {
      baseQuery += ` WHERE ${conditions.join(" AND ")}`;
    }

    const listQuery = `
      SELECT o.id, o.name, o.studentid, COALESCE(c.name,'—') AS club, o.role, o.department, o.program
      ${baseQuery}
      ORDER BY o.created_at DESC
      LIMIT $${++paramCount} OFFSET $${++paramCount}
    `;
    const listParams = params.concat([pageSize, offset]);

    const countQuery = `SELECT COUNT(*)::int AS total ${baseQuery}`;

    const [officersR, countR, clubsR] = await Promise.all([
      pool.query(listQuery, listParams),
      pool.query(countQuery, params),
      pool.query("SELECT id, name FROM clubs ORDER BY name ASC").catch(() => ({ rows: [] })),
    ]);

    const total = Number(countR.rows[0]?.total || 0);
    const totalPages = Math.max(Math.ceil(total / pageSize), 1);

    res.render("admin/officers", {
      title: "Manage Officers | UniClub Admin",
      officers: officersR.rows || [],
      currentPath: "/admin/officers",
      messages: [],
      pagination: { page: pageNum, limit: pageSize, total, totalPages },
      filters: { search, club_id },
      clubs: clubsR.rows || [],
    });
  } catch (error) {
    console.error("Error loading officers:", error);
    res.status(500).send("Server error while loading officers.");
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

router.post("/officers/add", async (req, res) => {
  const { name, studentid, club, role, department, program, permissions } = req.body;

  try {
    // Ensure permissions column exists
    await pool.query(`ALTER TABLE officers ADD COLUMN IF NOT EXISTS permissions JSONB`);
    const clubResult = await pool.query("SELECT id FROM clubs WHERE name = $1 LIMIT 1", [club]);
    const club_id = clubResult.rows[0]?.id || null;

    let perms = null;
    try { perms = permissions ? JSON.parse(permissions) : null; } catch (_) { perms = null; }
    if (!perms) {
      // default based on role
      const r = (role || '').toLowerCase();
      const actions = { view:false, create:false, update:false, edit:false, delete:false };
      const modules = { attendance:false };
      if (r === 'president' || r === 'chair' || r === 'admin') { Object.keys(actions).forEach(k => actions[k]=true); modules.attendance=true; }
      else if (r === 'secretary') { actions.view=actions.create=actions.update=true; modules.attendance=true; }
      else if (r === 'vp' || r === 'vice president') { actions.view=actions.create=actions.update=actions.edit=true; modules.attendance=true; }
      else { actions.view=true; }
      perms = { actions, modules };
    }

    await pool.query(
      `INSERT INTO officers (name, studentid, club_id, role, department, program, permissions, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
      [name, studentid, club_id, role, department, program, JSON.stringify(perms)]
    );
    res.redirect("/admin/officers");
  } catch (error) {
    console.error("Error adding officer:", error);
    res.render("admin/addOfficer", {
      title: "Add Officer | UniClub Admin",
      error: "Failed to add officer. Please check the details.",
      clubs: [],
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
    const result = await pool.query("SELECT * FROM clubs ORDER BY created_at DESC");
    res.render("admin/clubs", {
      title: "Manage Clubs | UniClub Admin",
      clubs: result.rows || [],
      currentPath: "/admin/clubs",
      messages: [],
    });
  } catch (error) {
    console.error("Error loading clubs:", error);
    res.status(500).send("Server error");
  }
});

// ✅ Add Club Form
router.get("/clubs/add", (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");
  res.render("admin/addClub", { title: "Add Club | UniClub Admin", error: null, currentPath: "/admin/clubs", messages: [] });
});

// ✅ Handle Add Club
router.post("/clubs/add", async (req, res) => {
  const { name, description, adviser, department, program, status } = req.body;

  try {
    await pool.query(
      `INSERT INTO clubs (name, description, adviser, department, program, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
      [name, description, adviser, department, program, status]
    );
    res.redirect("/admin/clubs");
  } catch (error) {
    console.error("Error adding club:", error);
    res.render("admin/addClub", {
      title: "Add Club | UniClub Admin",
      error: "Failed to add club",
    });
  }
});

// ✅ Edit Club Form
router.get("/clubs/edit/:id", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const result = await pool.query("SELECT * FROM clubs WHERE id = $1", [req.params.id]);
    if (result.rows.length === 0) return res.redirect("/admin/clubs");

    res.render("admin/editClub", {
      title: "Edit Club | UniClub Admin",
      club: result.rows[0],
      error: null,
      currentPath: "/admin/clubs",
      messages: [],
    });
  } catch (error) {
    console.error("Error loading club for edit:", error);
    res.status(500).send("Server error");
  }
});

// ✅ Handle Edit Club
router.post("/clubs/edit/:id", async (req, res) => {
  const { name, description, adviser, department, program, status } = req.body;
  const id = req.params.id;

  try {
    await pool.query(
      `UPDATE clubs
       SET name = $1, description = $2, adviser = $3,
           department = $4, program = $5, status = $6
       WHERE id = $7`,
      [name, description, adviser, department, program, status, id]
    );
    res.redirect("/admin/clubs");
  } catch (error) {
    console.error("Error updating club:", error);
    res.render("admin/editClub", {
      title: "Edit Club | UniClub Admin",
      club: { id, name, description, adviser, department, program, status },
      error: "Failed to update club",
    });
  }
});

// ✅ Delete Club
router.post("/clubs/delete/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM clubs WHERE id = $1", [req.params.id]);
    res.redirect("/admin/clubs");
  } catch (error) {
    console.error("Error deleting club:", error);
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
               COALESCE(NULLIF(e.status, ''), 'Scheduled') AS status
        FROM events e
        LEFT JOIN clubs c ON c.id = e.club_id
        ORDER BY e.date ASC NULLS LAST, e.created_at DESC
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

// Handle add requirement
router.post("/requirements/add", async (req, res) => {
  const { requirement, club_id, due_date, status } = req.body;

  try {
    await pool.query(
      `INSERT INTO requirements (requirement, club_id, due_date, status, created_at)
       VALUES ($1, $2, $3, $4, NOW())`,
      [requirement, club_id, due_date, status]
    );
    res.redirect("/admin/requirements");
  } catch (error) {
    console.error("Error adding requirement:", error);
    res.status(500).send("Server error while adding requirement.");
  }
});

// Edit requirement form
router.get("/requirements/edit/:id", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const [requirement, clubs] = await Promise.all([
      pool.query("SELECT * FROM requirements WHERE id = $1", [req.params.id]),
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
router.post("/requirements/edit/:id", async (req, res) => {
  const { requirement, club_id, due_date, status } = req.body;

  try {
    await pool.query(
      `UPDATE requirements 
       SET requirement = $1, club_id = $2, due_date = $3, status = $4 
       WHERE id = $5`,
      [requirement, club_id, due_date, status, req.params.id]
    );
    res.redirect("/admin/requirements");
  } catch (error) {
    console.error("Error updating requirement:", error);
    res.status(500).send("Server error.");
  }
});

// Delete requirement
router.post("/requirements/delete/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM requirements WHERE id = $1", [req.params.id]);
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
      "SELECT id, sender_name, sender_email, subject, content, created_at, read FROM messages ORDER BY created_at DESC"
    );
    res.render("admin/messages", {
      title: "Messages | UniClub Admin",
      messages: result.rows || [],
      currentPath: "/admin/messages",
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
    const result = await pool.query("SELECT * FROM messages WHERE id = $1", [id]);

    if (result.rows.length === 0) return res.redirect("/admin/messages");

    // Mark message as read
    await pool.query("UPDATE messages SET read = true WHERE id = $1", [id]);

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
router.post("/messages/delete/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM messages WHERE id = $1", [req.params.id]);
    res.redirect("/admin/messages");
  } catch (error) {
    console.error("Error deleting message:", error);
    res.status(500).send("Server error");
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

// Handle Add Event
router.post("/events/add", async (req, res) => {
  const { name, club_id, date, location, description } = req.body;

  try {
    await pool.query(
      `INSERT INTO events (name, club_id, date, location, description, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())`,
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

// Edit Event Form
router.get("/events/edit/:id", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const [event, clubs] = await Promise.all([
      pool.query("SELECT * FROM events WHERE id = $1", [req.params.id]),
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
router.post("/events/edit/:id", async (req, res) => {
  const { name, club_id, date, location, description } = req.body;

  try {
    await pool.query(
      `UPDATE events 
       SET name = $1, club_id = $2, date = $3, location = $4, description = $5 
       WHERE id = $6`,
      [name, club_id, date, location, description, req.params.id]
    );
    res.redirect("/admin/events");
  } catch (error) {
    console.error("Error updating event:", error);
    res.status(500).send("Server error");
  }
});

// Delete Event
router.post("/events/delete/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM events WHERE id = $1", [req.params.id]);
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
    const { type = "overview", startDate, endDate, club_id, status } = req.query;

    let reportData = {};
    let reportTitle = "Reports Overview";

    // Get available clubs for filtering
    const clubsResult = await pool.query("SELECT id, name FROM clubs ORDER BY name").catch(() => ({ rows: [] }));

    // Overview report
    if (type === "overview" || !type) {
      const [
        studentsCount,
        clubsCount,
        eventsCount,
        officersCount,
        requirementsCount,
        messagesCount,
      ] = await Promise.all([
        pool.query("SELECT COUNT(*) AS count FROM students").catch(() => ({ rows: [{ count: 0 }] })),
        pool.query("SELECT COUNT(*) AS count FROM clubs").catch(() => ({ rows: [{ count: 0 }] })),
        pool.query("SELECT COUNT(*) AS count FROM events").catch(() => ({ rows: [{ count: 0 }] })),
        pool.query("SELECT COUNT(*) AS count FROM officers").catch(() => ({ rows: [{ count: 0 }] })),
        pool.query("SELECT COUNT(*) AS count FROM requirements").catch(() => ({ rows: [{ count: 0 }] })),
        pool.query("SELECT COUNT(*) AS count FROM messages").catch(() => ({ rows: [{ count: 0 }] })),
      ]);

      reportData = {
        students: Number(studentsCount.rows[0]?.count || 0),
        clubs: Number(clubsCount.rows[0]?.count || 0),
        events: Number(eventsCount.rows[0]?.count || 0),
        officers: Number(officersCount.rows[0]?.count || 0),
        requirements: Number(requirementsCount.rows[0]?.count || 0),
        messages: Number(messagesCount.rows[0]?.count || 0),
      };
      reportTitle = "Overview Report";
    }

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
        query += ` AND e.status = $${++paramCount}`;
        params.push(status);
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

      query += " ORDER BY o.name ASC";
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
        query += ` AND e.status = $${++paramCount}`;
        params.push(status);
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

      query += " ORDER BY o.name ASC";
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
