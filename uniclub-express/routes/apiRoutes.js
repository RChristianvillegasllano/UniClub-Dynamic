// routes/apiRoutes.js
import express from "express";
import { body, validationResult } from "express-validator";
import pool from "../config/db.js";
import { writeLimiter, apiLimiter } from "../middleware/security.js";

const router = express.Router();

// Apply API rate limiting to all routes
router.use(apiLimiter);

// Middleware to check admin authentication for protected routes
const requireAdmin = (req, res, next) => {
  if (!req.session?.admin) {
    return res.status(401).json({ error: "Unauthorized. Admin login required." });
  }
  next();
};

// Helper function to set cache headers
const setCacheHeaders = (res, maxAge = 60) => {
  res.set("Cache-Control", `public, max-age=${maxAge}`);
};

/* ===============================
   📊 DASHBOARD API
================================= */

// Get dashboard statistics
router.get("/dashboard", requireAdmin, async (req, res) => {
  try {
    // Parallel queries for better performance
    const [
      studentsR,
      clubsR,
      eventsR,
      recentR,
      clubsListR,
      officersR,
      activitiesR,
      requirementsR,
      messagesR,
    ] = await Promise.all([
      pool.query("SELECT COUNT(*) AS count FROM students").catch(() => ({ rows: [{ count: 0 }] })),
      pool.query("SELECT COUNT(*) AS count FROM clubs").catch(() => ({ rows: [{ count: 0 }] })),
      pool.query("SELECT COUNT(*) AS count FROM events").catch(() => ({ rows: [{ count: 0 }] })),
      pool
        .query(
          `SELECT id, first_name, last_name, CONCAT(first_name, ' ', last_name) AS name, created_at FROM students ORDER BY created_at DESC LIMIT 6`
        )
        .catch(() => ({ rows: [] })),
      pool
        .query("SELECT id, name, department, adviser FROM clubs ORDER BY name LIMIT 8")
        .catch(() => ({ rows: [] })),
      pool
        .query(
          "SELECT id, first_name, last_name, CONCAT(first_name, ' ', last_name) AS name, studentid, club_id, role, department, program FROM officers ORDER BY last_name, first_name LIMIT 8"
        )
        .catch(() => ({ rows: [] })),
      pool
        .query(
          "SELECT id, activity, club, date, location, status FROM activities ORDER BY date DESC LIMIT 8"
        )
        .catch(() => ({ rows: [] })),
      pool
        .query(
          "SELECT id, requirement, club, due_date, status FROM requirements ORDER BY due_date DESC LIMIT 10"
        )
        .catch(() => ({ rows: [] })),
      pool
        .query(
          `SELECT id, sender_name AS \`from\`, subject, content, created_at, \`read\` FROM messages ORDER BY created_at DESC LIMIT 8`
        )
        .catch(() => ({ rows: [] })),
    ]);

    const studentsCount = Number(studentsR.rows[0]?.count || 0);
    const clubsCount = Number(clubsR.rows[0]?.count || 0);
    const eventsCount = Number(eventsR.rows[0]?.count || 0);

    res.json({
      success: true,
      data: {
        counts: {
          students: studentsCount,
          clubs: clubsCount,
          events: eventsCount,
        },
        recentStudents: recentR.rows || [],
        clubs: clubsListR.rows || [],
        officers: officersR.rows || [],
        activities: activitiesR.rows || [],
        requirements: requirementsR.rows || [],
        messages: messagesR.rows || [],
        analytics: {
          activeClubs: clubsCount,
          avgOfficersPerClub:
            clubsCount > 0 ? Math.round((officersR.rows.length || 0) / clubsCount) : 0,
          totalActivities: activitiesR.rows.length || 0,
        },
      },
    });
  } catch (error) {
    console.error("Error loading dashboard:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

/* ===============================
   👥 STUDENTS API
================================= */

// Get all students
router.get("/students", requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50, search = "" } = req.query;
    const offset = (page - 1) * limit;

    let query = "SELECT * FROM students";
    let params = [];
    let paramCount = 0;

    if (search) {
      const searchLower = `%${search.toLowerCase()}%`;
      query += ` WHERE (LOWER(first_name) LIKE ? OR LOWER(last_name) LIKE ? OR LOWER(CONCAT(first_name, ' ', last_name)) LIKE ? OR studentid LIKE ?)`;
      params.push(searchLower, searchLower, searchLower, `%${search}%`);
    }

    query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const result = await pool.query(query, params);
    const countResult = await pool.query(
      search
        ? "SELECT COUNT(*) FROM students WHERE (LOWER(first_name) LIKE ? OR LOWER(last_name) LIKE ? OR LOWER(CONCAT(first_name, ' ', last_name)) LIKE ? OR studentid LIKE ?)"
        : "SELECT COUNT(*) FROM students",
      search ? [`%${search.toLowerCase()}%`, `%${search.toLowerCase()}%`, `%${search.toLowerCase()}%`, `%${search}%`] : []
    );

    setCacheHeaders(res, 30);
    res.json({
      success: true,
      data: result.rows,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: Number(countResult.rows[0].count),
        totalPages: Math.ceil(Number(countResult.rows[0].count) / limit),
      },
    });
  } catch (error) {
    console.error("Error fetching students:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Get single student
router.get("/students/:id", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM students WHERE id = ?", [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Student not found" });
    }
    setCacheHeaders(res, 60);
    res.json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error fetching student:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Create student
router.post("/students", requireAdmin, writeLimiter, async (req, res) => {
  try {
    const { first_name, last_name, studentid, email, department, program, year } = req.body;
    
    // Check if student ID already exists
    const studentIdCheck = await pool.query(
      "SELECT id FROM students WHERE studentid = ?",
      [studentid]
    );
    if (studentIdCheck.rows.length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: "A student with this Student ID already exists. Student ID must be unique." 
      });
    }

    // Check if first name + last name combination already exists
    // Note: This only rejects when BOTH first name AND last name match
    // Examples: "John Doe" + "John Smith" = ACCEPTED (same first, different last)
    //           "John Doe" + "Jane Doe" = ACCEPTED (same last, different first)
    //           "John Doe" + "John Doe" = REJECTED (both match)
    const nameCheck = await pool.query(
      "SELECT id, studentid FROM students WHERE LOWER(TRIM(first_name)) = LOWER(TRIM(?)) AND LOWER(TRIM(last_name)) = LOWER(TRIM(?))",
      [first_name, last_name]
    );
    if (nameCheck.rows.length > 0) {
      const existingStudent = nameCheck.rows[0];
      return res.status(400).json({ 
        success: false, 
        error: `A student with the name "${first_name} ${last_name}" already exists (Student ID: ${existingStudent.studentid || 'N/A'}). Each student must have a unique name combination.` 
      });
    }
    
    const result = await pool.query(
      "INSERT INTO students (first_name, last_name, studentid, email, department, program, year_level, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())",
      [first_name, last_name, studentid, email, department, program, year]
    );
    // MySQL doesn't support RETURNING, so fetch the inserted record
    const inserted = await pool.query("SELECT * FROM students WHERE id = LAST_INSERT_ID()");
    result.rows = inserted.rows;
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error creating student:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Update student
router.put("/students/:id", requireAdmin, writeLimiter, async (req, res) => {
  try {
    const { first_name, last_name, studentid, email, department, program, year } = req.body;
    const studentId = req.params.id;
    
    // Check if student ID already exists (excluding current student)
    const studentIdCheck = await pool.query(
      "SELECT id FROM students WHERE studentid = ? AND id != ?",
      [studentid, studentId]
    );
    if (studentIdCheck.rows.length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: "A student with this Student ID already exists. Student ID must be unique." 
      });
    }

    // Check if first name + last name combination already exists (excluding current student)
    // Note: This only rejects when BOTH first name AND last name match
    // Examples: "John Doe" + "John Smith" = ACCEPTED (same first, different last)
    //           "John Doe" + "Jane Doe" = ACCEPTED (same last, different first)
    //           "John Doe" + "John Doe" = REJECTED (both match)
    const nameCheck = await pool.query(
      "SELECT id, studentid FROM students WHERE LOWER(TRIM(first_name)) = LOWER(TRIM(?)) AND LOWER(TRIM(last_name)) = LOWER(TRIM(?)) AND id != ?",
      [first_name, last_name, studentId]
    );
    if (nameCheck.rows.length > 0) {
      const existingStudent = nameCheck.rows[0];
      return res.status(400).json({ 
        success: false, 
        error: `A student with the name "${first_name} ${last_name}" already exists (Student ID: ${existingStudent.studentid || 'N/A'}). Each student must have a unique name combination.` 
      });
    }
    
    await pool.query(
      "UPDATE students SET first_name=?, last_name=?, studentid=?, email=?, department=?, program=?, year_level=? WHERE id=?",
      [first_name, last_name, studentid, email, department, program, year, studentId]
    );
    // MySQL doesn't support RETURNING, so fetch the updated record
    const result = await pool.query("SELECT * FROM students WHERE id = ?", [studentId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Student not found" });
    }
    res.json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error updating student:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Delete student
router.delete("/students/:id", requireAdmin, writeLimiter, async (req, res) => {
  try {
    const result = await pool.query("SELECT id FROM students WHERE id = ?", [req.params.id]);
    if (result.rows.length > 0) {
      await pool.query("DELETE FROM students WHERE id = ?", [req.params.id]);
    }
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Student not found" });
    }
    res.json({ success: true, message: "Student deleted successfully" });
  } catch (error) {
    console.error("Error deleting student:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

/* ===============================
   🏛️ CLUBS API
================================= */

// Get all clubs
router.get("/clubs", async (req, res) => {
  try {
    const { page = 1, limit = 50, search = "" } = req.query;
    const offset = (page - 1) * limit;

    let query = "SELECT * FROM clubs";
    let params = [];
    let paramCount = 0;

    if (search) {
      const searchLower = `%${search.toLowerCase()}%`;
      query += ` WHERE LOWER(name) LIKE ? OR LOWER(department) LIKE ?`;
      params.push(searchLower, searchLower);
    }

    query += ` ORDER BY name ASC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const result = await pool.query(query, params);
    const countResult = await pool.query(
      search
        ? "SELECT COUNT(*) FROM clubs WHERE LOWER(name) LIKE ? OR LOWER(department) LIKE ?"
        : "SELECT COUNT(*) FROM clubs",
      search ? [`%${search.toLowerCase()}%`, `%${search.toLowerCase()}%`] : []
    );

    setCacheHeaders(res, 120);
    res.json({
      success: true,
      data: result.rows,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: Number(countResult.rows[0].count),
        totalPages: Math.ceil(Number(countResult.rows[0].count) / limit),
      },
    });
  } catch (error) {
    console.error("Error fetching clubs:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Get single club
router.get("/clubs/:id", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM clubs WHERE id = ?", [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Club not found" });
    }
    setCacheHeaders(res, 120);
    res.json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error fetching club:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Create club
router.post("/clubs", requireAdmin, writeLimiter, async (req, res) => {
  try {
    const { name, description, adviser, department, category } = req.body;
    await pool.query(
      "INSERT INTO clubs (name, description, adviser, department, category) VALUES (?, ?, ?, ?, ?)",
      [name, description, adviser, department, category]
    );
    // MySQL doesn't support RETURNING, so fetch the inserted record
    const inserted = await pool.query("SELECT * FROM clubs WHERE id = LAST_INSERT_ID()");
    const result = { rows: inserted.rows };
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error creating club:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Update club
router.put("/clubs/:id", requireAdmin, writeLimiter, async (req, res) => {
  try {
    const { name, description, adviser, department, category } = req.body;
    await pool.query(
      "UPDATE clubs SET name=?, description=?, adviser=?, department=?, category=? WHERE id=?",
      [name, description, adviser, department, category, req.params.id]
    );
    // MySQL doesn't support RETURNING, so fetch the updated record
    const result = await pool.query("SELECT * FROM clubs WHERE id = ?", [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Club not found" });
    }
    res.json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error updating club:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Delete club
router.delete("/clubs/:id", requireAdmin, writeLimiter, async (req, res) => {
  try {
    const result = await pool.query("SELECT id FROM clubs WHERE id = ?", [req.params.id]);
    if (result.rows.length > 0) {
      await pool.query("DELETE FROM clubs WHERE id = ?", [req.params.id]);
    }
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Club not found" });
    }
    res.json({ success: true, message: "Club deleted successfully" });
  } catch (error) {
    console.error("Error deleting club:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

/* ===============================
   👔 OFFICERS API
================================= */

// Get all officers
router.get("/officers", async (req, res) => {
  try {
    const { page = 1, limit = 50, search = "", club_id } = req.query;
    const offset = (page - 1) * limit;

    let query =
      "SELECT o.*, c.name AS club_name FROM officers o LEFT JOIN clubs c ON o.club_id = c.id";
    let params = [];
    let paramCount = 0;
    const conditions = [];

    if (search) {
      const searchLower = `%${search.toLowerCase()}%`;
      conditions.push(`(LOWER(o.first_name) LIKE ? OR LOWER(o.last_name) LIKE ? OR LOWER(CONCAT(o.first_name, ' ', o.last_name)) LIKE ? OR o.studentid LIKE ?)`);
      params.push(searchLower, searchLower, searchLower, `%${search}%`);
    }

    if (club_id) {
      conditions.push(`o.club_id = ?`);
      params.push(club_id);
    }

    if (conditions.length > 0) {
      query += " WHERE " + conditions.join(" AND ");
    }

    query += ` ORDER BY o.last_name ASC, o.first_name ASC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const result = await pool.query(query, params);
    
    // Build count query with same conditions
    let countQuery = "SELECT COUNT(*) FROM officers o";
    const countParams = [];
    const countConditions = [];
    
    if (search) {
      const searchLower = `%${search.toLowerCase()}%`;
      countConditions.push(`(LOWER(o.first_name) LIKE ? OR LOWER(o.last_name) LIKE ? OR LOWER(CONCAT(o.first_name, ' ', o.last_name)) LIKE ? OR o.studentid LIKE ?)`);
      countParams.push(searchLower, searchLower, searchLower, `%${search}%`);
    }
    
    if (club_id) {
      countConditions.push(`o.club_id = ?`);
      countParams.push(club_id);
    }
    
    if (countConditions.length > 0) {
      countQuery += " WHERE " + countConditions.join(" AND ");
    }
    
    const countResult = await pool.query(countQuery, countParams);

    setCacheHeaders(res, 60);
    res.json({
      success: true,
      data: result.rows,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: Number(countResult.rows[0].count),
        totalPages: Math.ceil(Number(countResult.rows[0].count) / limit),
      },
    });
  } catch (error) {
    console.error("Error fetching officers:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Get single officer
router.get("/officers/:id", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT o.*, c.name AS club_name FROM officers o LEFT JOIN clubs c ON o.club_id = c.id WHERE o.id = ?",
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Officer not found" });
    }
    setCacheHeaders(res, 60);
    res.json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error fetching officer:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Create officer
router.post("/officers", requireAdmin, writeLimiter, async (req, res) => {
  try {
    const { first_name, last_name, studentid, club_id, role, department, program, permissions } = req.body;
    
    // Check if student ID already exists
    const studentIdCheck = await pool.query(
      "SELECT id FROM officers WHERE studentid = ?",
      [studentid]
    );
    if (studentIdCheck.rows.length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: "An officer with this Student ID already exists. Student ID must be unique." 
      });
    }

    // Check if first name + last name combination already exists
    // Note: This only rejects when BOTH first name AND last name match
    // Examples: "John Doe" + "John Smith" = ACCEPTED (same first, different last)
    //           "John Doe" + "Jane Doe" = ACCEPTED (same last, different first)
    //           "John Doe" + "John Doe" = REJECTED (both match)
    const nameCheck = await pool.query(
      "SELECT id, studentid FROM officers WHERE LOWER(TRIM(first_name)) = LOWER(TRIM(?)) AND LOWER(TRIM(last_name)) = LOWER(TRIM(?))",
      [first_name, last_name]
    );
    if (nameCheck.rows.length > 0) {
      const existingOfficer = nameCheck.rows[0];
      return res.status(400).json({ 
        success: false, 
        error: `An officer with the name "${first_name} ${last_name}" already exists (Student ID: ${existingOfficer.studentid || 'N/A'}). Each officer must have a unique name combination.` 
      });
    }
    
    await pool.query(
      `INSERT INTO officers (first_name, last_name, studentid, club_id, role, department, program, permissions) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [first_name, last_name, studentid, club_id, role, department, program, permissions ? JSON.stringify(permissions) : null]
    );
    // MySQL doesn't support RETURNING, so fetch the inserted record
    const inserted = await pool.query("SELECT * FROM officers WHERE id = LAST_INSERT_ID()");
    const result = { rows: inserted.rows };
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error creating officer:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Update officer
router.put("/officers/:id", requireAdmin, writeLimiter, async (req, res) => {
  try {
    const { first_name, last_name, studentid, club_id, role, department, program, permissions } = req.body;
    const officerId = req.params.id;
    
    // Check if student ID already exists (excluding current officer)
    const studentIdCheck = await pool.query(
      "SELECT id FROM officers WHERE studentid = ? AND id != ?",
      [studentid, officerId]
    );
    if (studentIdCheck.rows.length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: "An officer with this Student ID already exists. Student ID must be unique." 
      });
    }

    // Check if first name + last name combination already exists (excluding current officer)
    // Note: This only rejects when BOTH first name AND last name match
    // Examples: "John Doe" + "John Smith" = ACCEPTED (same first, different last)
    //           "John Doe" + "Jane Doe" = ACCEPTED (same last, different first)
    //           "John Doe" + "John Doe" = REJECTED (both match)
    const nameCheck = await pool.query(
      "SELECT id, studentid FROM officers WHERE LOWER(TRIM(first_name)) = LOWER(TRIM(?)) AND LOWER(TRIM(last_name)) = LOWER(TRIM(?)) AND id != ?",
      [first_name, last_name, officerId]
    );
    if (nameCheck.rows.length > 0) {
      const existingOfficer = nameCheck.rows[0];
      return res.status(400).json({ 
        success: false, 
        error: `An officer with the name "${first_name} ${last_name}" already exists (Student ID: ${existingOfficer.studentid || 'N/A'}). Each officer must have a unique name combination.` 
      });
    }
    
    await pool.query(
      `UPDATE officers SET first_name=?, last_name=?, studentid=?, club_id=?, role=?, department=?, program=?, permissions=? 
       WHERE id=?`,
      [
        first_name,
        last_name,
        studentid,
        club_id,
        role,
        department,
        program,
        permissions ? JSON.stringify(permissions) : null,
        officerId,
      ]
    );
    // MySQL doesn't support RETURNING, so fetch the updated record
    const result = await pool.query("SELECT * FROM officers WHERE id = ?", [officerId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Officer not found" });
    }
    res.json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error updating officer:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Delete officer
router.delete("/officers/:id", requireAdmin, writeLimiter, async (req, res) => {
  try {
    const result = await pool.query("SELECT id FROM officers WHERE id = ?", [req.params.id]);
    if (result.rows.length > 0) {
      await pool.query("DELETE FROM officers WHERE id = ?", [req.params.id]);
    }
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Officer not found" });
    }
    res.json({ success: true, message: "Officer deleted successfully" });
  } catch (error) {
    console.error("Error deleting officer:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

/* ===============================
   🎉 EVENTS API
================================= */

// Get all events
router.get("/events", async (req, res) => {
  try {
    const { page = 1, limit = 50, search = "", status } = req.query;
    const offset = (page - 1) * limit;

    // Determine if we need to join with clubs table (for search by club name)
    const needsJoin = !!search;
    
    let query = needsJoin 
      ? "SELECT events.* FROM events LEFT JOIN clubs ON clubs.id = events.club_id"
      : "SELECT * FROM events";
    let params = [];
    const conditions = [];

    // Exclude pending and rejected events by default (unless explicitly requested)
    if (!status || (status !== 'pending_approval' && status !== 'rejected')) {
      conditions.push(`(COALESCE(events.status, 'pending_approval') != 'pending_approval' AND COALESCE(events.status, 'pending_approval') != 'rejected')`);
    }

    if (search) {
      const searchLower = `%${search.toLowerCase()}%`;
      conditions.push(`(LOWER(events.name) LIKE ? OR LOWER(clubs.name) LIKE ?)`);
      params.push(searchLower, searchLower);
    }

    if (status) {
      conditions.push(`COALESCE(events.status, 'pending_approval') = ?`);
      params.push(status);
    }

    if (conditions.length > 0) {
      query += " WHERE " + conditions.join(" AND ");
    }

    query += ` ORDER BY events.date DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const result = await pool.query(query, params);
    
    // Build count query with same conditions
    let countQuery = needsJoin
      ? "SELECT COUNT(*) FROM events LEFT JOIN clubs ON clubs.id = events.club_id"
      : "SELECT COUNT(*) FROM events";
    const countParams = [];
    const countConditions = [];
    
    // Exclude pending and rejected events by default (unless explicitly requested)
    if (!status || (status !== 'pending_approval' && status !== 'rejected')) {
      countConditions.push(`(COALESCE(events.status, 'pending_approval') != 'pending_approval' AND COALESCE(events.status, 'pending_approval') != 'rejected')`);
    }
    
    if (search) {
      const searchLower = `%${search.toLowerCase()}%`;
      countConditions.push(`(LOWER(events.name) LIKE ? OR LOWER(clubs.name) LIKE ?)`);
      countParams.push(searchLower, searchLower);
    }
    
    if (status) {
      countConditions.push(`COALESCE(events.status, 'pending_approval') = ?`);
      countParams.push(status);
    }
    
    if (countConditions.length > 0) {
      countQuery += " WHERE " + countConditions.join(" AND ");
    }
    
    const countResult = await pool.query(countQuery, countParams);

    setCacheHeaders(res, 60);
    res.json({
      success: true,
      data: result.rows,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: Number(countResult.rows[0].count),
        totalPages: Math.ceil(Number(countResult.rows[0].count) / limit),
      },
    });
  } catch (error) {
    console.error("Error fetching events:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Get single event
router.get("/events/:id", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM events WHERE id = ?", [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Event not found" });
    }
    setCacheHeaders(res, 60);
    res.json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error fetching event:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Create event
router.post("/events", requireAdmin, writeLimiter, async (req, res) => {
  try {
    const { name, club, date, location, description, status } = req.body;
    await pool.query(
      "INSERT INTO events (name, club, date, location, description, status, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())",
      [name, club, date, location, description, status]
    );
    // MySQL doesn't support RETURNING, so fetch the inserted record
    const inserted = await pool.query("SELECT * FROM events WHERE id = LAST_INSERT_ID()");
    const result = { rows: inserted.rows };
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error creating event:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Update event
router.put("/events/:id", requireAdmin, writeLimiter, async (req, res) => {
  try {
    const { name, club, date, location, description, status } = req.body;
    await pool.query(
      "UPDATE events SET name=?, club=?, date=?, location=?, description=?, status=? WHERE id=?",
      [name, club, date, location, description, status, req.params.id]
    );
    // MySQL doesn't support RETURNING, so fetch the updated record
    const result = await pool.query("SELECT * FROM events WHERE id = ?", [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Event not found" });
    }
    res.json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error updating event:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Delete event
router.delete("/events/:id", requireAdmin, writeLimiter, async (req, res) => {
  try {
    const result = await pool.query("SELECT id FROM events WHERE id = ?", [req.params.id]);
    if (result.rows.length > 0) {
      await pool.query("DELETE FROM events WHERE id = ?", [req.params.id]);
    }
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Event not found" });
    }
    res.json({ success: true, message: "Event deleted successfully" });
  } catch (error) {
    console.error("Error deleting event:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

/* ===============================
   📋 REQUIREMENTS API
================================= */

// Get all requirements
router.get("/requirements", async (req, res) => {
  try {
    const { page = 1, limit = 50, search = "", status } = req.query;
    const offset = (page - 1) * limit;

    let query =
      "SELECT r.*, c.name AS club_name FROM requirements r LEFT JOIN clubs c ON r.club_id = c.id";
    let params = [];
    let paramCount = 0;
    const conditions = [];

    if (search) {
      const searchLower = `%${search.toLowerCase()}%`;
      conditions.push(`LOWER(r.requirement) LIKE ?`);
      params.push(searchLower);
    }

    if (status) {
      conditions.push(`r.status = ?`);
      params.push(status);
    }

    if (conditions.length > 0) {
      query += " WHERE " + conditions.join(" AND ");
    }

    // MySQL doesn't support NULLS LAST, so use ISNULL to put NULLs at end
    query += ` ORDER BY ISNULL(r.due_date), r.due_date DESC, r.created_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const result = await pool.query(query, params);
    
    // Build count query with same conditions
    let countQuery = "SELECT COUNT(*) FROM requirements r";
    const countParams = [];
    const countConditions = [];
    
    if (search) {
      const searchLower = `%${search.toLowerCase()}%`;
      countConditions.push(`LOWER(r.requirement) LIKE ?`);
      countParams.push(searchLower);
    }
    
    if (status) {
      countConditions.push(`r.status = ?`);
      countParams.push(status);
    }
    
    if (countConditions.length > 0) {
      countQuery += " WHERE " + countConditions.join(" AND ");
    }
    
    const countResult = await pool.query(countQuery, countParams);

    setCacheHeaders(res, 60);
    res.json({
      success: true,
      data: result.rows,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: Number(countResult.rows[0].count),
        totalPages: Math.ceil(Number(countResult.rows[0].count) / limit),
      },
    });
  } catch (error) {
    console.error("Error fetching requirements:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Get single requirement
router.get("/requirements/:id", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT r.*, c.name AS club_name FROM requirements r LEFT JOIN clubs c ON r.club_id = c.id WHERE r.id = ?",
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Requirement not found" });
    }
    setCacheHeaders(res, 60);
    res.json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error fetching requirement:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Create requirement
router.post("/requirements", requireAdmin, writeLimiter, async (req, res) => {
  try {
    const { requirement, club_id, due_date, status } = req.body;
    await pool.query(
      "INSERT INTO requirements (requirement, club_id, due_date, status, created_at) VALUES (?, ?, ?, ?, NOW())",
      [requirement, club_id, due_date, status]
    );
    // MySQL doesn't support RETURNING, so fetch the inserted record
    const inserted = await pool.query("SELECT * FROM requirements WHERE id = LAST_INSERT_ID()");
    const result = { rows: inserted.rows };
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error creating requirement:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Update requirement
router.put("/requirements/:id", requireAdmin, writeLimiter, async (req, res) => {
  try {
    const { requirement, club_id, due_date, status } = req.body;
    await pool.query(
      "UPDATE requirements SET requirement=?, club_id=?, due_date=?, status=? WHERE id=?",
      [requirement, club_id, due_date, status, req.params.id]
    );
    // MySQL doesn't support RETURNING, so fetch the updated record
    const result = await pool.query("SELECT * FROM requirements WHERE id = ?", [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Requirement not found" });
    }
    res.json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error updating requirement:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Delete requirement
router.delete("/requirements/:id", requireAdmin, writeLimiter, async (req, res) => {
  try {
    const result = await pool.query("SELECT id FROM requirements WHERE id = ?", [req.params.id]);
    if (result.rows.length > 0) {
      await pool.query("DELETE FROM requirements WHERE id = ?", [req.params.id]);
    }
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Requirement not found" });
    }
    res.json({ success: true, message: "Requirement deleted successfully" });
  } catch (error) {
    console.error("Error deleting requirement:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

/* ===============================
   💬 MESSAGES API
================================= */

// Get all messages
router.get("/messages", requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50, read } = req.query;
    const offset = (page - 1) * limit;

    let query = 'SELECT id, sender_name AS `from`, subject, content, created_at, `read` FROM messages';
    let params = [];
    let paramCount = 0;

    if (read !== undefined) {
      query += ` WHERE \`read\` = ?`;
      params.push(read === "true");
    }

    query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const result = await pool.query(query, params);
    const countResult = await pool.query(
      read !== undefined
        ? `SELECT COUNT(*) FROM messages WHERE \`read\` = ?`
        : "SELECT COUNT(*) FROM messages",
      read !== undefined ? [read === "true"] : []
    );

    setCacheHeaders(res, 30);
    res.json({
      success: true,
      data: result.rows,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: Number(countResult.rows[0].count),
        totalPages: Math.ceil(Number(countResult.rows[0].count) / limit),
      },
    });
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Get single message
router.get("/messages/:id", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM messages WHERE id = ?', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Message not found" });
    }
    // Mark as read
    await pool.query("UPDATE messages SET `read` = true WHERE id = ?", [req.params.id]);
    setCacheHeaders(res, 0);
    res.json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error fetching message:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Delete message
router.delete("/messages/:id", requireAdmin, writeLimiter, async (req, res) => {
  try {
    const result = await pool.query("SELECT id FROM messages WHERE id = ?", [req.params.id]);
    if (result.rows.length > 0) {
      await pool.query("DELETE FROM messages WHERE id = ?", [req.params.id]);
    }
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Message not found" });
    }
    res.json({ success: true, message: "Message deleted successfully" });
  } catch (error) {
    console.error("Error deleting message:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

export default router;

