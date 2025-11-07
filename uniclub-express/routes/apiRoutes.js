// routes/apiRoutes.js
import express from "express";
import pool from "../config/db.js";

const router = express.Router();

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
          `SELECT id, name, created_at FROM students ORDER BY created_at DESC LIMIT 6`
        )
        .catch(() => ({ rows: [] })),
      pool
        .query("SELECT id, name, department, adviser FROM clubs ORDER BY name LIMIT 8")
        .catch(() => ({ rows: [] })),
      pool
        .query(
          "SELECT id, name, studentid, club_id, role, department, program FROM officers ORDER BY name LIMIT 8"
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
          `SELECT id, "from", subject, content, created_at, read FROM messages ORDER BY created_at DESC LIMIT 8`
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
      query += ` WHERE name ILIKE $${++paramCount} OR studentid ILIKE $${paramCount}`;
      params.push(`%${search}%`);
    }

    query += ` ORDER BY created_at DESC LIMIT $${++paramCount} OFFSET $${++paramCount}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);
    const countResult = await pool.query(
      search
        ? "SELECT COUNT(*) FROM students WHERE name ILIKE $1 OR studentid ILIKE $1"
        : "SELECT COUNT(*) FROM students",
      search ? [`%${search}%`] : []
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
    const result = await pool.query("SELECT * FROM students WHERE id = $1", [req.params.id]);
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
router.post("/students", requireAdmin, async (req, res) => {
  try {
    const { name, studentid, email, department, program, year } = req.body;
    const result = await pool.query(
      "INSERT INTO students (name, studentid, email, department, program, year, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING *",
      [name, studentid, email, department, program, year]
    );
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error creating student:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Update student
router.put("/students/:id", requireAdmin, async (req, res) => {
  try {
    const { name, studentid, email, department, program, year } = req.body;
    const result = await pool.query(
      "UPDATE students SET name=$1, studentid=$2, email=$3, department=$4, program=$5, year=$6 WHERE id=$7 RETURNING *",
      [name, studentid, email, department, program, year, req.params.id]
    );
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
router.delete("/students/:id", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query("DELETE FROM students WHERE id = $1 RETURNING id", [
      req.params.id,
    ]);
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
      query += ` WHERE name ILIKE $${++paramCount} OR department ILIKE $${paramCount}`;
      params.push(`%${search}%`);
    }

    query += ` ORDER BY name ASC LIMIT $${++paramCount} OFFSET $${++paramCount}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);
    const countResult = await pool.query(
      search
        ? "SELECT COUNT(*) FROM clubs WHERE name ILIKE $1 OR department ILIKE $1"
        : "SELECT COUNT(*) FROM clubs",
      search ? [`%${search}%`] : []
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
    const result = await pool.query("SELECT * FROM clubs WHERE id = $1", [req.params.id]);
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
router.post("/clubs", requireAdmin, async (req, res) => {
  try {
    const { name, description, adviser, department } = req.body;
    const result = await pool.query(
      "INSERT INTO clubs (name, description, adviser, department) VALUES ($1, $2, $3, $4) RETURNING *",
      [name, description, adviser, department]
    );
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error creating club:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Update club
router.put("/clubs/:id", requireAdmin, async (req, res) => {
  try {
    const { name, description, adviser, department } = req.body;
    const result = await pool.query(
      "UPDATE clubs SET name=$1, description=$2, adviser=$3, department=$4 WHERE id=$5 RETURNING *",
      [name, description, adviser, department, req.params.id]
    );
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
router.delete("/clubs/:id", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query("DELETE FROM clubs WHERE id = $1 RETURNING id", [
      req.params.id,
    ]);
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
      conditions.push(`(o.name ILIKE $${++paramCount} OR o.studentid ILIKE $${paramCount})`);
      params.push(`%${search}%`);
    }

    if (club_id) {
      conditions.push(`o.club_id = $${++paramCount}`);
      params.push(club_id);
    }

    if (conditions.length > 0) {
      query += " WHERE " + conditions.join(" AND ");
    }

    query += ` ORDER BY o.name ASC LIMIT $${++paramCount} OFFSET $${++paramCount}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);
    
    // Build count query with same conditions
    let countQuery = "SELECT COUNT(*) FROM officers o";
    const countParams = [];
    let countParamCount = 0;
    const countConditions = [];
    
    if (search) {
      countConditions.push(`(o.name ILIKE $${++countParamCount} OR o.studentid ILIKE $${countParamCount})`);
      countParams.push(`%${search}%`);
    }
    
    if (club_id) {
      countConditions.push(`o.club_id = $${++countParamCount}`);
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
      "SELECT o.*, c.name AS club_name FROM officers o LEFT JOIN clubs c ON o.club_id = c.id WHERE o.id = $1",
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
router.post("/officers", requireAdmin, async (req, res) => {
  try {
    const { name, studentid, club_id, role, department, program, permissions } = req.body;
    const result = await pool.query(
      `INSERT INTO officers (name, studentid, club_id, role, department, program, permissions) 
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [name, studentid, club_id, role, department, program, permissions ? JSON.stringify(permissions) : null]
    );
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error creating officer:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Update officer
router.put("/officers/:id", requireAdmin, async (req, res) => {
  try {
    const { name, studentid, club_id, role, department, program, permissions } = req.body;
    const result = await pool.query(
      `UPDATE officers SET name=$1, studentid=$2, club_id=$3, role=$4, department=$5, program=$6, permissions=$7 
       WHERE id=$8 RETURNING *`,
      [
        name,
        studentid,
        club_id,
        role,
        department,
        program,
        permissions ? JSON.stringify(permissions) : null,
        req.params.id,
      ]
    );
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
router.delete("/officers/:id", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query("DELETE FROM officers WHERE id = $1 RETURNING id", [
      req.params.id,
    ]);
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

    let query = "SELECT * FROM events";
    let params = [];
    let paramCount = 0;
    const conditions = [];

    if (search) {
      conditions.push(`(name ILIKE $${++paramCount} OR club ILIKE $${paramCount})`);
      params.push(`%${search}%`);
    }

    if (status) {
      conditions.push(`status = $${++paramCount}`);
      params.push(status);
    }

    if (conditions.length > 0) {
      query += " WHERE " + conditions.join(" AND ");
    }

    query += ` ORDER BY date DESC LIMIT $${++paramCount} OFFSET $${++paramCount}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);
    
    // Build count query with same conditions
    let countQuery = "SELECT COUNT(*) FROM events";
    const countParams = [];
    let countParamCount = 0;
    const countConditions = [];
    
    if (search) {
      countConditions.push(`(name ILIKE $${++countParamCount} OR club ILIKE $${countParamCount})`);
      countParams.push(`%${search}%`);
    }
    
    if (status) {
      countConditions.push(`status = $${++countParamCount}`);
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
    const result = await pool.query("SELECT * FROM events WHERE id = $1", [req.params.id]);
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
router.post("/events", requireAdmin, async (req, res) => {
  try {
    const { name, club, date, location, description, status } = req.body;
    const result = await pool.query(
      "INSERT INTO events (name, club, date, location, description, status, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING *",
      [name, club, date, location, description, status]
    );
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error creating event:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Update event
router.put("/events/:id", requireAdmin, async (req, res) => {
  try {
    const { name, club, date, location, description, status } = req.body;
    const result = await pool.query(
      "UPDATE events SET name=$1, club=$2, date=$3, location=$4, description=$5, status=$6 WHERE id=$7 RETURNING *",
      [name, club, date, location, description, status, req.params.id]
    );
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
router.delete("/events/:id", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query("DELETE FROM events WHERE id = $1 RETURNING id", [
      req.params.id,
    ]);
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
      conditions.push(`r.requirement ILIKE $${++paramCount}`);
      params.push(`%${search}%`);
    }

    if (status) {
      conditions.push(`r.status = $${++paramCount}`);
      params.push(status);
    }

    if (conditions.length > 0) {
      query += " WHERE " + conditions.join(" AND ");
    }

    query += ` ORDER BY r.due_date DESC NULLS LAST, r.created_at DESC LIMIT $${++paramCount} OFFSET $${++paramCount}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);
    
    // Build count query with same conditions
    let countQuery = "SELECT COUNT(*) FROM requirements r";
    const countParams = [];
    let countParamCount = 0;
    const countConditions = [];
    
    if (search) {
      countConditions.push(`r.requirement ILIKE $${++countParamCount}`);
      countParams.push(`%${search}%`);
    }
    
    if (status) {
      countConditions.push(`r.status = $${++countParamCount}`);
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
      "SELECT r.*, c.name AS club_name FROM requirements r LEFT JOIN clubs c ON r.club_id = c.id WHERE r.id = $1",
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
router.post("/requirements", requireAdmin, async (req, res) => {
  try {
    const { requirement, club_id, due_date, status } = req.body;
    const result = await pool.query(
      "INSERT INTO requirements (requirement, club_id, due_date, status, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING *",
      [requirement, club_id, due_date, status]
    );
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error creating requirement:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Update requirement
router.put("/requirements/:id", requireAdmin, async (req, res) => {
  try {
    const { requirement, club_id, due_date, status } = req.body;
    const result = await pool.query(
      "UPDATE requirements SET requirement=$1, club_id=$2, due_date=$3, status=$4 WHERE id=$5 RETURNING *",
      [requirement, club_id, due_date, status, req.params.id]
    );
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
router.delete("/requirements/:id", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query("DELETE FROM requirements WHERE id = $1 RETURNING id", [
      req.params.id,
    ]);
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

    let query = 'SELECT id, "from", subject, content, created_at, read FROM messages';
    let params = [];
    let paramCount = 0;

    if (read !== undefined) {
      query += ` WHERE read = $${++paramCount}`;
      params.push(read === "true");
    }

    query += ` ORDER BY created_at DESC LIMIT $${++paramCount} OFFSET $${++paramCount}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);
    const countResult = await pool.query(
      read !== undefined
        ? `SELECT COUNT(*) FROM messages WHERE read = $1`
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
    const result = await pool.query('SELECT * FROM messages WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Message not found" });
    }
    // Mark as read
    await pool.query("UPDATE messages SET read = true WHERE id = $1", [req.params.id]);
    setCacheHeaders(res, 0);
    res.json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Error fetching message:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Delete message
router.delete("/messages/:id", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query("DELETE FROM messages WHERE id = $1 RETURNING id", [
      req.params.id,
    ]);
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

