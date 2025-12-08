// routes/officerRoutes.js
import express from "express";
import bcrypt from "bcryptjs";
import { body, validationResult } from "express-validator";
import pool from "../config/db.js";
import { writeLimiter, csrfProtection } from "../middleware/security.js";

const router = express.Router();

// Apply CSRF protection to all POST/PUT/DELETE routes
router.use(csrfProtection);

// ✅ View Officers Page
router.get("/", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const [officersResult, clubsResult] = await Promise.all([
      pool.query(
        `SELECT o.*, c.name AS club_name
           FROM officers o
           LEFT JOIN clubs c ON c.id = o.club_id
          ORDER BY o.id ASC`
      ),
      pool.query("SELECT id, name FROM clubs ORDER BY name"),
    ]);
    res.render("admin/officers", {
      title: "Manage Officers | UniClub Admin",
      officers: officersResult.rows,
      clubs: clubsResult.rows,
    });
  } catch (error) {
    console.error("Error loading officers:", error);
    res.status(500).send("Server error");
  }
});

// ✅ Add Officer Form
router.get("/add", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const { rows: clubs } = await pool.query("SELECT id, name FROM clubs ORDER BY name");
    res.render("admin/addOfficer", {
      title: "Add Officer",
      error: null,
      clubs,
      formData: null,
    });
  } catch (error) {
    console.error("Error loading clubs for officer add:", error);
    res.render("admin/addOfficer", {
      title: "Add Officer",
      error: "Unable to load clubs",
      clubs: [],
      formData: null,
    });
  }
});

// ✅ Handle Add Officer
router.post("/add", writeLimiter, async (req, res) => {
  const {
    name,
    studentid,
    club_id,
    role,
    username,
    password,
    department,
    program,
    photo_url,
    permissions = "{}",
  } = req.body;

  try {
    const password_hash = await bcrypt.hash(password, 10);
    const rawPermissions = permissions && permissions.trim() ? permissions : "{}";
    let permissionsValue = "{}";
    try {
      permissionsValue = JSON.stringify(JSON.parse(rawPermissions));
    } catch (err) {
      permissionsValue = "{}";
    }

    await pool.query(
      `INSERT INTO officers (
         name, studentid, club_id, role, department, program,
         username, password_hash, photo_url, permissions
       )
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        name,
        studentid,
        club_id ? Number(club_id) : null,
        role,
        department || null,
        program || null,
        username,
        password_hash,
        photo_url || null,
        permissionsValue,
      ]
    );
    res.redirect("/admin/officers");
  } catch (error) {
    console.error("Error adding officer:", error);
    const { rows: clubs } = await pool.query("SELECT id, name FROM clubs ORDER BY name").catch(() => ({ rows: [] }));
    res.render("admin/addOfficer", {
      title: "Add Officer",
      error: "Failed to add officer",
      clubs,
      formData: req.body,
    });
  }
});

// ✅ Edit Officer Form
router.get("/edit/:id", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const [officerResult, clubsResult] = await Promise.all([
      pool.query("SELECT * FROM officers WHERE id = ?", [req.params.id]),
      pool.query("SELECT id, name FROM clubs ORDER BY name"),
    ]);

    if (officerResult.rows.length === 0) return res.redirect("/admin/officers");

    const officer = officerResult.rows[0];

    res.render("admin/editOfficer", {
      title: "Edit Officer",
      officer,
      clubs: clubsResult.rows,
      error: null,
      formData: null,
    });
  } catch (error) {
    console.error("Error loading officer for edit:", error);
    res.status(500).send("Server error");
  }
});

// ✅ Handle Edit Officer
router.post("/edit/:id", writeLimiter, async (req, res) => {
  const id = Number(req.params.id);
  const {
    name,
    studentid,
    club_id,
    role,
    username,
    password,
    department,
    program,
    photo_url,
    permissions = "{}",
  } = req.body;

  try {
    const existingRes = await pool.query("SELECT password_hash FROM officers WHERE id = ?", [id]);
    if (!existingRes.rows.length) return res.redirect("/admin/officers");

    let password_hash = existingRes.rows[0].password_hash;
    if (password && password.trim()) {
      password_hash = await bcrypt.hash(password, 10);
    }

    const rawPermissions = permissions && permissions.trim() ? permissions : "{}";
    let permissionsValue = "{}";
    try {
      permissionsValue = JSON.stringify(JSON.parse(rawPermissions));
    } catch (err) {
      permissionsValue = "{}";
    }

    await pool.query(
      `UPDATE officers
          SET name = ?,
              studentid = ?,
              club_id = ?,
              role = ?,
              department = ?,
              program = ?,
              username = ?,
              password_hash = ?,
              photo_url = ?,
              permissions = ?
        WHERE id = ?`,
      [
        name,
        studentid,
        club_id ? Number(club_id) : null,
        role,
        department || null,
        program || null,
        username,
        password_hash,
        photo_url || null,
        permissionsValue,
        id,
      ]
    );
    res.redirect("/admin/officers");
  } catch (error) {
    console.error("Error updating officer:", error);
    const [officerResult, clubsResult] = await Promise.all([
      pool.query("SELECT * FROM officers WHERE id = ?", [id]).catch(() => ({ rows: [{ id }] })),
      pool.query("SELECT id, name FROM clubs ORDER BY name").catch(() => ({ rows: [] })),
    ]);
    const officer = officerResult.rows[0] || { id };
    res.render("admin/editOfficer", {
      title: "Edit Officer",
      officer,
      clubs: clubsResult.rows,
      error: "Failed to update officer",
      formData: req.body,
    });
  }
});

// ✅ Delete Officer
router.post("/delete/:id", writeLimiter, async (req, res) => {
  try {
    await pool.query("DELETE FROM officers WHERE id = ?", [req.params.id]);
    res.redirect("/admin/officers");
  } catch (error) {
    console.error("Error deleting officer:", error);
    res.status(500).send("Server error");
  }
});

export default router;
