// routes/officerRoutes.js
import express from "express";
import pool from "../config/db.js";

const router = express.Router();

// Get all officers
router.get("/", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM officers ORDER BY id ASC");
    res.json(rows);
  } catch (err) {
    console.error("Error fetching officers:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// Add new officer
router.post("/", async (req, res) => {
  try {
    const { name, birthday, student_id, department, program, club, role, permissions } = req.body;
    // MySQL doesn't support RETURNING, so insert then fetch
    await pool.query(
      `INSERT INTO officers (name, birthday, student_id, department, program, club, role, permissions)
       VALUES (?,?,?,?,?,?,?,?)`,
      [name, birthday, student_id, department, program, club, role, permissions]
    );
    // Fetch the inserted record
    const { rows } = await pool.query(
      `SELECT * FROM officers WHERE id = LAST_INSERT_ID()`
    );
    res.json(rows[0]);
  } catch (err) {
    console.error("Error inserting officer:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// Update officer
router.put("/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { name, birthday, student_id, department, program, club, role, permissions } = req.body;
    await pool.query(
      `UPDATE officers SET name=?, birthday=?, student_id=?, department=?, program=?, club=?, role=?, permissions=? WHERE id=?`,
      [name, birthday, student_id, department, program, club, role, permissions, id]
    );
    res.json({ message: "Officer updated successfully" });
  } catch (err) {
    console.error("Error updating officer:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// Delete officer
router.delete("/:id", async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query("DELETE FROM officers WHERE id=?", [id]);
    res.json({ message: "Officer deleted successfully" });
  } catch (err) {
    console.error("Error deleting officer:", err);
    res.status(500).json({ error: "Database error" });
  }
});

export default router;
