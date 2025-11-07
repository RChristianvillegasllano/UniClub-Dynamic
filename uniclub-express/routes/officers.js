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
    const { rows } = await pool.query(
      `INSERT INTO officers (name, birthday, student_id, department, program, club, role, permissions)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [name, birthday, student_id, department, program, club, role, permissions]
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
      `UPDATE officers SET name=$1, birthday=$2, student_id=$3, department=$4, program=$5, club=$6, role=$7, permissions=$8 WHERE id=$9`,
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
    await pool.query("DELETE FROM officers WHERE id=$1", [id]);
    res.json({ message: "Officer deleted successfully" });
  } catch (err) {
    console.error("Error deleting officer:", err);
    res.status(500).json({ error: "Database error" });
  }
});

export default router;
