// routes/officerRoutes.js
import express from "express";
import pool from "../config/db.js";

const router = express.Router();

// ✅ View Officers Page
router.get("/", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const result = await pool.query("SELECT * FROM officers ORDER BY id ASC");
    res.render("admin/officers", {
      title: "Manage Officers | UniClub Admin",
      officers: result.rows,
    });
  } catch (error) {
    console.error("Error loading officers:", error);
    res.status(500).send("Server error");
  }
});

// ✅ Add Officer Form
router.get("/add", (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");
  res.render("admin/addOfficer", { title: "Add Officer", error: null });
});

// ✅ Handle Add Officer
router.post("/add", async (req, res) => {
  const { name, studentid, club, role } = req.body;

  try {
    await pool.query(
      "INSERT INTO officers (name, studentid, club, role) VALUES ($1, $2, $3, $4)",
      [name, studentid, club, role]
    );
    res.redirect("/admin/officers");
  } catch (error) {
    console.error("Error adding officer:", error);
    res.render("admin/addOfficer", { title: "Add Officer", error: "Failed to add officer" });
  }
});

// ✅ Edit Officer Form
router.get("/edit/:id", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const result = await pool.query("SELECT * FROM officers WHERE id = $1", [req.params.id]);
    if (result.rows.length === 0) return res.redirect("/admin/officers");

    res.render("admin/editOfficer", {
      title: "Edit Officer",
      officer: result.rows[0],
      error: null,
    });
  } catch (error) {
    console.error("Error loading officer for edit:", error);
    res.status(500).send("Server error");
  }
});

// ✅ Handle Edit Officer
router.post("/edit/:id", async (req, res) => {
  const { name, studentid, club, role } = req.body;
  const id = req.params.id;

  try {
    await pool.query(
      "UPDATE officers SET name = $1, studentid = $2, club = $3, role = $4 WHERE id = $5",
      [name, studentid, club, role, id]
    );
    res.redirect("/admin/officers");
  } catch (error) {
    console.error("Error updating officer:", error);
    res.render("admin/editOfficer", {
      title: "Edit Officer",
      officer: { id, name, studentid, club, role },
      error: "Failed to update officer",
    });
  }
});

// ✅ Delete Officer
router.post("/delete/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM officers WHERE id = $1", [req.params.id]);
    res.redirect("/admin/officers");
  } catch (error) {
    console.error("Error deleting officer:", error);
    res.status(500).send("Server error");
  }
});

export default router;
