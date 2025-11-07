import express from "express";
import pool from "../config/db.js";

const router = express.Router();

// ✅ View Clubs (Admin UI)
router.get("/manage", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM clubs ORDER BY id ASC");
    res.render("admin/clubs", { title: "Manage Clubs | UniClub", clubs: rows });
  } catch (err) {
    console.error("Error loading clubs:", err);
    res.status(500).send("Server Error");
  }
});

// ✅ Add Club Form
router.get("/add", (req, res) => {
  res.render("admin/addClub", { title: "Add Club | UniClub", error: null });
});

// ✅ Handle Add Club
router.post("/add", async (req, res) => {
  const { name, description, adviser, department } = req.body;
  try {
    await pool.query(
      "INSERT INTO clubs (name, description, adviser, department) VALUES ($1,$2,$3,$4)",
      [name, description, adviser, department]
    );
    res.redirect("/clubs/manage");
  } catch (err) {
    console.error("Error adding club:", err);
    res.render("admin/addClub", { error: "Failed to add club" });
  }
});

// ✅ Edit Club Form
router.get("/edit/:id", async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM clubs WHERE id=$1", [req.params.id]);
    res.render("admin/editClub", { title: "Edit Club | UniClub", club: rows[0], error: null });
  } catch (err) {
    console.error("Error loading club:", err);
    res.status(500).send("Server Error");
  }
});

// ✅ Handle Edit Club
router.post("/edit/:id", async (req, res) => {
  const { name, description, adviser, department } = req.body;
  try {
    await pool.query(
      "UPDATE clubs SET name=$1, description=$2, adviser=$3, department=$4 WHERE id=$5",
      [name, description, adviser, department, req.params.id]
    );
    res.redirect("/clubs/manage");
  } catch (err) {
    console.error("Error updating club:", err);
    res.render("admin/editClub", { error: "Failed to update club" });
  }
});

// ✅ Delete Club
router.post("/delete/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM clubs WHERE id=$1", [req.params.id]);
    res.redirect("/clubs/manage");
  } catch (err) {
    console.error("Error deleting club:", err);
    res.status(500).send("Server Error");
  }
});

export default router;
