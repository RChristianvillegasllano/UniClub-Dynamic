// routes/eventRoutes.js
import express from "express";
import pool from "../config/db.js";

const router = express.Router();

/* ===============================
   🎉 EVENT MANAGEMENT (Admin Panel)
================================= */

// View All Events
router.get("/", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const result = await pool.query("SELECT * FROM events ORDER BY date DESC");
    res.render("admin/events", {
      title: "Manage Events | UniClub Admin",
      events: result.rows || [],
    });
  } catch (err) {
    console.error("Error fetching events:", err);
    res.status(500).send("Server error while loading events.");
  }
});

// Add Event Form
router.get("/add", (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");
  res.render("admin/addEvent", {
    title: "Add Event | UniClub Admin",
    error: null,
  });
});

// Handle Add Event
router.post("/add", async (req, res) => {
  const { name, club, date, location, description, status } = req.body;

  try {
    await pool.query(
      "INSERT INTO events (name, club, date, location, description, status, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())",
      [name, club, date, location, description, status]
    );
    res.redirect("/admin/events");
  } catch (err) {
    console.error("Error adding event:", err);
    res.render("admin/addEvent", {
      title: "Add Event | UniClub Admin",
      error: "Failed to add event. Please check input fields.",
    });
  }
});

// Edit Event Form
router.get("/edit/:id", async (req, res) => {
  if (!req.session?.admin) return res.redirect("/admin/login");

  try {
    const result = await pool.query("SELECT * FROM events WHERE id = ?", [req.params.id]);
    if (result.rows.length === 0) return res.redirect("/admin/events");

    res.render("admin/editEvent", {
      title: "Edit Event | UniClub Admin",
      event: result.rows[0],
      error: null,
    });
  } catch (err) {
    console.error("Error fetching event for edit:", err);
    res.status(500).send("Server error.");
  }
});

// Handle Edit Event
router.post("/edit/:id", async (req, res) => {
  const { name, club, date, location, description, status } = req.body;

  try {
    await pool.query(
      "UPDATE events SET name=?, club=?, date=?, location=?, description=?, status=? WHERE id=?",
      [name, club, date, location, description, status, req.params.id]
    );
    res.redirect("/admin/events");
  } catch (err) {
    console.error("Error updating event:", err);
    res.render("admin/editEvent", {
      title: "Edit Event | UniClub Admin",
      event: { id: req.params.id, name, club, date, location, description, status },
      error: "Failed to update event.",
    });
  }
});

// Delete Event
router.post("/delete/:id", async (req, res) => {
  try {
    await pool.query("DELETE FROM events WHERE id = ?", [req.params.id]);
    res.redirect("/admin/events");
  } catch (err) {
    console.error("Error deleting event:", err);
    res.status(500).send("Server error while deleting event.");
  }
});

export default router;
