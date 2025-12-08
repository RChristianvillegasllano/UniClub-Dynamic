import express from "express";
import pool from "../config/db.js";
import { requireOfficer } from "./officerAuthRoutes.js";

const router = express.Router();

router.use(requireOfficer);

router.get("/profile", (req, res) => {
  res.json({ officer: req.session.officer });
});

router.get("/announcements", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, subject AS title, content AS message, audience, created_at
         FROM announcements
        ORDER BY created_at DESC LIMIT 50`
    );
    res.json({ announcements: rows });
  } catch (error) {
    console.error("Officer API announcements error:", error);
    res.status(500).json({ error: "Failed to load announcements" });
  }
});

router.get("/club", async (req, res) => {
  try {
    const clubId = req.session.officer.club_id;
    if (!clubId) return res.json({ club: null });

    const { rows } = await pool.query(
      `SELECT id, name, description, adviser, category, department, program, status
         FROM clubs WHERE id = ?`,
      [clubId]
    );
    res.json({ club: rows[0] || null });
  } catch (error) {
    console.error("Officer API club error:", error);
    res.status(500).json({ error: "Failed to load club" });
  }
});

router.get("/attendance", async (req, res) => {
  try {
    const clubId = req.session.officer.club_id;
    const { rows } = await pool.query(
      `SELECT id, member_name, status, created_at
         FROM attendance
        WHERE club_id = ?
        ORDER BY created_at DESC`,
      [clubId]
    );
    res.json({ attendance: rows });
  } catch (error) {
    console.error("Officer API attendance error:", error);
    res.status(500).json({ error: "Failed to load attendance" });
  }
});

router.post("/attendance", async (req, res) => {
  try {
    const clubId = req.session.officer.club_id;
    const { member_name, status = "Not Marked" } = req.body;
    if (!member_name) return res.status(400).json({ error: "member_name is required" });

    // MySQL doesn't support RETURNING, so insert then fetch
    await pool.query(
      `INSERT INTO attendance (club_id, member_name, status)
       VALUES (?, ?, ?)`,
      [clubId, member_name, status]
    );
    // Fetch the inserted record
    const { rows } = await pool.query(
      `SELECT id, member_name, status, created_at
       FROM attendance
       WHERE id = LAST_INSERT_ID()`
    );
    res.status(201).json({ attendance: rows[0] });
  } catch (error) {
    console.error("Officer API add attendance error:", error);
    res.status(500).json({ error: "Failed to add attendance" });
  }
});

router.patch("/attendance/:id", async (req, res) => {
  try {
    const clubId = req.session.officer.club_id;
    const { status } = req.body;
    const { id } = req.params;
    if (!status) return res.status(400).json({ error: "status is required" });

    // MySQL doesn't support RETURNING, so update then fetch
    await pool.query(
      `UPDATE attendance
          SET status = ?
        WHERE id = ? AND club_id = ?`,
      [status, id, clubId]
    );
    // Fetch the updated record
    const { rows } = await pool.query(
      `SELECT id, member_name, status, created_at
       FROM attendance
       WHERE id = ? AND club_id = ?`,
      [id, clubId]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Attendance not found" });
    res.json({ attendance: rows[0] });
  } catch (error) {
    console.error("Officer API update attendance error:", error);
    res.status(500).json({ error: "Failed to update attendance" });
  }
});

router.get("/applications", async (req, res) => {
  try {
    const clubId = req.session.officer.club_id;
    const { rows } = await pool.query(
      `SELECT id, name, applying_for, current_clubs, status, created_at
         FROM membership_applications
        WHERE club_id = ?
        ORDER BY created_at DESC`,
      [clubId]
    );
    res.json({ applications: rows });
  } catch (error) {
    console.error("Officer API applications error:", error);
    res.status(500).json({ error: "Failed to load applications" });
  }
});

router.patch("/applications/:id", async (req, res) => {
  try {
    const clubId = req.session.officer.club_id;
    const { status } = req.body;
    const { id } = req.params;
    
    if (!status) {
      return res.status(400).json({ success: false, error: "status is required" });
    }

    if (!['approved', 'rejected', 'pending'].includes(status.toLowerCase())) {
      return res.status(400).json({ success: false, error: "Invalid status. Must be 'approved', 'rejected', or 'pending'" });
    }

    // First, get the application to check if it exists and get student info
    // Note: Using ? for MySQL (the db wrapper converts $1, $2 to ?)
    const { rows: appRows } = await pool.query(
      `SELECT id, name, student_id, applying_for, current_clubs, status, created_at
       FROM membership_applications
       WHERE id = ? AND club_id = ?`,
      [id, clubId]
    );

    if (appRows.length === 0) {
      return res.status(404).json({ success: false, error: "Application not found" });
    }

    const application = appRows[0];

    // Update the application status
    await pool.query(
      `UPDATE membership_applications
          SET status = ?
        WHERE id = ? AND club_id = ?`,
      [status, id, clubId]
    );

    // If approved and student_id exists, ensure the student is linked to the club
    if (status.toLowerCase() === 'approved' && application.student_id) {
      try {
        // Check if club_members table exists and add student if it does
        // This is optional - the membership_applications table with status='approved' 
        // can serve as the source of truth for club membership
        // Note: MySQL doesn't support ON CONFLICT, using INSERT IGNORE or checking first
        await pool.query(
          `INSERT IGNORE INTO club_members (student_id, club_id, joined_at, status)
           VALUES (?, ?, NOW(), 'active')`,
          [application.student_id, clubId]
        ).catch(() => {
          // If club_members table doesn't exist, that's okay
          // The membership_applications table with status='approved' is sufficient
        });
      } catch (memberError) {
        // Ignore errors related to club_members table - it's optional
        console.log("Note: club_members table may not exist, using membership_applications as source of truth");
      }

      // Award 5 points for joining a club
      try {
        console.log(`[Points] Attempting to award points for student ${application.student_id}, application ${id}, club ${clubId}`);
        
        if (!application.student_id) {
          console.warn(`[Points] No student_id in application ${id}, cannot award points`);
        } else {
          // Ensure student_points table exists
          try {
            await pool.query(`
              CREATE TABLE IF NOT EXISTS student_points (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id INT NOT NULL,
                points INT NOT NULL DEFAULT 0,
                source VARCHAR(100) NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_student_id (student_id),
                INDEX idx_created_at (created_at)
              )
            `);
            console.log(`[Points] student_points table ensured to exist`);
          } catch (createError) {
            console.error(`[Points] Error creating student_points table:`, createError.message);
            // Continue anyway - table might already exist
          }
          
          // First, check if points were already awarded for this application
          const existingPoints = await pool.query(
            `SELECT id FROM student_points 
             WHERE student_id = ? AND source = ? AND description LIKE ?`,
            [application.student_id, 'club_join', `%application_id:${id}%`]
          ).catch((e) => {
            console.error(`[Points] Error checking existing points:`, e.message);
            return { rows: [] };
          });

          console.log(`[Points] Existing points check: ${existingPoints.rows.length} records found`);

          // Only award points if they haven't been awarded for this specific application
          if (existingPoints.rows.length === 0) {
            // Get club name for description
            const clubResult = await pool.query(
              `SELECT name FROM clubs WHERE id = ?`,
              [clubId]
            ).catch((e) => {
              console.error(`[Points] Error fetching club name:`, e.message);
              return { rows: [] };
            });
            
            const clubName = clubResult.rows[0]?.name || 'Club';
            
            // Award 5 points
            try {
              const insertResult = await pool.query(
                `INSERT INTO student_points (student_id, points, source, description, created_at)
                 VALUES (?, 5, 'club_join', ?, NOW())`,
                [application.student_id, `Joined ${clubName} (application_id:${id})`]
              );
              
              console.log(`[Points] ✅ Successfully awarded 5 points to student ${application.student_id} for joining club ${clubId} (${clubName})`);
            } catch (insertError) {
              console.error(`[Points] ❌ Error inserting points:`, insertError.message);
              console.error(`[Points] SQL Error Code:`, insertError.code);
              console.error(`[Points] SQL Error Number:`, insertError.errno);
            }
          } else {
            console.log(`[Points] Points already awarded for application ${id}, skipping`);
          }
        }
      } catch (pointsError) {
        // If student_points table creation or insertion fails, log but don't fail
        console.error("[Points] ❌ Error in points awarding process:", pointsError.message);
        console.error("[Points] Error stack:", pointsError.stack);
      }
    }

    // Fetch the updated record
    const { rows: updatedRows } = await pool.query(
      `SELECT id, name, student_id, applying_for, current_clubs, status, created_at
       FROM membership_applications
       WHERE id = ? AND club_id = ?`,
      [id, clubId]
    );

    if (updatedRows.length === 0) {
      return res.status(404).json({ success: false, error: "Application not found after update" });
    }

    res.json({ 
      success: true, 
      application: updatedRows[0],
      message: `Application ${status === 'approved' ? 'approved' : status === 'rejected' ? 'rejected' : 'updated'} successfully`
    });
  } catch (error) {
    console.error("Officer API update application error:", error);
    res.status(500).json({ 
      success: false, 
      error: "Failed to update application",
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

export default router;


























