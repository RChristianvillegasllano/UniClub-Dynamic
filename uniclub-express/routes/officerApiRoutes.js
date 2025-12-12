import express from "express";
import pool from "../config/db.js";
import { requireOfficer } from "./officerAuthRoutes.js";
import { hasPermission, canAccessPage } from "../config/tierPermissions.js";
import { protectResource, protectClubResource } from "../middleware/authorization.js";

const router = express.Router();

router.use(requireOfficer);

// Helper middleware to check permissions for API actions
function requireApiPermission(permission) {
  return async (req, res, next) => {
    try {
      const officer = req.session?.officer;
      if (!officer) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      const role = officer.role || '';
      
      if (!hasPermission(role, permission)) {
        console.log(`[API Permission Denied] Officer ${officer.id} (${role}) attempted action requiring permission: ${permission}`);
        return res.status(403).json({ 
          error: "You don't have permission to perform this action based on your role." 
        });
      }

      next();
    } catch (error) {
      console.error("Error checking API permission:", error);
      return res.status(500).json({ error: "Server error" });
    }
  };
}

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
  // Check if officer has access to attendance
  // Note: All officers can access 'home', so checking it is redundant
  // Only check attendance permission directly
  const role = (req.session.officer.role || '').toLowerCase();
  if (!canAccessPage(role, 'attendance')) {
    return res.status(403).json({ error: "You don't have permission to view attendance" });
  }
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

router.post("/attendance", requireApiPermission('create_attendance'), async (req, res) => {
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

router.patch("/attendance/:id", requireApiPermission('edit_attendance'), async (req, res) => {
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

// Mark RSVP student as Present or Absent
router.post("/attendance/rsvp/:eventId/:studentId", requireApiPermission('create_attendance'), async (req, res) => {
  try {
    const clubId = req.session.officer.club_id;
    const { status } = req.body; // 'Present' or 'Absent'
    const eventId = parseInt(req.params.eventId);
    const studentId = parseInt(req.params.studentId);
    
    if (!status || !['Present', 'Absent'].includes(status)) {
      return res.status(400).json({ error: "status must be 'Present' or 'Absent'" });
    }
    
    if (!eventId || isNaN(eventId) || !studentId || isNaN(studentId)) {
      return res.status(400).json({ error: "Invalid event ID or student ID" });
    }
    
    // Verify event belongs to the officer's club
    const { rows: eventRows } = await pool.query(
      `SELECT id, name FROM events WHERE id = ? AND club_id = ?`,
      [eventId, clubId]
    );
    
    if (eventRows.length === 0) {
      return res.status(404).json({ error: "Event not found" });
    }
    
    // Get student name
    const { rows: studentRows } = await pool.query(
      `SELECT id, CONCAT(first_name, ' ', last_name) as student_name, studentid
       FROM students WHERE id = ?`,
      [studentId]
    );
    
    if (studentRows.length === 0) {
      return res.status(404).json({ error: "Student not found" });
    }
    
    const studentName = studentRows[0].student_name;
    const eventName = eventRows[0].name;
    
    // Check if student has RSVP'd to this event
    const { rows: rsvpRows } = await pool.query(
      `SELECT id FROM event_attendance WHERE event_id = ? AND student_id = ?`,
      [eventId, studentId]
    );
    
    if (rsvpRows.length === 0) {
      return res.status(404).json({ error: "Student has not RSVP'd to this event" });
    }
    
    // Ensure attended column exists in event_attendance
    try {
      await pool.query(`ALTER TABLE event_attendance ADD COLUMN attended TINYINT(1) DEFAULT NULL`);
    } catch (err) {
      if (err.code !== 'ER_DUP_FIELDNAME' && err.errno !== 1060) {
        console.error('Error adding attended column:', err);
      }
    }
    
    // Ensure attendance_status column exists (to store 'Present' or 'Absent')
    try {
      await pool.query(`ALTER TABLE event_attendance ADD COLUMN attendance_status VARCHAR(20) DEFAULT NULL`);
    } catch (err) {
      if (err.code !== 'ER_DUP_FIELDNAME' && err.errno !== 1060) {
        console.error('Error adding attendance_status column:', err);
      }
    }
    
    // Check previous attendance status to handle point adjustments
    const { rows: previousRows } = await pool.query(
      `SELECT attendance_status FROM event_attendance WHERE event_id = ? AND student_id = ?`,
      [eventId, studentId]
    );
    const previousStatus = previousRows[0]?.attendance_status;
    
    // Update event_attendance with attendance status
    await pool.query(
      `UPDATE event_attendance 
       SET attended = ?, attendance_status = ?, updated_at = NOW()
       WHERE event_id = ? AND student_id = ?`,
      [status === 'Present' ? 1 : 0, status, eventId, studentId]
    );
    
    // Award points if marked as Present (and not already awarded for this event)
    if (status === 'Present') {
      try {
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
        } catch (createError) {
          // Table might already exist, continue
          if (createError.code !== 'ER_TABLE_EXISTS_ERROR' && createError.errno !== 1050) {
            console.error('[Points] Error creating student_points table:', createError.message);
          }
        }
        
        // Check if points were already awarded for this specific event attendance
        const existingPoints = await pool.query(
          `SELECT id FROM student_points 
           WHERE student_id = ? AND source = ? AND description LIKE ?`,
          [studentId, 'event_attendance', `%event_id:${eventId}%`]
        ).catch((e) => {
          console.error('[Points] Error checking existing points:', e.message);
          return { rows: [] };
        });
        
        // Only award points if they haven't been awarded for this event yet
        if (existingPoints.rows.length === 0) {
          // Award 5 points for attending an event
          const pointsAwarded = 5;
          await pool.query(
            `INSERT INTO student_points (student_id, points, source, description, created_at)
             VALUES (?, ?, 'event_attendance', ?, NOW())`,
            [studentId, pointsAwarded, `Attended event: ${eventName} (event_id:${eventId})`]
          );
          console.log(`[Points] Awarded ${pointsAwarded} points to student ${studentId} for attending event ${eventId} (${eventName})`);
        } else {
          console.log(`[Points] Points already awarded to student ${studentId} for event ${eventId}, skipping`);
        }
      } catch (pointsError) {
        // Log error but don't fail the attendance update
        console.error('[Points] Error awarding points for attendance:', pointsError.message);
      }
    }
    
    // Get updated record
    const { rows: updatedRows } = await pool.query(
      `SELECT 
        id, 
        event_id, 
        student_id, 
        status as rsvp_status,
        attended,
        attendance_status,
        created_at,
        updated_at
       FROM event_attendance
       WHERE event_id = ? AND student_id = ?`,
      [eventId, studentId]
    );
    
    res.json({ 
      success: true,
      attendance: {
        id: updatedRows[0].id,
        event_id: eventId,
        student_id: studentId,
        student_name: studentName,
        event_name: eventName,
        status: status,
        attended: status === 'Present' ? 1 : 0,
        updated_at: updatedRows[0].updated_at
      },
      message: `${studentName} marked as ${status}`
    });
  } catch (error) {
    console.error("Officer API mark RSVP attendance error:", error);
    res.status(500).json({ error: "Failed to mark attendance" });
  }
});

router.get("/applications", async (req, res) => {
  // Check if officer has access to members
  // Note: All officers can access 'home', so checking it is redundant
  // Only check members permission directly
  const role = (req.session.officer.role || '').toLowerCase();
  if (!canAccessPage(role, 'members')) {
    return res.status(403).json({ error: "You don't have permission to view applications" });
  }
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

router.patch("/applications/:id", requireApiPermission('approve_applications'), async (req, res) => {
  try {
    const clubId = req.session.officer.club_id;
    const { status } = req.body;
    const { id } = req.params;
    const role = (req.session.officer.role || '').toLowerCase();
    
    // Double-check permission
    if (!hasPermission(role, 'approve_applications')) {
      return res.status(403).json({ 
        success: false, 
        error: "You don't have permission to approve or reject applications." 
      });
    }
    
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


























