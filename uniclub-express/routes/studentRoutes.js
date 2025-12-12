// routes/studentRoutes.js
import express from "express";
import bcrypt from "bcryptjs";
import { body, validationResult } from "express-validator";
import pool from "../config/db.js";
import { loginLimiter, csrfProtection } from "../middleware/security.js";
import { 
  strictAuthLimiter,
  recordFailedAttempt,
  clearFailedAttempts,
  isAccountLocked,
  getLockoutTimeRemaining,
  logSecurityEvent
} from "../middleware/advancedSecurity.js";
import { updateEventStatuses } from "../utils/eventStatus.js";

const router = express.Router();

// Apply CSRF protection to all POST/PUT/DELETE routes in this router
router.use(csrfProtection);

// Name validation helper: only letters, spaces, hyphens, and apostrophes
function validateName(name, fieldName = "Name") {
  if (!name || typeof name !== 'string') {
    return { valid: false, error: `${fieldName} is required` };
  }
  
  const trimmed = name.trim();
  if (trimmed.length === 0) {
    return { valid: false, error: `${fieldName} cannot be empty` };
  }
  
  // Pattern: only letters, spaces, hyphens, and apostrophes
  const namePattern = /^[A-Za-z\s'-]+$/;
  
  // Check for potentially malicious content (excluding apostrophe which is allowed)
  const dangerousPatterns = /[<>\"&;{}[\]()=+*$%#@!`~|\\]/;
  
  if (dangerousPatterns.test(trimmed) || !namePattern.test(trimmed)) {
    return { 
      valid: false, 
      error: `${fieldName} contains invalid characters. Only letters, spaces, hyphens (-), and apostrophes (') are allowed.` 
    };
  }
  
  if (trimmed.length > 100) {
    return { valid: false, error: `${fieldName} must be 100 characters or less` };
  }
  
  return { valid: true, value: trimmed };
}

router.get("/", (_req, res) => {
  res.redirect("/student/login");
});

router.get("/login", (req, res) => {
  // Redirect if already logged in
  if (req.session?.student) {
    return res.redirect("/student/dashboard");
  }
  
  const signup = req.query.signup;
  // Get error from query string if present (e.g., from CSRF failure redirect)
  const error = req.query.error === 'csrf_invalid' 
    ? 'Security token expired. Please refresh the page and try again.' 
    : req.query.error || null;
  
  res.render("student/login", {
    title: "Student Portal | UniClub",
    signup: signup,
    error: error,
    csrfToken: res.locals.csrfToken || req.csrfToken?.() || '',
  });
});

router.post("/login", 
  strictAuthLimiter,
  loginLimiter,
  body('email').trim().isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('password').notEmpty().withMessage('Password is required'),
  async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render("student/login", {
      title: "Student Portal | UniClub",
      error: errors.array()[0].msg,
    });
  }

  const { email, password } = req.body;
  
  // Validate email and password (additional check)
  if (!email || !password) {
    return res.render("student/login", {
      title: "Student Portal | UniClub",
      error: "Email and password are required",
    });
  }

  // Normalize email and get client IP - must be defined before try block
  // Ensure email is a string before calling toLowerCase
  const normalizedEmail = (email && typeof email === 'string') ? email.toLowerCase().trim() : '';
  const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
  
  // Additional safety check - if normalizedEmail is empty after normalization, reject
  if (!normalizedEmail) {
    return res.render("student/login", {
      title: "Student Portal | UniClub",
      error: "Invalid email format",
    });
  }

  try {

    // Ensure password column exists
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS password VARCHAR(255)`);

    // Find student by email
    const { rows } = await pool.query(
      `SELECT 
         id,
         first_name,
         last_name,
         CONCAT(first_name, ' ', last_name) AS name,
         email,
         password,
         studentid,
         department,
         program,
         year_level,
         birthdate,
         profile_picture
       FROM students 
       WHERE email = ? 
       LIMIT 1`,
      [normalizedEmail]
    );

    const student = rows[0];
    
    // Check if student exists
    if (!student) {
      recordFailedAttempt(normalizedEmail, clientIP);
      logSecurityEvent('FAILED_LOGIN', { email: normalizedEmail, reason: 'User not found', ip: clientIP }, req);
      return res.render("student/login", {
        title: "Student Portal | UniClub",
        error: "Invalid email or password",
      });
    }

    // Check if password exists (for accounts created before password was added)
    if (!student.password) {
      recordFailedAttempt(normalizedEmail, clientIP);
      logSecurityEvent('FAILED_LOGIN', { email: normalizedEmail, reason: 'No password set', ip: clientIP }, req);
      return res.render("student/login", {
        title: "Student Portal | UniClub",
        error: "Account not set up. Please contact support or sign up again.",
      });
    }

    // Compare password
    const passwordMatch = await bcrypt.compare(password, student.password);
    
    if (!passwordMatch) {
      recordFailedAttempt(normalizedEmail, clientIP);
      logSecurityEvent('FAILED_LOGIN', { email: normalizedEmail, reason: 'Invalid password', ip: clientIP }, req);
      return res.render("student/login", {
        title: "Student Portal | UniClub",
        error: "Invalid email or password",
      });
    }
    
    // Clear failed attempts on successful login
    clearFailedAttempts(normalizedEmail, clientIP);
    logSecurityEvent('SUCCESSFUL_LOGIN', { email: normalizedEmail, studentId: student.id, ip: clientIP }, req);

    // Create session
    req.session.student = {
      id: student.id,
      name: student.name,
      first_name: student.first_name,
      last_name: student.last_name,
      email: student.email,
      studentid: student.studentid,
      department: student.department,
      program: student.program,
      year_level: student.year_level,
      birthdate: student.birthdate,
      profile_picture: student.profile_picture || null,
    };

    // Save session before redirecting to ensure CSRF secret persists
    req.session.save((err) => {
      if (err) {
        console.error("Error saving session during student login:", err);
        return res.render("student/login", { 
          title: "Student Portal | UniClub", 
          error: "Server error during login" 
        });
      }
      res.redirect("/student/dashboard");
    });
  } catch (error) {
    console.error("Student login error:", error);
    return res.render("student/login", {
      title: "Student Portal | UniClub",
      error: "An error occurred during login. Please try again.",
    });
  }
});

router.post("/logout", (req, res) => {
  // Properly destroy session server-side
  const sessionId = req.sessionID;
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying student session:", err);
    } else {
      console.log(`[LOGOUT] Student session ${sessionId} destroyed`);
    }
    // Clear cookie
    res.clearCookie('sessionId');
    res.redirect("/student/login");
  });
});

router.get("/logout", (req, res) => {
  // Properly destroy session server-side
  const sessionId = req.sessionID;
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
    } else {
      console.log(`[LOGOUT] Student session ${sessionId} destroyed`);
    }
    // Clear cookie
    res.clearCookie('sessionId');
    res.redirect("/student/login");
  });
});

router.get("/signup", (req, res) => {
  // Redirect if already logged in
  if (req.session?.student) {
    return res.redirect("/student/dashboard");
  }
  
  res.render("student/signup", {
    title: "Sign Up | UniClub",
  });
});

router.post("/signup", 
  body('first_name').trim().isLength({ min: 1, max: 100 }).matches(/^[A-Za-z\s'-]+$/).withMessage('First name must be 1-100 characters, letters, spaces, hyphens, and apostrophes only'),
  body('last_name').trim().isLength({ min: 1, max: 100 }).matches(/^[A-Za-z\s'-]+$/).withMessage('Last name must be 1-100 characters, letters, spaces, hyphens, and apostrophes only'),
  body('birthdate').isISO8601().withMessage('Valid birthdate is required'),
  body('studentid').matches(/^\d{6}$/).withMessage('Student ID must be exactly 6 digits'),
  body('department').notEmpty().trim().withMessage('Department is required'),
  body('program').notEmpty().trim().withMessage('Program is required'),
  body('year_level').isIn(['1', '2', '3', '4']).withMessage('Year level must be 1, 2, 3, or 4'),
  body('email').matches(/^[a-z]\.[a-z]+\.\d{6}\.tc@umindanao\.edu\.ph$/i).normalizeEmail().withMessage('Email must follow format: firstinitial.lastname.6digitid.tc@umindanao.edu.ph'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
  body('confirmPassword').custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error('Passwords do not match');
    }
    return true;
  }),
  async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render("student/signup", {
      title: "Sign Up | UniClub",
      error: errors.array()[0].msg,
    });
  }

  const { first_name, last_name, birthdate, studentid, department, program, year_level, email, password, confirmPassword } = req.body;

  try {
    // Validate first name
    const firstNameValidation = validateName(first_name, "First name");
    if (!firstNameValidation.valid) {
      return res.render("student/signup", {
        title: "Sign Up | UniClub",
        error: firstNameValidation.error,
      });
    }

    // Validate last name
    const lastNameValidation = validateName(last_name, "Last name");
    if (!lastNameValidation.valid) {
      return res.render("student/signup", {
        title: "Sign Up | UniClub",
        error: lastNameValidation.error,
      });
    }

    // Validate birthdate
    if (!birthdate) {
      return res.render("student/signup", {
        title: "Sign Up | UniClub",
        error: "Birthdate is required",
      });
    }

    // Validate student ID: exactly 6 digits
    if (!studentid || !/^\d{6}$/.test(studentid)) {
      return res.render("student/signup", {
        title: "Sign Up | UniClub",
        error: "Student ID is required and must be exactly 6 digits",
      });
    }

    // Validate department
    if (!department) {
      return res.render("student/signup", {
        title: "Sign Up | UniClub",
        error: "Department is required",
      });
    }

    // Validate program
    if (!program) {
      return res.render("student/signup", {
        title: "Sign Up | UniClub",
        error: "Program is required",
      });
    }

    // Validate year level
    if (!year_level || !['1', '2', '3', '4'].includes(year_level)) {
      return res.render("student/signup", {
        title: "Sign Up | UniClub",
        error: "Year level is required and must be 1, 2, 3, or 4",
      });
    }

    // Validate email format: firstinitial.lastname.6digits.tc@umindanao.edu.ph
    const emailPattern = /^[a-z]\.[a-z]+\.\d{6}\.tc@umindanao\.edu\.ph$/i;
    if (!email || !emailPattern.test(email)) {
      return res.render("student/signup", {
        title: "Sign Up | UniClub",
        error: "Email must follow format: firstinitial.lastname.6digitid.tc@umindanao.edu.ph (e.g., j.delacruz.111222.tc@umindanao.edu.ph)",
      });
    }

    // Validate password
    const trimmedPassword = password ? password.trim() : '';
    if (!trimmedPassword || trimmedPassword.length < 8) {
      return res.render("student/signup", {
        title: "Sign Up | UniClub",
        error: "Password is required and must be at least 8 characters long",
      });
    }

    // Validate password match
    const trimmedConfirmPassword = confirmPassword ? confirmPassword.trim() : '';
    if (trimmedPassword !== trimmedConfirmPassword) {
      return res.render("student/signup", {
        title: "Sign Up | UniClub",
        error: "Passwords do not match",
      });
    }

    // Ensure required columns exist
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS birthdate DATE`);
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS studentid VARCHAR(50)`);
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS department VARCHAR(100)`);
    await pool.query(`ALTER TABLE students ADD COLUMN IF NOT EXISTS password VARCHAR(255)`);

    // Check if email already exists
    const emailCheck = await pool.query(
      "SELECT id FROM students WHERE email = ?",
      [email.toLowerCase()]
    );
    if (emailCheck.rows.length > 0) {
      return res.render("student/signup", {
        title: "Sign Up | UniClub",
        error: "An account with this email already exists. Please use a different email or log in.",
      });
    }

    // Check if student ID already exists
    const studentIdCheck = await pool.query(
      "SELECT id FROM students WHERE studentid = ?",
      [studentid]
    );
    if (studentIdCheck.rows.length > 0) {
      return res.render("student/signup", {
        title: "Sign Up | UniClub",
        error: "An account with this Student ID already exists. Please contact support if you believe this is an error.",
      });
    }

    // Check if first name + last name combination already exists
    // Note: This only rejects when BOTH first name AND last name match
    // Examples: "John Doe" + "John Smith" = ACCEPTED (same first, different last)
    //           "John Doe" + "Jane Doe" = ACCEPTED (same last, different first)
    //           "John Doe" + "John Doe" = REJECTED (both match)
    const nameCheck = await pool.query(
      "SELECT id FROM students WHERE LOWER(TRIM(first_name)) = LOWER(TRIM(?)) AND LOWER(TRIM(last_name)) = LOWER(TRIM(?))",
      [firstNameValidation.value, lastNameValidation.value]
    );
    if (nameCheck.rows.length > 0) {
      return res.render("student/signup", {
        title: "Sign Up | UniClub",
        error: "An account with this name already exists. Please contact support if you believe this is an error.",
      });
    }

    // Hash password (use trimmed password)
    const hashedPassword = await bcrypt.hash(trimmedPassword, 10);

    // Ensure status column exists
    try {
      await pool.query(`ALTER TABLE students ADD COLUMN status VARCHAR(50) DEFAULT 'Active'`);
    } catch (err) {
      // Column already exists, ignore error
      if (err.code !== 'ER_DUP_FIELDNAME' && err.errno !== 1060) {
        console.error('Error adding status column:', err);
      }
    }

    // Insert student into database
    await pool.query(
      `INSERT INTO students (first_name, last_name, birthdate, studentid, department, program, year_level, email, password, status, created_at) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Active', NOW())`,
      [
        firstNameValidation.value,
        lastNameValidation.value,
        birthdate,
        studentid,
        department,
        program,
        year_level,
        email.toLowerCase(),
        hashedPassword
      ]
    );

    // Redirect to login with success message
    res.redirect("/student/login?signup=success");
  } catch (error) {
    console.error("Error during student signup:", error);
    
    // Check for unique constraint violations
    // MySQL error code 1062 = Duplicate entry, 23000 = Integrity constraint violation
    if (error.code === '1062' || error.code === '23000' || error.code === '23505') {
      const errorMessage = error.message || '';
      if (errorMessage.includes('email') || (error.constraint && error.constraint.includes('email'))) {
        return res.render("student/signup", {
          title: "Sign Up | UniClub",
          error: "An account with this email already exists. Please use a different email or log in.",
        });
      }
      if (errorMessage.includes('studentid') || (error.constraint && error.constraint.includes('studentid'))) {
        return res.render("student/signup", {
          title: "Sign Up | UniClub",
          error: "An account with this Student ID already exists. Please contact support if you believe this is an error.",
        });
      }
    }

    return res.render("student/signup", {
      title: "Sign Up | UniClub",
      error: "An error occurred during registration. Please try again later.",
    });
  }
});

// Middleware to require student authentication
export function requireStudent(req, res, next) {
  if (!req.session?.student) {
    return res.redirect("/student/login");
  }
  next();
}

router.get("/dashboard", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;
    
    // Get student's department for filtering
    const studentDepartment = (student?.department || '').trim();
    const studentDeptLower = studentDepartment.toLowerCase();
    const hasDepartment = studentDepartment && studentDepartment.trim() !== '';
    
    console.log(`[Dashboard] Filtering clubs for student department: "${studentDepartment}"`);
    
    // Get clubs filtered by: student's department OR category = 'Civic' OR category = 'Religious'
    // IMPORTANT: Only show clubs from student's department, or Civic/Religious categories
    // Do NOT show clubs from other departments, even if they have Academic or other categories
    let clubsResult;
    try {
      // Now get clubs with counts and member data (filtered by department)
      clubsResult = await pool.query(`
        SELECT 
          c.id,
          c.name,
          c.description,
          c.category,
          c.department,
          c.adviser,
          c.photo,
          COALESCE(c.status, 'Active') as status,
          COALESCE(o_counts.officer_count, 0) as officer_count,
          COALESCE(e_counts.event_count, 0) as event_count,
          COALESCE(m_counts.member_count, 0) as member_count,
          next_event.name as next_event_name,
          next_event.date as next_event_date,
          CASE 
            WHEN membership.student_id IS NOT NULL AND (membership.status = 'approved' OR membership.status = 'Approved') THEN 1
            ELSE 0
          END as is_member
        FROM clubs c
        LEFT JOIN (
          SELECT club_id, COUNT(*) as officer_count
          FROM officers
          GROUP BY club_id
        ) o_counts ON o_counts.club_id = c.id
        LEFT JOIN (
          SELECT club_id, COUNT(*) as event_count
          FROM events
          GROUP BY club_id
        ) e_counts ON e_counts.club_id = c.id
        LEFT JOIN (
          SELECT club_id, COUNT(*) as member_count
          FROM membership_applications
          WHERE status = 'approved' OR status = 'Approved'
          GROUP BY club_id
        ) m_counts ON m_counts.club_id = c.id
        LEFT JOIN (
          SELECT club_id, name, date
          FROM events
          WHERE date >= CURRENT_DATE
          ORDER BY date ASC
          LIMIT 1
        ) next_event ON next_event.club_id = c.id
        LEFT JOIN (
          SELECT student_id, club_id, status
          FROM membership_applications
          WHERE student_id = ?
          ORDER BY created_at DESC
        ) membership ON membership.club_id = c.id
        WHERE (c.status = 'Active' OR c.status IS NULL)
        AND (
          -- Show clubs from student's department (if department is provided and matches)
          (? = 1 AND c.department IS NOT NULL AND c.department != '' AND LOWER(TRIM(c.department)) = ?)
          OR
          -- Show Civic clubs (any department)
          LOWER(TRIM(COALESCE(c.category, ''))) = 'civic'
          OR
          -- Show Religious clubs (any department)
          LOWER(TRIM(COALESCE(c.category, ''))) = 'religious'
        )
        AND NOT (
          -- Exclude clubs from OTHER departments that are NOT Civic or Religious
          ? = 1
          AND c.department IS NOT NULL 
          AND c.department != ''
          AND LOWER(TRIM(c.department)) != ?
          AND LOWER(TRIM(COALESCE(c.category, ''))) NOT IN ('civic', 'religious')
        )
        ORDER BY c.name ASC
      `, [
        studentId,
        hasDepartment ? 1 : 0, 
        studentDeptLower,
        hasDepartment ? 1 : 0,
        studentDeptLower
      ]);
      console.log("Clubs query successful. Found clubs:", clubsResult.rows?.length || 0);
      if (clubsResult.rows && clubsResult.rows.length > 0) {
        console.log("Sample club data:", {
          id: clubsResult.rows[0].id,
          name: clubsResult.rows[0].name,
          category: clubsResult.rows[0].category,
          status: clubsResult.rows[0].status
        });
      }
    } catch (err) {
      console.error("Error fetching clubs:", err);
      console.error("Error details:", err.message);
      console.error("Error stack:", err.stack);
      clubsResult = { rows: [] };
    }
    
    const clubs = clubsResult.rows || [];
    console.log("Total clubs to render:", clubs.length);
    
    // Get upcoming events with club names (exclude pending/rejected events)
    const eventsResult = await pool.query(
      `SELECT 
        e.id,
        e.name,
        e.date,
        e.end_date,
        e.location,
        e.description,
        c.name as club_name,
        c.category as club_category,
        -- Use database status if it's a valid final status, otherwise calculate based on dates
        CASE 
          WHEN e.status IN ('Ongoing', 'ongoing', 'Completed', 'completed', 'Cancelled', 'cancelled') THEN e.status
          WHEN e.date IS NULL THEN 'Scheduled'
          WHEN DATE(e.date) > CURDATE() THEN 'Scheduled'
          WHEN DATE(e.date) = CURDATE() OR (DATE(e.date) <= CURDATE() AND COALESCE(DATE(e.end_date), DATE(e.date)) >= CURDATE()) THEN 'Ongoing'
          WHEN COALESCE(DATE(e.end_date), DATE(e.date)) < CURDATE() THEN 'Completed'
          ELSE COALESCE(e.status, 'Scheduled')
        END AS status
       FROM events e
       LEFT JOIN clubs c ON e.club_id = c.id
       WHERE COALESCE(e.status, 'pending_approval') != 'pending_approval'
         AND COALESCE(e.status, 'pending_approval') != 'rejected'
         AND COALESCE(e.status, '') NOT IN ('Completed', 'completed', 'Cancelled', 'cancelled')
         AND (e.posted_to_students = 1 OR e.posted_to_students IS NULL)
         -- Exclude events that have ended (show only upcoming and ongoing events)
         AND (
           -- Event is upcoming (date in future)
           DATE(e.date) > CURDATE()
           OR
           -- Event is ongoing (date is today or past, but end_date is today or future)
           (DATE(e.date) <= CURDATE() AND (e.end_date IS NULL OR DATE(e.end_date) >= CURDATE()))
         )
       ORDER BY e.date ASC 
       LIMIT 10`
    ).catch(() => ({ rows: [] }));
    
    const events = (eventsResult.rows || []).map(row => {
      // Normalize status
      let status = row.status || 'Scheduled';
      if (status) {
        status = status.charAt(0).toUpperCase() + status.slice(1).toLowerCase();
      }
      
      return {
        id: row.id,
        name: row.name,
        date: row.date ? new Date(row.date).toLocaleDateString() : 'TBA',
        location: row.location || 'TBA',
        description: row.description || '',
        club_name: row.club_name || 'Unknown Club',
        club_category: row.club_category || 'General',
        status: status
      };
    });

    // Get statistics
    const statsResult = await pool.query(`
      SELECT 
        (SELECT COUNT(*) FROM clubs WHERE status = 'Active' OR status IS NULL) as total_clubs,
        (SELECT COUNT(*) FROM events WHERE date >= CURRENT_DATE) as upcoming_events,
        (SELECT COUNT(*) FROM students) as total_students
    `).catch(() => ({ rows: [{ total_clubs: 0, upcoming_events: 0, total_students: 0 }] }));
    
    const stats = statsResult.rows[0] || { total_clubs: 0, upcoming_events: 0, total_students: 0 };

    // Get recent announcements (if announcements table exists)
    const announcementsResult = await pool.query(`
      SELECT id, subject as title, content as message, created_at
      FROM announcements
      WHERE audience = 'All Members' OR audience = 'All Students'
      ORDER BY created_at DESC
      LIMIT 5
    `).catch(() => ({ rows: [] }));
    
    const announcements = announcementsResult.rows || [];

    // Get unread messages count
    let unreadMessagesCount = 0;
    try {
      const messagesResult = await pool.query(`
        SELECT COUNT(*) as count
        FROM messages
        WHERE \`read\` = 0 OR \`read\` IS NULL
      `).catch(() => ({ rows: [{ count: 0 }] }));
      unreadMessagesCount = Number(messagesResult.rows[0]?.count || 0);
    } catch (e) {
      unreadMessagesCount = 0;
    }

    // Get featured/popular clubs (clubs with most members and events)
    // Use actual counts - no forced minimums
    let featuredClubs = clubs
      .map(club => {
        // Use actual member_count from database
        const memberCount = Number(club.member_count || 0);
        const eventCount = Number(club.event_count || 0);
        
        return {
          ...club,
          display_member_count: memberCount, // Use actual count, can be 0
          display_event_count: eventCount // Use actual count, can be 0
        };
      })
      .sort((a, b) => {
        // Sort by member count first, then event count
        const memberDiff = (b.display_member_count || 0) - (a.display_member_count || 0);
        if (memberDiff !== 0) return memberDiff;
        return (b.display_event_count || 0) - (a.display_event_count || 0);
      })
      .slice(0, 3);

    // Fetch member names for featured clubs
    for (let i = 0; i < featuredClubs.length; i++) {
      try {
        const membersResult = await pool.query(`
          SELECT 
            s.first_name,
            s.last_name,
            CONCAT(s.first_name, ' ', s.last_name) as full_name
          FROM membership_applications ma
          INNER JOIN students s ON s.id = ma.student_id
          WHERE ma.club_id = ? 
          AND (ma.status = 'approved' OR ma.status = 'Approved')
          ORDER BY ma.created_at DESC
          LIMIT 3
        `, [featuredClubs[i].id]).catch(() => ({ rows: [] }));
        
        const memberNames = membersResult.rows || [];
        featuredClubs[i].member_names = memberNames.map(m => 
          m.full_name || `${(m.first_name || '').trim()} ${(m.last_name || '').trim()}`.trim()
        ).filter(name => name);
        featuredClubs[i].first_member_name = featuredClubs[i].member_names[0] || null;
      } catch (e) {
        console.error(`Error fetching members for club ${featuredClubs[i].id}:`, e);
        featuredClubs[i].member_names = [];
        featuredClubs[i].first_member_name = null;
      }
    }

    // Get student's actual stats
    let studentStats = {
      clubsJoined: 0,
      eventsAttended: 0,
      points: 0
    };
    let myClubs = [];
    let recentActivity = [];
    let achievements = [];

    if (studentId) {
      // Get student's joined clubs count
      try {
        const myClubsResult = await pool.query(`
          SELECT COUNT(*) as count
          FROM membership_applications
          WHERE student_id = ? AND (status = 'approved' OR status = 'Approved')
        `, [studentId]).catch(() => ({ rows: [{ count: 0 }] }));
        studentStats.clubsJoined = Number(myClubsResult.rows[0]?.count || 0);

        // Get student's actual clubs
        const myClubsData = await pool.query(`
          SELECT 
            c.id,
            c.name,
            c.description,
            c.category,
            c.department,
            c.photo,
            COALESCE(o_counts.officer_count, 0) as officer_count,
            COALESCE(e_counts.event_count, 0) as event_count,
            ma.created_at as joined_date
          FROM membership_applications ma
          INNER JOIN clubs c ON c.id = ma.club_id
          LEFT JOIN (
            SELECT club_id, COUNT(*) as officer_count
            FROM officers
            GROUP BY club_id
          ) o_counts ON o_counts.club_id = c.id
          LEFT JOIN (
            SELECT club_id, COUNT(*) as event_count
            FROM events
            GROUP BY club_id
          ) e_counts ON e_counts.club_id = c.id
          WHERE ma.student_id = ? 
          AND LOWER(COALESCE(ma.status, '')) = 'approved'
          AND (c.status = 'Active' OR c.status IS NULL)
          ORDER BY ma.created_at DESC
          LIMIT 3
        `, [studentId]).catch(() => ({ rows: [] }));
        myClubs = myClubsData.rows || [];

        // Get events attended count (if there's an attendance table)
        try {
          const eventsAttendedResult = await pool.query(`
            SELECT COUNT(*) as count
            FROM event_attendance
            WHERE student_id = ?
          `, [studentId]).catch(() => ({ rows: [{ count: 0 }] }));
          studentStats.eventsAttended = Number(eventsAttendedResult.rows[0]?.count || 0);
        } catch (e) {
          // Table might not exist, use 0
          studentStats.eventsAttended = 0;
        }

        // Get points (if there's a points system)
        try {
          // Ensure student_points table exists
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
          `).catch(() => {}); // Ignore errors if table already exists
          
          const pointsResult = await pool.query(`
            SELECT COALESCE(SUM(points), 0) as total
            FROM student_points
            WHERE student_id = ?
          `, [studentId]).catch((e) => {
            console.error("[Dashboard] Error fetching points:", e.message);
            return { rows: [{ total: 0 }] };
          });
          studentStats.points = Number(pointsResult.rows[0]?.total || 0);
          console.log(`[Dashboard] Student ${studentId} has ${studentStats.points} points`);
        } catch (e) {
          // Table might not exist, use 0
          console.error("[Dashboard] Error in points calculation:", e.message);
          studentStats.points = 0;
        }

        // Get recent activity (club joins, event attendance, etc.)
        try {
          const activityResult = await pool.query(`
            SELECT 
              'club_join' as type,
              c.name as title,
              c.description as description,
              c.photo,
              ma.created_at as created_at,
              c.category
            FROM membership_applications ma
            INNER JOIN clubs c ON c.id = ma.club_id
            WHERE ma.student_id = ? AND (ma.status = 'approved' OR ma.status = 'Approved')
            ORDER BY ma.created_at DESC
            LIMIT 5
          `, [studentId]).catch(() => ({ rows: [] }));
          recentActivity = activityResult.rows || [];
        } catch (e) {
          recentActivity = [];
        }

        // Calculate achievements dynamically
        let achievements = [];
        // Club Starter - joined first club
        if (studentStats.clubsJoined >= 1) {
          achievements.push({
            id: 'club_starter',
            title: 'Club Starter',
            description: 'Joined your first club',
            icon: '🌟',
            earned: true,
            progress: 100
          });
        } else {
          achievements.push({
            id: 'club_starter',
            title: 'Club Starter',
            description: 'Join your first club',
            icon: '🌟',
            earned: false,
            progress: 0
          });
        }

        // Event Enthusiast - attend 5 events
        const eventsNeeded = 5;
        const eventProgress = Math.min((studentStats.eventsAttended / eventsNeeded) * 100, 100);
        achievements.push({
          id: 'event_enthusiast',
          title: 'Event Enthusiast',
          description: `Attend ${eventsNeeded} events`,
          icon: '🎯',
          earned: studentStats.eventsAttended >= eventsNeeded,
          progress: eventProgress,
          current: studentStats.eventsAttended,
          target: eventsNeeded
        });

        // Club Leader - become officer (check if student is an officer)
        let isOfficer = false;
        try {
          const officerCheck = await pool.query(`
            SELECT COUNT(*) as count
            FROM officers
            WHERE studentid = ? OR (first_name = ? AND last_name = ?)
          `, [student?.studentid || '', student?.first_name || '', student?.last_name || '']).catch(() => ({ rows: [{ count: 0 }] }));
          isOfficer = Number(officerCheck.rows[0]?.count || 0) > 0;
        } catch (e) {
          isOfficer = false;
        }
        achievements.push({
          id: 'club_leader',
          title: 'Club Leader',
          description: 'Become a club officer',
          icon: '🏆',
          earned: isOfficer,
          progress: isOfficer ? 100 : 0,
          current: isOfficer ? 1 : 0,
          target: 1
        });
      } catch (err) {
        console.error("Error fetching student stats:", err);
      }
    } else {
      // Default achievements for new users
      achievements = [
        {
          id: 'club_starter',
          title: 'Club Starter',
          description: 'Join your first club',
          icon: '🌟',
          earned: false,
          progress: 0
        },
        {
          id: 'event_enthusiast',
          title: 'Event Enthusiast',
          description: 'Attend 5 events',
          icon: '🎯',
          earned: false,
          progress: 0,
          current: 0,
          target: 5
        },
        {
          id: 'club_leader',
          title: 'Club Leader',
          description: 'Become a club officer',
          icon: '🏆',
          earned: false,
          progress: 0,
          current: 0,
          target: 1
        }
      ];
    }

    res.render("student/dashboard", {
      title: "Student Dashboard | UniClub",
      studentName: student.name || student.first_name || "Student",
      student: student,
      user: student,
      clubs: clubs,
      events: events,
      announcements: announcements,
      featuredClubs: featuredClubs,
      myClubs: myClubs,
      studentStats: studentStats,
      recentActivity: recentActivity,
      unreadMessagesCount: unreadMessagesCount,
      achievements: achievements || [],
      stats: {
        totalClubs: Number(stats.total_clubs || 0),
        upcomingEvents: Number(stats.upcoming_events || 0),
        totalStudents: Number(stats.total_students || 0)
      },
      csrfToken: req.csrfToken()
    });
  } catch (error) {
    console.error("Error loading dashboard:", error);
    res.render("student/dashboard", {
      title: "Student Dashboard | UniClub",
      studentName: req.session.student?.name || req.session.student?.first_name || "Student",
      student: req.session.student || {},
      user: req.session.student || {},
      clubs: [],
      events: [],
      unreadMessagesCount: 0,
      achievements: [],
      stats: {
        totalClubs: 0,
        upcomingEvents: 0,
        totalStudents: 0
      }
    });
  }
});

// Discover Clubs Page
router.get("/discover", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;

    if (!studentId) {
      return res.redirect("/student/login");
    }

    // Get student's department (case-insensitive matching)
    const studentDepartment = (student?.department || '').trim();
    
    console.log(`[Discover] Filtering clubs for student department: "${studentDepartment}"`);
    
    // First, let's check what clubs exist in the database
    const allClubsCheck = await pool.query(`
      SELECT id, name, department, category, status 
      FROM clubs 
      WHERE (status = 'Active' OR status IS NULL)
      LIMIT 10
    `).catch(() => ({ rows: [] }));
    console.log(`[Discover] Total active clubs in database:`, allClubsCheck.rows.length);
    if (allClubsCheck.rows.length > 0) {
      console.log(`[Discover] Sample clubs:`, allClubsCheck.rows.map(c => ({
        name: c.name,
        department: c.department,
        category: c.category
      })));
    }
    
    // Get all clubs filtered by: student's department OR category = 'Civic' OR category = 'Religious'
    // IMPORTANT: Only show clubs from student's department, or Civic/Religious categories
    // Do NOT show clubs from other departments, even if they have Academic or other categories
    let clubsResult;
    try {
      // Simplified query: Show clubs that match student's department OR are Civic/Religious
      // AND exclude clubs from other departments that are NOT Civic/Religious
      const studentDeptLower = studentDepartment.toLowerCase();
      const hasDepartment = studentDepartment && studentDepartment.trim() !== '';
      
      clubsResult = await pool.query(`
        SELECT 
          c.id,
          c.name,
          c.description,
          c.category,
          c.department,
          c.adviser,
          c.photo,
          COALESCE(c.status, 'Active') as status,
          COALESCE(o_counts.officer_count, 0) as officer_count,
          COALESCE(e_counts.event_count, 0) as event_count,
          COALESCE(m_counts.member_count, 0) as member_count,
          next_event.name as next_event_name,
          next_event.date as next_event_date
        FROM clubs c
        LEFT JOIN (
          SELECT club_id, COUNT(*) as officer_count
          FROM officers
          GROUP BY club_id
        ) o_counts ON o_counts.club_id = c.id
        LEFT JOIN (
          SELECT club_id, COUNT(*) as event_count
          FROM events
          GROUP BY club_id
        ) e_counts ON e_counts.club_id = c.id
        LEFT JOIN (
          SELECT club_id, COUNT(*) as member_count
          FROM membership_applications
          WHERE status = 'approved' OR status = 'Approved'
          GROUP BY club_id
        ) m_counts ON m_counts.club_id = c.id
        LEFT JOIN (
          SELECT club_id, name, date
          FROM events
          WHERE date >= CURRENT_DATE
          ORDER BY date ASC
          LIMIT 1
        ) next_event ON next_event.club_id = c.id
        LEFT JOIN (
          SELECT student_id, club_id, status
          FROM membership_applications
          WHERE student_id = ?
          ORDER BY created_at DESC
        ) membership ON membership.club_id = c.id
        WHERE (c.status = 'Active' OR c.status IS NULL)
        AND (
          -- Show clubs from student's department (if department is provided and matches)
          (? = 1 AND c.department IS NOT NULL AND c.department != '' AND LOWER(TRIM(c.department)) = ?)
          OR
          -- Show Civic clubs (any department)
          LOWER(TRIM(COALESCE(c.category, ''))) = 'civic'
          OR
          -- Show Religious clubs (any department)
          LOWER(TRIM(COALESCE(c.category, ''))) = 'religious'
        )
        AND NOT (
          -- Exclude clubs from OTHER departments that are NOT Civic or Religious
          ? = 1
          AND c.department IS NOT NULL 
          AND c.department != ''
          AND LOWER(TRIM(c.department)) != ?
          AND LOWER(TRIM(COALESCE(c.category, ''))) NOT IN ('civic', 'religious')
        )
        ORDER BY c.name ASC
      `, [
        studentId,
        hasDepartment ? 1 : 0, 
        studentDeptLower,
        hasDepartment ? 1 : 0,
        studentDeptLower
      ]);
      
      console.log(`[Discover] Query parameters:`, {
        hasDepartment,
        studentDeptLower,
        studentDepartment
      });
      console.log(`[Discover] Clubs fetched for department "${studentDepartment}":`, clubsResult.rows?.length || 0);
      if (clubsResult.rows && clubsResult.rows.length > 0) {
        console.log(`[Discover] Sample clubs:`, clubsResult.rows.slice(0, 5).map(c => {
          const clubDept = (c.department || '').trim().toLowerCase();
          const clubCat = (c.category || '').trim().toLowerCase();
          const studentDept = (studentDepartment || '').trim().toLowerCase();
          
          let matchReason = 'unknown';
          if (clubDept && clubDept === studentDept) {
            matchReason = 'department';
          } else if (clubCat === 'civic') {
            matchReason = 'civic';
          } else if (clubCat === 'religious') {
            matchReason = 'religious';
          }
          
          return { 
            name: c.name, 
            department: c.department, 
            category: c.category,
            match_reason: matchReason
          };
        }));
      } else {
        console.log(`[Discover] No clubs found. Checking if query is too restrictive...`);
      }
    } catch (queryError) {
      console.error("[Discover] Error fetching clubs:", queryError);
      clubsResult = { rows: [] };
    }

    const clubs = (clubsResult.rows || []).map(club => {
      // Use actual member_count from database
      const memberCount = Number(club.member_count || 0);
      const eventCount = Number(club.event_count || 0);
      
      return {
        ...club,
        logo: club.photo, // Map photo to logo for template compatibility
        display_member_count: memberCount, // Use actual count, can be 0
        display_event_count: eventCount // Use actual count, can be 0
      };
    });
    console.log("Discover page - Total clubs to render:", clubs.length);

    // Get featured/popular clubs from the filtered list (clubs with most events)
    let featuredClubs = clubs
      .map(club => {
        // Use actual member_count from database
        const memberCount = Number(club.member_count || 0);
        const eventCount = Number(club.event_count || 0);
        
        return {
          ...club,
          display_member_count: memberCount, // Use actual count, can be 0
          display_event_count: eventCount // Use actual count, can be 0
        };
      })
      .sort((a, b) => {
        // Sort by member count first, then event count
        const memberDiff = (b.display_member_count || 0) - (a.display_member_count || 0);
        if (memberDiff !== 0) return memberDiff;
        return (b.display_event_count || 0) - (a.display_event_count || 0);
      })
      .slice(0, 3);

    // Fetch member names for featured clubs
    for (let i = 0; i < featuredClubs.length; i++) {
      try {
        const membersResult = await pool.query(`
          SELECT 
            s.first_name,
            s.last_name,
            CONCAT(s.first_name, ' ', s.last_name) as full_name
          FROM membership_applications ma
          INNER JOIN students s ON s.id = ma.student_id
          WHERE ma.club_id = ? 
          AND (ma.status = 'approved' OR ma.status = 'Approved')
          ORDER BY ma.created_at DESC
          LIMIT 3
        `, [featuredClubs[i].id]).catch(() => ({ rows: [] }));
        
        const memberNames = membersResult.rows || [];
        featuredClubs[i].member_names = memberNames.map(m => 
          m.full_name || `${(m.first_name || '').trim()} ${(m.last_name || '').trim()}`.trim()
        ).filter(name => name);
        featuredClubs[i].first_member_name = featuredClubs[i].member_names[0] || null;
      } catch (e) {
        console.error(`Error fetching members for club ${featuredClubs[i].id}:`, e);
        featuredClubs[i].member_names = [];
        featuredClubs[i].first_member_name = null;
      }
    }

    // Get pending applications
    let pendingApplications = [];
    try {
      const pendingResult = await pool.query(`
        SELECT 
          ma.id,
          ma.club_id,
          ma.status,
          ma.created_at,
          c.name as club_name,
          c.description,
          c.category
        FROM membership_applications ma
        LEFT JOIN clubs c ON c.id = ma.club_id
        WHERE ma.student_id = ? 
        AND (ma.status IS NULL OR ma.status = 'pending' OR LOWER(ma.status) = 'pending')
        ORDER BY ma.created_at DESC
      `, [studentId]);
      pendingApplications = pendingResult.rows || [];
    } catch (appError) {
      console.error("Error fetching pending applications:", appError);
      pendingApplications = [];
    }

    // Get invitations (if invitations table exists)
    let invitations = [];
    try {
      const invitationsResult = await pool.query(`
        SELECT 
          i.id,
          i.club_id,
          i.created_at,
          c.name as club_name,
          c.description,
          c.category
        FROM invitations i
        LEFT JOIN clubs c ON c.id = i.club_id
        WHERE i.student_id = ? AND i.status = 'pending'
        ORDER BY i.created_at DESC
      `, [studentId]).catch(() => ({ rows: [] }));
      invitations = invitationsResult.rows || [];
    } catch (invError) {
      invitations = [];
    }

    // Get announcements
    const announcementsResult = await pool.query(`
      SELECT id, subject as title, content as message, created_at
      FROM announcements
      WHERE audience = 'All Members' OR audience = 'All Students'
      ORDER BY created_at DESC
      LIMIT 5
    `).catch(() => ({ rows: [] }));
    
    const announcements = announcementsResult.rows || [];

    // Get statistics for hero section
    const statsResult = await pool.query(`
      SELECT 
        (SELECT COUNT(*) FROM clubs WHERE status = 'Active' OR status IS NULL) as total_clubs,
        (SELECT COUNT(*) FROM events WHERE date >= CURRENT_DATE) as upcoming_events,
        (SELECT COUNT(*) FROM students) as total_students
    `).catch(() => ({ rows: [{ total_clubs: 0, upcoming_events: 0, total_students: 0 }] }));
    
    const stats = statsResult.rows[0] || { total_clubs: 0, upcoming_events: 0, total_students: 0 };

    res.render("student/discover", {
      title: "Discover Clubs | UniClub",
      student: student,
      clubs: clubs,
      featuredClubs: featuredClubs,
      pendingApplications: pendingApplications,
      invitations: invitations,
      announcements: announcements,
      stats: stats,
      csrfToken: (req.csrfToken && typeof req.csrfToken === 'function') ? req.csrfToken() : (res.locals.csrfToken || '')
    });
  } catch (error) {
    console.error("Error loading discover page:", error);
    res.render("student/discover", {
      title: "Discover Clubs | UniClub",
      student: req.session.student || {},
      clubs: [],
      featuredClubs: [],
      pendingApplications: [],
      invitations: [],
      announcements: [],
      stats: { total_clubs: 0, upcoming_events: 0, total_students: 0 },
      csrfToken: (req.csrfToken && typeof req.csrfToken === 'function') ? req.csrfToken() : (res.locals.csrfToken || '')
    });
  }
});

// Club Details Page
router.get("/club/:id", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;
    const clubId = req.params.id;

    if (!studentId) {
      return res.redirect("/student/login");
    }

    // Get club details
    const clubResult = await pool.query(`
      SELECT 
        c.id,
        c.name,
        c.description,
        c.category,
        c.department,
        c.adviser,
        c.photo,
        c.program,
        c.status,
        COALESCE(c.status, 'Active') as status,
        COALESCE(m_counts.member_count, 0) as member_count,
        COALESCE(e_counts.event_count, 0) as event_count,
        next_event.name as next_event_name,
        next_event.date as next_event_date,
        next_event.location as next_event_location,
        next_event.description as next_event_description,
        next_event.next_event_id,
        CASE 
          WHEN next_event_rsvp.student_id IS NOT NULL AND (next_event_rsvp.status = 'going' OR next_event_rsvp.status IS NULL) THEN 'going'
          WHEN next_event_rsvp.student_id IS NOT NULL AND next_event_rsvp.status = 'interested' THEN 'interested'
          ELSE 'not_responded'
        END as next_event_rsvp_status
      FROM clubs c
      LEFT JOIN (
        SELECT club_id, COUNT(*) as member_count
        FROM membership_applications
        WHERE status = 'approved' OR status = 'Approved'
        GROUP BY club_id
      ) m_counts ON m_counts.club_id = c.id
      LEFT JOIN (
        SELECT club_id, COUNT(*) as event_count
        FROM events
        WHERE COALESCE(status, 'pending_approval') != 'pending_approval'
          AND COALESCE(status, 'pending_approval') != 'rejected'
          AND COALESCE(status, '') NOT IN ('Completed', 'completed', 'Cancelled', 'cancelled')
          AND (
            -- Event is upcoming (date in future)
            DATE(date) > CURDATE()
            OR
            -- Event is ongoing (date is today or past, but end_date is today or future)
            (DATE(date) <= CURDATE() AND (end_date IS NULL OR DATE(end_date) >= CURDATE()))
          )
        GROUP BY club_id
      ) e_counts ON e_counts.club_id = c.id
      LEFT JOIN (
        SELECT club_id, id as next_event_id, name, date, location, description
        FROM events
        WHERE COALESCE(status, 'pending_approval') != 'pending_approval'
          AND COALESCE(status, 'pending_approval') != 'rejected'
          AND COALESCE(status, '') NOT IN ('Completed', 'completed', 'Cancelled', 'cancelled')
          AND (posted_to_students = 1 OR posted_to_students IS NULL)
          -- Exclude events that have ended (show only upcoming and ongoing events)
          AND (
            -- Event is upcoming (date in future)
            DATE(date) > CURDATE()
            OR
            -- Event is ongoing (date is today or past, but end_date is today or future)
            (DATE(date) <= CURDATE() AND (end_date IS NULL OR DATE(end_date) >= CURDATE()))
          )
        ORDER BY date ASC
        LIMIT 1
      ) next_event ON next_event.club_id = c.id
      LEFT JOIN event_attendance next_event_rsvp ON next_event_rsvp.event_id = next_event.next_event_id AND next_event_rsvp.student_id = ?
      WHERE c.id = ? AND (c.status = 'Active' OR c.status IS NULL)
    `, [studentId, clubId]);

    if (!clubResult.rows || clubResult.rows.length === 0) {
      return res.status(404).render("errors/404", { title: "Club Not Found" });
    }

    const club = clubResult.rows[0];

    // Get upcoming events with RSVP status
    const eventsResult = await pool.query(`
      SELECT 
        e.id,
        e.name as title,
        e.date,
        e.end_date,
        e.location,
        e.description,
        e.created_at,
        CASE 
          WHEN ea.student_id IS NOT NULL AND (ea.status = 'going' OR ea.status IS NULL) THEN 'going'
          WHEN ea.student_id IS NOT NULL AND ea.status = 'interested' THEN 'interested'
          ELSE 'not_responded'
        END as rsvp_status,
        -- Use database status if it's a valid final status, otherwise calculate based on dates
        CASE 
          WHEN e.status IN ('Ongoing', 'ongoing', 'Completed', 'completed', 'Cancelled', 'cancelled') THEN e.status
          WHEN e.date IS NULL THEN 'Scheduled'
          WHEN DATE(e.date) > CURDATE() THEN 'Scheduled'
          WHEN DATE(e.date) = CURDATE() OR (DATE(e.date) <= CURDATE() AND COALESCE(DATE(e.end_date), DATE(e.date)) >= CURDATE()) THEN 'Ongoing'
          WHEN COALESCE(DATE(e.end_date), DATE(e.date)) < CURDATE() THEN 'Completed'
          ELSE COALESCE(e.status, 'Scheduled')
        END AS status
      FROM events e
      LEFT JOIN event_attendance ea ON ea.event_id = e.id AND ea.student_id = ?
      WHERE e.club_id = ? 
        AND COALESCE(e.status, 'pending_approval') != 'pending_approval'
        AND COALESCE(e.status, 'pending_approval') != 'rejected'
        AND COALESCE(e.status, '') NOT IN ('Completed', 'completed', 'Cancelled', 'cancelled')
        AND (e.posted_to_students = 1 OR e.posted_to_students IS NULL)
        -- Exclude events that have ended (show only upcoming and ongoing events)
        AND (
          -- Event is upcoming (date in future)
          DATE(e.date) > CURDATE()
          OR
          -- Event is ongoing (date is today or past, but end_date is today or future)
          (DATE(e.date) <= CURDATE() AND (e.end_date IS NULL OR DATE(e.end_date) >= CURDATE()))
        )
      ORDER BY e.date ASC
      LIMIT 10
    `, [studentId, clubId]);

    const events = (eventsResult.rows || []).map(row => {
      // Normalize status
      let status = row.status || 'Scheduled';
      if (status) {
        status = status.charAt(0).toUpperCase() + status.slice(1).toLowerCase();
      }
      return {
        ...row,
        status: status
      };
    });

    // Get officers
    const officersResult = await pool.query(`
      SELECT 
        id,
        first_name,
        last_name,
        CONCAT(first_name, ' ', last_name) as name,
        role as position,
        department,
        program,
        studentid,
        profile_picture
      FROM officers
      WHERE club_id = ? AND (status = 'Active' OR status IS NULL)
      ORDER BY 
        CASE role
          WHEN 'President' THEN 1
          WHEN 'Vice President' THEN 2
          WHEN 'Secretary' THEN 3
          WHEN 'Treasurer' THEN 4
          WHEN 'Auditor' THEN 5
          ELSE 6
        END,
        first_name ASC
    `, [clubId]);

    const officers = officersResult.rows || [];

    // Check if student is a member
    const membershipResult = await pool.query(`
      SELECT status
      FROM membership_applications
      WHERE student_id = ? AND club_id = ?
      ORDER BY created_at DESC
      LIMIT 1
    `, [studentId, clubId]);

    const isMember = membershipResult.rows.length > 0 && 
                     (membershipResult.rows[0].status === 'approved' || membershipResult.rows[0].status === 'Approved');

    // Get member count growth (compare current month vs last month)
    const growthResult = await pool.query(`
      SELECT 
        COUNT(*) as current_month,
        (SELECT COUNT(*) 
         FROM membership_applications 
         WHERE club_id = ? 
         AND (status = 'approved' OR status = 'Approved')
         AND MONTH(created_at) = MONTH(DATE_SUB(CURRENT_DATE, INTERVAL 1 MONTH))
         AND YEAR(created_at) = YEAR(DATE_SUB(CURRENT_DATE, INTERVAL 1 MONTH))
        ) as last_month
      FROM membership_applications
      WHERE club_id = ?
      AND (status = 'approved' OR status = 'Approved')
      AND MONTH(created_at) = MONTH(CURRENT_DATE)
      AND YEAR(created_at) = YEAR(CURRENT_DATE)
    `, [clubId, clubId]);

    const growth = growthResult.rows[0] || { current_month: 0, last_month: 0 };
    const growthPercent = growth.last_month > 0 
      ? Math.round(((growth.current_month - growth.last_month) / growth.last_month) * 100)
      : 0;

    // Parse program if it's JSON
    let programs = [];
    if (club.program) {
      try {
        if (typeof club.program === 'string') {
          programs = JSON.parse(club.program);
        } else {
          programs = club.program;
        }
        if (!Array.isArray(programs)) {
          programs = [programs];
        }
      } catch (e) {
        programs = [];
      }
    }

    // Get announcements
    const announcementsResult = await pool.query(`
      SELECT id, subject as title, content as message, created_at
      FROM announcements
      WHERE audience = 'All Members' OR audience = 'All Students'
      ORDER BY created_at DESC
      LIMIT 5
    `).catch(() => ({ rows: [] }));
    
    const announcements = announcementsResult.rows || [];

    res.render("student/club", {
      title: `${club.name} | UniClub`,
      student: student,
      club: club,
      events: events,
      officers: officers,
      isMember: isMember,
      memberCount: Number(club.member_count || 0),
      eventCount: Number(club.event_count || 0),
      growthPercent: growthPercent,
      programs: programs,
      announcements: announcements,
      csrfToken: (req.csrfToken && typeof req.csrfToken === 'function') ? req.csrfToken() : (res.locals.csrfToken || '')
    });
  } catch (error) {
    console.error("Error loading club details page:", error);
    res.status(500).render("errors/500", { title: "Server Error", error });
  }
});

// My Clubs Page
router.get("/my-clubs", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;

    if (!studentId) {
      return res.redirect("/student/login");
    }

    // Get approved memberships (clubs the student has joined) with detailed stats
    const myClubsResult = await pool.query(`
      SELECT 
        c.id,
        c.name,
        c.description,
        c.category,
        c.department,
        c.adviser,
        c.photo,
        COALESCE(c.status, 'Active') as status,
        ma.created_at as joined_date,
        ma.status as membership_status,
        COALESCE(m_counts.member_count, 0) as member_count,
        COALESCE(e_counts.event_count, 0) as event_count,
        COALESCE(upcoming_counts.upcoming_event_count, 0) as upcoming_event_count,
        next_event.date as next_event_date,
        next_event.name as next_event_name,
        next_event.location as next_event_location
      FROM membership_applications ma
      INNER JOIN clubs c ON c.id = ma.club_id
      LEFT JOIN (
        SELECT club_id, COUNT(*) as member_count
        FROM membership_applications
        WHERE status = 'approved' OR status = 'Approved'
        GROUP BY club_id
      ) m_counts ON m_counts.club_id = c.id
      LEFT JOIN (
        SELECT club_id, COUNT(*) as event_count
        FROM events
        WHERE date >= CURRENT_DATE
        GROUP BY club_id
      ) e_counts ON e_counts.club_id = c.id
      LEFT JOIN (
        SELECT club_id, COUNT(*) as upcoming_event_count
        FROM events
        WHERE date >= CURRENT_DATE
        GROUP BY club_id
      ) upcoming_counts ON upcoming_counts.club_id = c.id
      LEFT JOIN (
        SELECT e1.club_id, e1.date, e1.name, e1.location
        FROM events e1
        WHERE (e1.date >= CURRENT_DATE OR e1.date IS NULL)
        AND e1.id = (
          SELECT e2.id
          FROM events e2
          WHERE e2.club_id = e1.club_id
          AND (e2.date >= CURRENT_DATE OR e2.date IS NULL)
          ORDER BY COALESCE(e2.date, '9999-12-31') ASC
          LIMIT 1
        )
      ) next_event ON next_event.club_id = c.id
      WHERE ma.student_id = ? 
      AND LOWER(COALESCE(ma.status, '')) = 'approved'
      ORDER BY ma.created_at DESC
    `, [studentId]).catch(() => ({ rows: [] }));

    let myClubs = myClubsResult.rows || [];

    // Get student activity per club (events attended, points, last active) and member names
    for (let i = 0; i < myClubs.length; i++) {
      const club = myClubs[i];
      
      // Get events attended count for this student in this club
      try {
        const eventsAttendedResult = await pool.query(`
          SELECT COUNT(*) as count
          FROM event_attendance ea
          INNER JOIN events e ON ea.event_id = e.id
          WHERE ea.student_id = ? AND e.club_id = ?
        `, [studentId, club.id]).catch(() => ({ rows: [{ count: 0 }] }));
        club.events_attended = Number(eventsAttendedResult.rows[0]?.count || 0);
      } catch (e) {
        club.events_attended = 0;
      }

      // Get points earned for this student in this club
      // Note: student_points table doesn't have event_id or club_id columns
      // We'll try to match points by source and description containing club name
      try {
        const pointsResult = await pool.query(`
          SELECT COALESCE(SUM(sp.points), 0) as total
          FROM student_points sp
          WHERE sp.student_id = ?
            AND (
              (sp.source = 'club_join' AND sp.description LIKE ?)
              OR (sp.source = 'event_attendance' AND EXISTS (
                SELECT 1 FROM event_attendance ea
                INNER JOIN events e ON ea.event_id = e.id
                WHERE ea.student_id = ? AND e.club_id = ?
              ))
            )
        `, [studentId, `%${club.name}%`, studentId, club.id]).catch(() => ({ rows: [{ total: 0 }] }));
        club.points_earned = Number(pointsResult.rows[0]?.total || 0);
      } catch (e) {
        console.error('Error calculating club points:', e);
        club.points_earned = 0;
      }

      // Get last active date (most recent event attendance or club join date)
      try {
        const lastActiveResult = await pool.query(`
          SELECT MAX(activity_date) as last_active
          FROM (
            SELECT ea.created_at as activity_date 
            FROM event_attendance ea 
            INNER JOIN events e ON ea.event_id = e.id 
            WHERE ea.student_id = ? AND e.club_id = ?
            UNION ALL
            SELECT ma.created_at as activity_date 
            FROM membership_applications ma 
            WHERE ma.student_id = ? AND ma.club_id = ? AND (ma.status = 'approved' OR ma.status = 'Approved')
          ) as activities
        `, [studentId, club.id, studentId, club.id]).catch(() => ({ rows: [{ last_active: null }] }));
        club.last_active = lastActiveResult.rows[0]?.last_active || club.joined_date;
      } catch (e) {
        club.last_active = club.joined_date;
      }

      // Fetch member names for this club (similar to discover.ejs)
      try {
        const membersResult = await pool.query(`
          SELECT 
            s.id,
            s.first_name,
            s.last_name,
            CONCAT(s.first_name, ' ', s.last_name) as full_name
          FROM membership_applications ma
          INNER JOIN students s ON s.id = ma.student_id
          WHERE ma.club_id = ? 
          AND (ma.status = 'approved' OR ma.status = 'Approved')
          ORDER BY ma.created_at DESC
          LIMIT 3
        `, [club.id]).catch(() => ({ rows: [] }));
        
        const memberNames = membersResult.rows || [];
        club.member_names = memberNames.map(m => 
          m.full_name || `${(m.first_name || '').trim()} ${(m.last_name || '').trim()}`.trim()
        ).filter(name => name);
        club.first_member_name = club.member_names[0] || null;
        
        // Ensure member_count is accurate (use actual count from query if available)
        if (!club.member_count || club.member_count === 0) {
          // Get accurate member count
          const memberCountResult = await pool.query(`
            SELECT COUNT(*) as count
            FROM membership_applications
            WHERE club_id = ? 
            AND (status = 'approved' OR status = 'Approved')
          `, [club.id]).catch(() => ({ rows: [{ count: 0 }] }));
          club.member_count = Number(memberCountResult.rows[0]?.count || 0);
        }
      } catch (e) {
        console.error(`Error fetching members for club ${club.id}:`, e);
        club.member_names = [];
        club.first_member_name = null;
        // If member_count is still 0, try to get it
        if (!club.member_count || club.member_count === 0) {
          try {
            const memberCountResult = await pool.query(`
              SELECT COUNT(*) as count
              FROM membership_applications
              WHERE club_id = ? 
              AND (status = 'approved' OR status = 'Approved')
            `, [club.id]).catch(() => ({ rows: [{ count: 0 }] }));
            club.member_count = Number(memberCountResult.rows[0]?.count || 0);
          } catch (err) {
            club.member_count = 0;
          }
        }
      }
    }

    // Get overall stats
    // Calculate clubsJoined from actual approved memberships
    // Ensure we count all approved memberships, not just active clubs
    const clubsJoinedCount = myClubs.length;
    
    const stats = {
      clubsJoined: clubsJoinedCount,
      eventsAttended: 0,
      pointsEarned: 0,
      achievements: 0
    };
    
    // Debug log to verify clubsJoined count
    console.log(`[My Clubs] Student ${studentId} has ${clubsJoinedCount} clubs joined. myClubs.length = ${myClubs.length}`);
    
    // Double-check: if myClubs has items but stats.clubsJoined is 0, fix it
    if (myClubs.length > 0 && stats.clubsJoined === 0) {
      stats.clubsJoined = myClubs.length;
      console.log(`[My Clubs] Fixed stats.clubsJoined to ${myClubs.length}`);
    }

    // Calculate achievements dynamically
    let achievementsCount = 0;
    try {
      // Achievement 1: First Club Joined
      if (myClubs.length > 0) {
        achievementsCount++;
      }

      // Achievement 2: Active Member (joined 3+ clubs)
      if (myClubs.length >= 3) {
        achievementsCount++;
      }

      // Achievement 3: Event Enthusiast (attended 5+ events)
      if (stats.eventsAttended >= 5) {
        achievementsCount++;
      }

      // Achievement 4: Point Collector (earned 100+ points)
      if (stats.pointsEarned >= 100) {
        achievementsCount++;
      }

      // Achievement 5: Social Butterfly (joined 5+ clubs)
      if (myClubs.length >= 5) {
        achievementsCount++;
      }

      // Achievement 6: Dedicated Member (attended 10+ events)
      if (stats.eventsAttended >= 10) {
        achievementsCount++;
      }
    } catch (e) {
      achievementsCount = 0;
    }
    
    stats.achievements = achievementsCount;

    // Calculate total events attended
    try {
      const totalEventsResult = await pool.query(`
        SELECT COUNT(*) as count
        FROM event_attendance
        WHERE student_id = ?
      `, [studentId]).catch(() => ({ rows: [{ count: 0 }] }));
      stats.eventsAttended = Number(totalEventsResult.rows[0]?.count || 0);
    } catch (e) {
      stats.eventsAttended = 0;
    }

    // Calculate total points
    try {
      const totalPointsResult = await pool.query(`
        SELECT COALESCE(SUM(points), 0) as total
        FROM student_points
        WHERE student_id = ?
      `, [studentId]).catch(() => ({ rows: [{ total: 0 }] }));
      stats.pointsEarned = Number(totalPointsResult.rows[0]?.total || 0);
    } catch (e) {
      stats.pointsEarned = 0;
    }

    // Get active clubs count (clubs with recent activity)
    const activeClubsCount = myClubs.filter(club => {
      const daysSinceActive = club.last_active ? 
        Math.floor((new Date() - new Date(club.last_active)) / (1000 * 60 * 60 * 24)) : 999;
      return daysSinceActive < 30;
    }).length;

    // Get upcoming events count (from student's clubs)
    let upcomingEventsCount = 0;
    let upcomingEventsThisWeek = 0;
    try {
      const upcomingEventsResult = await pool.query(`
        SELECT COUNT(*) as count
        FROM events e
        INNER JOIN membership_applications ma ON ma.club_id = e.club_id
        WHERE ma.student_id = ?
        AND (ma.status = 'approved' OR ma.status = 'Approved')
        AND (e.date >= CURRENT_DATE OR e.date IS NULL)
      `, [studentId]).catch(() => ({ rows: [{ count: 0 }] }));
      upcomingEventsCount = Number(upcomingEventsResult.rows[0]?.count || 0);

      // Get events this week (next 7 days)
      const thisWeekResult = await pool.query(`
        SELECT COUNT(*) as count
        FROM events e
        INNER JOIN membership_applications ma ON ma.club_id = e.club_id
        WHERE ma.student_id = ?
        AND (ma.status = 'approved' OR ma.status = 'Approved')
        AND e.date >= CURRENT_DATE
        AND e.date <= DATE_ADD(CURRENT_DATE, INTERVAL 7 DAY)
      `, [studentId]).catch(() => ({ rows: [{ count: 0 }] }));
      upcomingEventsThisWeek = Number(thisWeekResult.rows[0]?.count || 0);
    } catch (e) {
      upcomingEventsCount = 0;
      upcomingEventsThisWeek = 0;
    }

    // Get unread messages count
    let unreadMessagesCount = 0;
    try {
      const messagesResult = await pool.query(`
        SELECT COUNT(*) as count
        FROM messages
        WHERE \`read\` = 0 OR \`read\` IS NULL
      `, []).catch(() => ({ rows: [{ count: 0 }] }));
      unreadMessagesCount = Number(messagesResult.rows[0]?.count || 0);
    } catch (e) {
      unreadMessagesCount = 0;
    }

    // Get suggested clubs (clubs not joined, sorted by popularity)
    // Only show clubs from student's department, plus Civic and Religious clubs
    let suggestedClubs = [];
    try {
      // Get student's department for filtering
      const studentDepartment = (student?.department || '').trim();
      const studentDeptLower = studentDepartment.toLowerCase();
      const hasDepartment = studentDepartment && studentDepartment.trim() !== '';
      
      const suggestedResult = await pool.query(`
        SELECT 
          c.id,
          c.name,
          c.description,
          c.category,
          c.department,
          c.photo,
          COALESCE(m_counts.member_count, 0) as member_count
        FROM clubs c
        LEFT JOIN (
          SELECT club_id, COUNT(*) as member_count
          FROM membership_applications
          WHERE status = 'approved' OR status = 'Approved'
          GROUP BY club_id
        ) m_counts ON m_counts.club_id = c.id
        WHERE c.id NOT IN (
          SELECT club_id
          FROM membership_applications
          WHERE student_id = ? AND (status = 'approved' OR status = 'Approved')
        )
        AND (c.status = 'Active' OR c.status IS NULL)
        AND (
          -- Show clubs from student's department (if department is provided and matches)
          (? = 1 AND c.department IS NOT NULL AND c.department != '' AND LOWER(TRIM(c.department)) = ?)
          OR
          -- Show Civic clubs (any department)
          LOWER(TRIM(COALESCE(c.category, ''))) = 'civic'
          OR
          -- Show Religious clubs (any department)
          LOWER(TRIM(COALESCE(c.category, ''))) = 'religious'
        )
        AND NOT (
          -- Exclude clubs from OTHER departments that are NOT Civic or Religious
          ? = 1
          AND c.department IS NOT NULL 
          AND c.department != ''
          AND LOWER(TRIM(c.department)) != ?
          AND LOWER(TRIM(COALESCE(c.category, ''))) NOT IN ('civic', 'religious')
        )
        ORDER BY m_counts.member_count DESC, c.name ASC
        LIMIT 4
      `, [
        studentId,
        hasDepartment ? 1 : 0, 
        studentDeptLower,
        hasDepartment ? 1 : 0,
        studentDeptLower
      ]).catch(() => ({ rows: [] }));
      suggestedClubs = suggestedResult.rows || [];

      // Fetch member names for suggested clubs
      for (let i = 0; i < suggestedClubs.length; i++) {
        try {
          const membersResult = await pool.query(`
            SELECT 
              s.id,
              s.first_name,
              s.last_name,
              CONCAT(s.first_name, ' ', s.last_name) as full_name
            FROM membership_applications ma
            INNER JOIN students s ON s.id = ma.student_id
            WHERE ma.club_id = ? 
            AND (ma.status = 'approved' OR ma.status = 'Approved')
            ORDER BY ma.created_at DESC
            LIMIT 3
          `, [suggestedClubs[i].id]).catch(() => ({ rows: [] }));
          
          const memberNames = membersResult.rows || [];
          suggestedClubs[i].member_names = memberNames.map(m => 
            m.full_name || `${(m.first_name || '').trim()} ${(m.last_name || '').trim()}`.trim()
          ).filter(name => name);
          suggestedClubs[i].first_member_name = suggestedClubs[i].member_names[0] || null;
        } catch (e) {
          console.error(`Error fetching members for suggested club ${suggestedClubs[i].id}:`, e);
          suggestedClubs[i].member_names = [];
          suggestedClubs[i].first_member_name = null;
        }
      }
    } catch (e) {
      suggestedClubs = [];
    }

    // Get announcements
    const announcementsResult = await pool.query(`
      SELECT id, subject as title, content as message, created_at
      FROM announcements
      WHERE audience = 'All Members' OR audience = 'All Students'
      ORDER BY created_at DESC
      LIMIT 5
    `).catch(() => ({ rows: [] }));
    
    const announcements = announcementsResult.rows || [];

    // Debug: Log stats before rendering
    console.log(`[My Clubs Route] Rendering with stats:`, {
      clubsJoined: stats.clubsJoined,
      eventsAttended: stats.eventsAttended,
      pointsEarned: stats.pointsEarned,
      achievements: stats.achievements,
      myClubsCount: myClubs.length
    });

    res.render("student/my-clubs", {
      title: "My Clubs | UniClub",
      student: student,
      myClubs: myClubs,
      stats: stats,
      activeClubsCount: activeClubsCount,
      upcomingEventsCount: upcomingEventsCount,
      upcomingEventsThisWeek: upcomingEventsThisWeek,
      unreadMessagesCount: unreadMessagesCount,
      suggestedClubs: suggestedClubs,
      announcements: announcements,
      csrfToken: (req.csrfToken && typeof req.csrfToken === 'function') ? req.csrfToken() : (res.locals.csrfToken || '')
    });
  } catch (error) {
    console.error("Error loading my clubs page:", error);
    res.render("student/my-clubs", {
      title: "My Clubs | UniClub",
      student: req.session.student || {},
      myClubs: [],
      stats: { clubsJoined: 0, eventsAttended: 0, pointsEarned: 0, achievements: 0 },
      activeClubsCount: 0,
      upcomingEventsCount: 0,
      upcomingEventsThisWeek: 0,
      unreadMessagesCount: 0,
      suggestedClubs: [],
      announcements: [],
      csrfToken: (req.csrfToken && typeof req.csrfToken === 'function') ? req.csrfToken() : (res.locals.csrfToken || '')
    });
  }
});

// My Applications Page
router.get("/applications", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;

    if (!studentId) {
      return res.redirect("/student/login");
    }

    // Get all applications with club details
    let allApplications = [];
    try {
      const applicationsResult = await pool.query(`
        SELECT 
          ma.id,
          ma.club_id,
          ma.status,
          ma.created_at,
          ma.name as application_name,
          ma.applying_for,
          c.name as club_name,
          c.description as club_description,
          c.category,
          c.photo as club_photo,
          c.adviser,
          c.department
        FROM membership_applications ma
        LEFT JOIN clubs c ON c.id = ma.club_id
        WHERE ma.student_id = ?
        ORDER BY ma.created_at DESC
      `, [studentId]);
      allApplications = applicationsResult.rows || [];
    } catch (appError) {
      console.error("Error fetching applications:", appError);
      allApplications = [];
    }

    // Calculate statistics
    const stats = {
      total: allApplications.length,
      pending: 0,
      approved: 0,
      rejected: 0
    };

    allApplications.forEach(app => {
      const status = (app.status || 'pending').toLowerCase();
      if (status === 'approved') {
        stats.approved++;
      } else if (status === 'rejected') {
        stats.rejected++;
      } else {
        stats.pending++;
      }
    });

    res.render("student/applications", {
      title: "My Applications | UniClub",
      student: student,
      applications: allApplications,
      stats: stats,
      csrfToken: req.csrfToken()
    });
  } catch (error) {
    console.error("Error loading applications page:", error);
    res.render("student/applications", {
      title: "My Applications | UniClub",
      student: req.session.student || {},
      applications: [],
      stats: { total: 0, pending: 0, approved: 0, rejected: 0 },
      csrfToken: req.csrfToken()
    });
  }
});

// Withdraw Application
router.post("/applications/:id/withdraw", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;
    const applicationId = req.params.id;

    if (!studentId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    // Check if application belongs to student and is still pending
    const applicationResult = await pool.query(`
      SELECT id, status, club_id
      FROM membership_applications
      WHERE id = ? AND student_id = ?
    `, [applicationId, studentId]);

    if (applicationResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Application not found" });
    }

    const application = applicationResult.rows[0];
    const status = (application.status || 'pending').toLowerCase();

    // Only allow withdrawal of pending applications
    if (status !== 'pending') {
      return res.status(400).json({ success: false, error: "Only pending applications can be withdrawn" });
    }

    // Delete the application
    await pool.query(`
      DELETE FROM membership_applications
      WHERE id = ? AND student_id = ?
    `, [applicationId, studentId]);

    console.log(`[Withdraw Application] Student ${studentId} withdrew application ${applicationId}`);

    return res.json({ success: true, message: "Application withdrawn successfully" });
  } catch (error) {
    console.error("Error withdrawing application:", error);
    return res.status(500).json({ success: false, error: "Failed to withdraw application" });
  }
});

// Messages Page
router.get("/messages", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;

    if (!studentId) {
      return res.redirect("/student/login");
    }

    // Get all messages
    let messages = [];
    try {
      const messagesResult = await pool.query(`
        SELECT 
          id,
          sender_name as sender,
          sender_email as email,
          subject,
          content as message,
          \`read\` as is_read,
          created_at
        FROM messages
        ORDER BY created_at DESC
      `).catch(() => ({ rows: [] }));
      messages = messagesResult.rows || [];
    } catch (msgError) {
      console.error("Error fetching messages:", msgError);
      messages = [];
    }

    // Get unread count
    const unreadCount = messages.filter(msg => !msg.is_read || msg.is_read === 0).length;

    res.render("student/messages", {
      title: "Messages | UniClub",
      student: student,
      messages: messages,
      unreadCount: unreadCount,
      csrfToken: req.csrfToken()
    });
  } catch (error) {
    console.error("Error loading messages page:", error);
    res.render("student/messages", {
      title: "Messages | UniClub",
      student: req.session.student || {},
      messages: [],
      unreadCount: 0,
      csrfToken: req.csrfToken()
    });
  }
});

// Events Page
router.get("/events", requireStudent, async (req, res) => {
  // Auto-update event statuses before loading events
  await updateEventStatuses();
  
  try {
    const student = req.session.student;
    const studentId = student?.id;

    if (!studentId) {
      return res.redirect("/student/login");
    }

    // Get all events with comprehensive data
    let eventsResult;
    try {
      eventsResult = await pool.query(`
        SELECT 
          e.id,
          e.name,
          e.date,
          e.end_date,
          e.location,
          e.description,
          c.id as club_id,
          c.name as club_name,
          c.category as club_category,
          c.photo as club_photo,
          COALESCE(going_counts.going_count, 0) as going_count,
          COALESCE(interested_counts.interested_count, 0) as interested_count,
          CASE 
            WHEN ea.student_id IS NOT NULL AND (ea.status = 'going' OR ea.status IS NULL) THEN 'going'
            WHEN ea.student_id IS NOT NULL AND ea.status = 'interested' THEN 'interested'
            ELSE 'not_responded'
          END as rsvp_status,
          COALESCE(ea.attendance_status, NULL) as attendance_status,
          -- Use database status if it's a valid final status, otherwise calculate based on dates
          CASE 
            WHEN e.status IN ('Ongoing', 'ongoing', 'Completed', 'completed', 'Cancelled', 'cancelled') THEN e.status
            WHEN e.date IS NULL THEN 'Scheduled'
            WHEN DATE(e.date) > CURDATE() THEN 'Scheduled'
            WHEN DATE(e.date) = CURDATE() OR (DATE(e.date) <= CURDATE() AND COALESCE(DATE(e.end_date), DATE(e.date)) >= CURDATE()) THEN 'Ongoing'
            WHEN COALESCE(DATE(e.end_date), DATE(e.date)) < CURDATE() THEN 'Completed'
            ELSE COALESCE(e.status, 'Scheduled')
          END AS status
        FROM events e
        LEFT JOIN clubs c ON e.club_id = c.id
        LEFT JOIN (
          SELECT event_id, COUNT(*) as going_count
          FROM event_attendance
          WHERE status = 'going' OR status IS NULL
          GROUP BY event_id
        ) going_counts ON going_counts.event_id = e.id
        LEFT JOIN (
          SELECT event_id, COUNT(*) as interested_count
          FROM event_attendance
          WHERE status = 'interested'
          GROUP BY event_id
        ) interested_counts ON interested_counts.event_id = e.id
        LEFT JOIN event_attendance ea ON ea.event_id = e.id AND ea.student_id = ?
        WHERE COALESCE(e.status, 'pending_approval') != 'pending_approval'
          AND COALESCE(e.status, 'pending_approval') != 'rejected'
          AND COALESCE(e.status, '') NOT IN ('Completed', 'completed', 'Cancelled', 'cancelled')
          AND (e.posted_to_students = 1 OR e.posted_to_students IS NULL)
          -- Exclude events that have ended (show only upcoming and ongoing events)
          AND (
            -- Event is upcoming (date in future)
            DATE(e.date) > CURDATE()
            OR
            -- Event is ongoing (date is today or past, but end_date is today or future)
            (DATE(e.date) <= CURDATE() AND (e.end_date IS NULL OR DATE(e.end_date) >= CURDATE()))
          )
        ORDER BY 
          CASE WHEN e.date >= CURRENT_DATE THEN 0 ELSE 1 END,
          e.date ASC
      `, [studentId]);
    } catch (queryError) {
      console.error("Error fetching events:", queryError);
      // Fallback query without attendance data
      try {
        eventsResult = await pool.query(`
          SELECT 
            e.id,
            e.name,
            e.date,
            e.end_date,
            e.location,
            e.description,
            c.id as club_id,
            c.name as club_name,
            c.category as club_category,
            c.photo as club_photo,
            0 as going_count,
            0 as interested_count,
            'not_responded' as rsvp_status,
            -- Use database status if it's a valid final status, otherwise calculate based on dates
            CASE 
              WHEN e.status IN ('Ongoing', 'ongoing', 'Completed', 'completed', 'Cancelled', 'cancelled') THEN e.status
              WHEN e.date IS NULL THEN 'Scheduled'
              WHEN DATE(e.date) > CURDATE() THEN 'Scheduled'
              WHEN DATE(e.date) = CURDATE() OR (DATE(e.date) <= CURDATE() AND COALESCE(DATE(e.end_date), DATE(e.date)) >= CURDATE()) THEN 'Ongoing'
              WHEN COALESCE(DATE(e.end_date), DATE(e.date)) < CURDATE() THEN 'Completed'
              ELSE COALESCE(e.status, 'Scheduled')
            END AS status
          FROM events e
          LEFT JOIN clubs c ON e.club_id = c.id
          WHERE COALESCE(e.status, 'pending_approval') != 'pending_approval'
            AND COALESCE(e.status, 'pending_approval') != 'rejected'
            AND COALESCE(e.status, '') NOT IN ('Completed', 'completed', 'Cancelled', 'cancelled')
            AND (e.posted_to_students = 1 OR e.posted_to_students IS NULL)
            -- Exclude events that have ended (show only upcoming and ongoing events)
            AND (
              -- Event is upcoming (date in future)
              DATE(e.date) > CURDATE()
              OR
              -- Event is ongoing (date is today or past, but end_date is today or future)
              (DATE(e.date) <= CURDATE() AND (e.end_date IS NULL OR DATE(e.end_date) >= CURDATE()))
            )
          ORDER BY 
            CASE WHEN e.date >= CURRENT_DATE THEN 0 ELSE 1 END,
            e.date ASC
        `);
      } catch (fallbackError) {
        console.error("Error in fallback query:", fallbackError);
        eventsResult = { rows: [] };
      }
    }

    const events = (eventsResult.rows || []).map(row => ({
      id: row.id,
      name: row.name,
      date: row.date,
      location: row.location || 'TBA',
      description: row.description || '',
      club_id: row.club_id,
      club_name: row.club_name || 'Unknown Club',
      club_category: row.club_category || 'General',
      club_photo: row.club_photo,
      going_count: Number(row.going_count || 0),
      interested_count: Number(row.interested_count || 0),
      rsvp_status: row.rsvp_status || 'not_responded'
    }));

    // Calculate stats
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const weekStart = new Date(today);
    weekStart.setDate(today.getDate() - today.getDay()); // Start of week (Sunday)
    const weekEnd = new Date(weekStart);
    weekEnd.setDate(weekStart.getDate() + 6); // End of week (Saturday)
    const nextWeekEnd = new Date(weekEnd);
    nextWeekEnd.setDate(weekEnd.getDate() + 7);

    const stats = {
      totalEvents: events.filter(e => e.date && new Date(e.date) >= today).length,
      youGoing: events.filter(e => e.rsvp_status === 'going').length,
      thisWeek: events.filter(e => {
        if (!e.date) return false;
        const eventDate = new Date(e.date);
        return eventDate >= weekStart && eventDate <= weekEnd;
      }).length,
      happeningToday: events.filter(e => {
        if (!e.date) return false;
        const eventDate = new Date(e.date);
        eventDate.setHours(0, 0, 0, 0);
        return eventDate.getTime() === today.getTime();
      }).length
    };

    // Get unique categories and clubs for filters
    const categories = [...new Set(events.map(e => e.club_category).filter(Boolean))];
    const clubs = [...new Set(events.map(e => ({ id: e.club_id, name: e.club_name })).filter(c => c.name))];

    // Get student's clubs for "My Clubs Only" filter
    const myClubsResult = await pool.query(`
      SELECT DISTINCT club_id
      FROM membership_applications
      WHERE student_id = ? AND (status = 'approved' OR status = 'Approved')
    `, [studentId]).catch(() => ({ rows: [] }));
    const myClubIds = (myClubsResult.rows || []).map(r => r.club_id);

    // Get announcements
    const announcementsResult = await pool.query(`
      SELECT id, subject as title, content as message, created_at
      FROM announcements
      WHERE audience = 'All Members' OR audience = 'All Students'
      ORDER BY created_at DESC
      LIMIT 5
    `).catch(() => ({ rows: [] }));
    
    const announcements = announcementsResult.rows || [];

    res.render("student/events", {
      title: "Events | UniClub",
      student: student,
      events: events,
      stats: stats,
      categories: categories,
      clubs: clubs,
      myClubIds: myClubIds,
      announcements: announcements,
      csrfToken: (req.csrfToken && typeof req.csrfToken === 'function') ? req.csrfToken() : (res.locals.csrfToken || '')
    });
  } catch (error) {
    console.error("Error loading events page:", error);
    res.render("student/events", {
      title: "Events | UniClub",
      student: req.session.student || {},
      events: [],
      stats: { totalEvents: 0, youGoing: 0, thisWeek: 0, happeningToday: 0 },
      categories: [],
      clubs: [],
      myClubIds: [],
      announcements: [],
      csrfToken: (req.csrfToken && typeof req.csrfToken === 'function') ? req.csrfToken() : (res.locals.csrfToken || '')
    });
  }
});

// Join Club - Submit Membership Application
router.post("/clubs/join", requireStudent, async (req, res) => {
  // Ensure we always return JSON
  res.setHeader('Content-Type', 'application/json');
  
  try {
    const student = req.session.student;
    const studentId = student?.id;
    
    if (!studentId) {
      return res.status(401).json({ 
        success: false, 
        error: "You must be logged in to join a club" 
      });
    }

    const { club_id, club_name } = req.body;

    if (!club_id) {
      return res.status(400).json({ 
        success: false, 
        error: "Club ID is required" 
      });
    }

    // Convert club_id to number
    const clubId = Number(club_id);
    if (isNaN(clubId)) {
      return res.status(400).json({ 
        success: false, 
        error: "Invalid club ID" 
      });
    }

    // Verify club exists
    const clubCheck = await pool.query(
      "SELECT id, name FROM clubs WHERE id = ? AND (status = 'Active' OR status IS NULL)",
      [clubId]
    );

    if (clubCheck.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: "Club not found or is not active" 
      });
    }

    // Check if student already has a pending or approved application for this club
    const existingApp = await pool.query(
      `SELECT id, status FROM membership_applications 
       WHERE student_id = ? AND club_id = ? 
       AND (status IS NULL OR status = 'pending' OR status = 'approved' OR status = 'Approved')`,
      [studentId, clubId]
    ).catch(() => ({ rows: [] }));

    if (existingApp.rows.length > 0) {
      const app = existingApp.rows[0];
      if (app.status === 'approved' || app.status === 'Approved') {
        return res.status(400).json({ 
          success: false, 
          error: "You are already a member of this club" 
        });
      } else {
        return res.status(400).json({ 
          success: false, 
          error: "⏳ You already have a pending application for this club. Please wait for the club officers to review your request before submitting another application." 
        });
      }
    }

    // Get student's name
    const studentName = student.name || `${student.first_name || ''} ${student.last_name || ''}`.trim() || 'Student';

    // Get student's current club count (approved applications)
    const currentClubsResult = await pool.query(
      `SELECT COUNT(*) as count FROM membership_applications 
       WHERE student_id = ? AND (status = 'approved' OR status = 'Approved')`,
      [studentId]
    ).catch(() => ({ rows: [{ count: 0 }] }));
    
    const currentClubs = Number(currentClubsResult.rows[0]?.count || 0);

    // Ensure membership_applications table exists with required columns
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS membership_applications (
          id INT AUTO_INCREMENT PRIMARY KEY,
          student_id INT NOT NULL,
          club_id INT NOT NULL,
          name VARCHAR(255) NOT NULL,
          applying_for VARCHAR(255),
          current_clubs INT DEFAULT 0,
          status VARCHAR(50) DEFAULT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          INDEX idx_student_id (student_id),
          INDEX idx_club_id (club_id),
          INDEX idx_status (status)
        )
      `);
    } catch (tableError) {
      // Table might already exist, try to add missing columns
      try {
        await pool.query(`ALTER TABLE membership_applications ADD COLUMN IF NOT EXISTS name VARCHAR(255)`);
        await pool.query(`ALTER TABLE membership_applications ADD COLUMN IF NOT EXISTS applying_for VARCHAR(255)`);
        await pool.query(`ALTER TABLE membership_applications ADD COLUMN IF NOT EXISTS current_clubs INT DEFAULT 0`);
        await pool.query(`ALTER TABLE membership_applications ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT NULL`);
        await pool.query(`ALTER TABLE membership_applications ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);
      } catch (alterError) {
        // Columns might already exist, continue
        console.log('Note: Some columns may already exist in membership_applications table');
      }
    }

    // Insert the membership application
    await pool.query(
      `INSERT INTO membership_applications (student_id, club_id, name, applying_for, current_clubs, status, created_at)
       VALUES (?, ?, ?, ?, ?, NULL, NOW())`,
      [studentId, clubId, studentName, club_name || 'Membership', currentClubs]
    );

    console.log(`[Join Club] Student ${studentId} (${studentName}) applied to join club ${clubId}`);

    return res.json({ 
      success: true, 
      message: `Your application to join ${club_name || 'the club'} has been submitted successfully.` 
    });
  } catch (error) {
    console.error("Error submitting join request:", error);
    return res.status(500).json({ 
      success: false, 
      error: "An error occurred while submitting your application. Please try again." 
    });
  }
});

// Leave Club
router.post("/clubs/leave", requireStudent, async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  
  try {
    const student = req.session.student;
    const studentId = student?.id;
    const { club_id } = req.body;

    if (!studentId) {
      return res.status(401).json({ 
        success: false, 
        error: "You must be logged in to leave a club" 
      });
    }

    if (!club_id || isNaN(parseInt(club_id))) {
      return res.status(400).json({ 
        success: false, 
        error: "Invalid club ID" 
      });
    }

    const clubId = parseInt(club_id);

    // Verify student is a member
    const membershipResult = await pool.query(`
      SELECT id, status
      FROM membership_applications
      WHERE student_id = ? AND club_id = ?
      ORDER BY created_at DESC
      LIMIT 1
    `, [studentId, clubId]);

    if (membershipResult.rows.length === 0 || 
        (membershipResult.rows[0].status !== 'approved' && membershipResult.rows[0].status !== 'Approved')) {
      return res.status(400).json({ 
        success: false, 
        error: "You are not a member of this club" 
      });
    }

    // Get club and president info
    const clubResult = await pool.query(`
      SELECT c.id, c.name, o.id as president_id, o.first_name, o.last_name
      FROM clubs c
      LEFT JOIN officers o ON o.club_id = c.id AND LOWER(TRIM(o.role)) LIKE '%president%'
      WHERE c.id = ?
      LIMIT 1
    `, [clubId]);

    if (clubResult.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: "Club not found" 
      });
    }

    const club = clubResult.rows[0];
    const presidentId = club.president_id;
    const studentName = `${student.first_name || ''} ${student.last_name || ''}`.trim() || student.email || 'A student';

    // Update membership status to 'left' or delete the record
    // We'll update status to 'left' to keep a record
    await pool.query(`
      UPDATE membership_applications
      SET status = 'left'
      WHERE student_id = ? AND club_id = ?
    `, [studentId, clubId]);

    // Send notification message to president if president exists
    if (presidentId) {
      try {
        // Ensure messages table has modern columns
        const columnCheck = await pool.query(`
          SELECT COLUMN_NAME 
          FROM INFORMATION_SCHEMA.COLUMNS 
          WHERE TABLE_SCHEMA = DATABASE() 
          AND TABLE_NAME = 'messages' 
          AND COLUMN_NAME IN ('sender_id', 'receiver_id', 'sender_type', 'receiver_type')
        `).catch(() => ({ rows: [] }));

        const foundColumns = columnCheck.rows.map(r => r.COLUMN_NAME);
        const hasModernColumns = ['sender_id', 'receiver_id', 'sender_type', 'receiver_type'].every(col => foundColumns.includes(col));

        if (hasModernColumns) {
          await pool.query(`
            INSERT INTO messages (sender_id, receiver_id, sender_type, receiver_type, sender_name, subject, content, created_at)
            VALUES (?, ?, 'student', 'officer', ?, ?, ?, NOW())
          `, [
            studentId,
            presidentId,
            studentName,
            `Student Left ${club.name}`,
            `${studentName} has left ${club.name}. They are no longer a member of the club.`
          ]);
        } else {
          // Fallback to old message structure
          await pool.query(`
            INSERT INTO messages (sender_name, sender_email, subject, content, created_at)
            VALUES (?, ?, ?, ?, NOW())
          `, [
            studentName,
            student.email || '',
            `Student Left ${club.name}`,
            `${studentName} has left ${club.name}. They are no longer a member of the club.`
          ]);
        }
      } catch (msgError) {
        console.error("Error sending notification to president:", msgError);
        // Don't fail the leave request if message sending fails
      }
    }

    console.log(`[Leave Club] Student ${studentId} (${studentName}) left club ${clubId} (${club.name})`);

    return res.json({ 
      success: true, 
      message: `You have successfully left ${club.name}. The club president has been notified.` 
    });
  } catch (error) {
    console.error("Error leaving club:", error);
    return res.status(500).json({ 
      success: false, 
      error: "Failed to leave the club. Please try again." 
    });
  }
});

// RSVP to Event
router.post("/events/:id/rsvp", requireStudent, async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  
  try {
    const student = req.session.student;
    const studentId = student?.id;
    
    if (!studentId) {
      return res.status(401).json({ 
        success: false, 
        error: "You must be logged in to RSVP to events" 
      });
    }

    const eventId = parseInt(req.params.id);
    const { action, status } = req.body; // action: 'going', 'interested', 'cancel'

    if (!eventId || isNaN(eventId)) {
      return res.status(400).json({ 
        success: false, 
        error: "Invalid event ID" 
      });
    }

    // Verify event exists and is posted
    const { rows: eventRows } = await pool.query(
      `SELECT id, status, posted_to_students 
       FROM events 
       WHERE id = ? 
         AND COALESCE(status, 'pending_approval') != 'pending_approval'
         AND COALESCE(status, 'pending_approval') != 'rejected'
         AND (posted_to_students = 1 OR posted_to_students IS NULL)`,
      [eventId]
    );

    if (eventRows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: "Event not found or not available for RSVP" 
      });
    }

    // Determine RSVP status
    let rsvpStatus = null;
    if (action === 'cancel') {
      rsvpStatus = null; // Remove RSVP
    } else if (status === 'interested') {
      rsvpStatus = 'interested';
    } else {
      rsvpStatus = 'going'; // Default to 'going'
    }

    // Ensure event_attendance table exists
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS event_attendance (
          id INT AUTO_INCREMENT PRIMARY KEY,
          event_id INT NOT NULL,
          student_id INT NOT NULL,
          status VARCHAR(50) DEFAULT 'going',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          UNIQUE KEY unique_event_student (event_id, student_id),
          INDEX idx_event_id (event_id),
          INDEX idx_student_id (student_id)
        )
      `);
    } catch (tableError) {
      // Table might already exist, continue
      console.log("Event attendance table check:", tableError.message);
    }

    if (rsvpStatus === null) {
      // Remove RSVP
      await pool.query(
        `DELETE FROM event_attendance WHERE event_id = ? AND student_id = ?`,
        [eventId, studentId]
      );
      
      return res.json({ 
        success: true, 
        message: "RSVP removed successfully",
        rsvp_status: 'not_responded'
      });
    } else {
      // Insert or update RSVP
      await pool.query(
        `INSERT INTO event_attendance (event_id, student_id, status, created_at, updated_at)
         VALUES (?, ?, ?, NOW(), NOW())
         ON DUPLICATE KEY UPDATE 
           status = VALUES(status),
           updated_at = NOW()`,
        [eventId, studentId, rsvpStatus]
      );
      
      return res.json({ 
        success: true, 
        message: `You are now ${rsvpStatus === 'going' ? 'going' : 'interested'} in this event`,
        rsvp_status: rsvpStatus
      });
    }
  } catch (error) {
    console.error("Error processing RSVP:", error);
    return res.status(500).json({ 
      success: false, 
      error: "An error occurred while processing your RSVP. Please try again." 
    });
  }
});

// Leave Club - Remove Membership
router.post("/clubs/leave", requireStudent, async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  
  try {
    const student = req.session.student;
    const studentId = student?.id;
    
    if (!studentId) {
      return res.status(401).json({ 
        success: false, 
        error: "You must be logged in to leave a club" 
      });
    }

    const { club_id } = req.body;

    if (!club_id) {
      return res.status(400).json({ 
        success: false, 
        error: "Club ID is required" 
      });
    }

    const clubId = Number(club_id);
    if (isNaN(clubId)) {
      return res.status(400).json({ 
        success: false, 
        error: "Invalid club ID" 
      });
    }

    // Verify student is a member of this club
    const membershipCheck = await pool.query(
      `SELECT id, status FROM membership_applications 
       WHERE student_id = ? AND club_id = ? 
       AND (status = 'approved' OR status = 'Approved')`,
      [studentId, clubId]
    ).catch(() => ({ rows: [] }));

    if (membershipCheck.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: "You are not a member of this club" 
      });
    }

    // Get club name for response
    const clubResult = await pool.query(
      "SELECT name FROM clubs WHERE id = ?",
      [clubId]
    ).catch(() => ({ rows: [] }));
    
    const clubName = clubResult.rows[0]?.name || 'the club';

    // Delete or update the membership application
    // Option 1: Delete the membership
    await pool.query(
      `DELETE FROM membership_applications 
       WHERE student_id = ? AND club_id = ? 
       AND (status = 'approved' OR status = 'Approved')`,
      [studentId, clubId]
    );

    console.log(`[Leave Club] Student ${studentId} left club ${clubId}`);

    return res.json({ 
      success: true, 
      message: `You have successfully left ${clubName}.` 
    });
  } catch (error) {
    console.error("Error leaving club:", error);
    return res.status(500).json({ 
      success: false, 
      error: "An error occurred while leaving the club. Please try again." 
    });
  }
});

// Messages Page
router.get("/messages", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;

    if (!studentId) {
      return res.redirect("/student/login");
    }

    // Ensure messages table has modern columns
    const columnsToAdd = [
      { name: 'sender_id', def: 'INT' },
      { name: 'receiver_id', def: 'INT' },
      { name: 'sender_type', def: "VARCHAR(20) DEFAULT 'student'" },
      { name: 'receiver_type', def: "VARCHAR(20) DEFAULT 'officer'" }
    ];

    for (const col of columnsToAdd) {
      try {
        await pool.query(`ALTER TABLE messages ADD COLUMN ${col.name} ${col.def}`);
      } catch (err) {
        // Ignore duplicate column errors
        if (err.code !== 'ER_DUP_FIELDNAME' && err.errno !== 1060) {
          console.warn(`Warning: Could not add column ${col.name}:`, err.message);
        }
      }
    }

    const conversationId = req.query.conversation;

    // Get clubs the student is a member of
    const myClubsResult = await pool.query(`
      SELECT DISTINCT c.id, c.name
      FROM clubs c
      INNER JOIN membership_applications ma ON ma.club_id = c.id
      WHERE ma.student_id = ? AND (ma.status = 'approved' OR ma.status = 'Approved')
    `, [studentId]).catch(() => ({ rows: [] }));

    const myClubIds = myClubsResult.rows.map(c => c.id);
    const clubs = myClubsResult.rows || [];

    // Get conversations (officers from student's clubs + admin)
    let conversations = [];
    
    // Add Admin as a conversation (special ID: -1 or 'admin')
    const adminConversation = {
      id: 'admin',
      name: 'Admin',
      role: 'Administrator',
      club_id: null,
      club_name: 'UniClub System',
      photo: null,
      is_online: 1,
      type: 'admin'
    };
    
    // Get officers from student's clubs
    if (myClubIds.length > 0) {
      const conversationsResult = await pool.query(`
        SELECT 
          o.id,
          o.first_name,
          o.last_name,
          o.role,
          o.club_id,
          c.name as club_name,
          c.photo as club_photo,
          CONCAT(o.first_name, ' ', o.last_name) as name,
          CASE WHEN o.id IS NOT NULL THEN 1 ELSE 0 END as is_online
        FROM officers o
        INNER JOIN clubs c ON c.id = o.club_id
        WHERE o.club_id IN (${myClubIds.map(() => '?').join(',')})
        ORDER BY o.role ASC, o.first_name ASC
      `, myClubIds).catch(() => ({ rows: [] }));

      // Get last message and unread count for each conversation
      // Check if messages table has all modern columns
      const columnCheck = await pool.query(`
        SELECT COLUMN_NAME 
        FROM INFORMATION_SCHEMA.COLUMNS 
        WHERE TABLE_SCHEMA = DATABASE() 
        AND TABLE_NAME = 'messages' 
        AND COLUMN_NAME IN ('sender_id', 'receiver_id', 'sender_type', 'receiver_type')
      `).catch(() => ({ rows: [] }));

      const foundColumns = columnCheck.rows.map(r => r.COLUMN_NAME);
      const hasModernColumns = ['sender_id', 'receiver_id', 'sender_type', 'receiver_type'].every(col => foundColumns.includes(col));
      
      // Add admin conversation with last message and unread count
      if (hasModernColumns) {
        // Get admin messages (using recipient_id/recipient_type for old admin messages, or sender_type='admin')
        const adminLastMessageResult = await pool.query(`
          SELECT content, created_at
          FROM messages
          WHERE (
            (receiver_id = ? AND receiver_type = 'student' AND (sender_type = 'admin' OR sender_name = 'Admin'))
            OR (sender_id = ? AND sender_type = 'student' AND receiver_type = 'admin')
          )
          ORDER BY created_at DESC
          LIMIT 1
        `, [studentId, studentId]).catch(() => ({ rows: [] }));
        
        adminConversation.last_message = adminLastMessageResult.rows[0]?.content || null;
        adminConversation.last_message_time = adminLastMessageResult.rows[0]?.created_at || null;
        
        // Count unread admin messages
        const adminUnreadResult = await pool.query(`
          SELECT COUNT(*) as count
          FROM messages
          WHERE receiver_id = ? AND receiver_type = 'student'
          AND (sender_type = 'admin' OR sender_name = 'Admin')
          AND (\`read\` = 0 OR \`read\` IS NULL)
        `, [studentId]).catch(() => ({ rows: [{ count: 0 }] }));
        
        adminConversation.unread_count = Number(adminUnreadResult.rows[0]?.count || 0);
      }

      for (const conv of conversationsResult.rows) {
        let lastMessage = null;
        let unreadCount = 0;

        if (hasModernColumns) {
          // Use modern structure with sender_id/receiver_id
          const lastMessageResult = await pool.query(`
            SELECT content, created_at
            FROM messages
            WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
            AND (sender_type = 'student' OR sender_type = 'officer')
            AND (receiver_type = 'student' OR receiver_type = 'officer')
            ORDER BY created_at DESC
            LIMIT 1
          `, [studentId, conv.id, conv.id, studentId]).catch(() => ({ rows: [] }));

          lastMessage = lastMessageResult.rows[0] || null;

          const unreadResult = await pool.query(`
            SELECT COUNT(*) as count
            FROM messages
            WHERE sender_id = ? AND receiver_id = ? 
            AND sender_type = 'officer' AND receiver_type = 'student'
            AND (\`read\` = 0 OR \`read\` IS NULL)
          `, [conv.id, studentId]).catch(() => ({ rows: [{ count: 0 }] }));

          unreadCount = Number(unreadResult.rows[0]?.count || 0);
        } else {
          // Fallback: use sender_name/recipient_name if available
          const studentName = `${student.first_name || ''} ${student.last_name || ''}`.trim();
          const officerName = conv.name;
          
          const lastMessageResult = await pool.query(`
            SELECT content, created_at
            FROM messages
            WHERE (sender_name = ? OR sender_name = ?)
            ORDER BY created_at DESC
            LIMIT 1
          `, [studentName, officerName]).catch(() => ({ rows: [] }));

          lastMessage = lastMessageResult.rows[0] || null;
        }

        conversations.push({
          id: conv.id,
          name: conv.name,
          role: conv.role,
          club_id: conv.club_id,
          club_name: conv.club_name,
          photo: conv.photo || conv.club_photo,
          is_online: conv.is_online,
          type: 'officer',
          last_message: lastMessage ? lastMessage.content : null,
          last_message_time: lastMessage ? lastMessage.created_at : null,
          unread_count: unreadCount
        });
      }
    }
    
    // Add admin at the beginning of conversations
    conversations.unshift(adminConversation);

    // Get active conversation and its messages
    let activeConversation = null;
    let activeMessages = [];

    if (conversationId) {
      activeConversation = conversations.find(c => String(c.id) === String(conversationId));
      
      if (activeConversation) {
        // Check if messages table has modern columns
        const columnCheck = await pool.query(`
          SELECT COLUMN_NAME 
          FROM INFORMATION_SCHEMA.COLUMNS 
          WHERE TABLE_SCHEMA = DATABASE() 
          AND TABLE_NAME = 'messages' 
          AND COLUMN_NAME IN ('sender_id', 'receiver_id', 'sender_type', 'receiver_type')
        `).catch(() => ({ rows: [] }));

        const foundColumns = columnCheck.rows.map(r => r.COLUMN_NAME);
        const hasModernColumns = ['sender_id', 'receiver_id', 'sender_type', 'receiver_type'].every(col => foundColumns.includes(col));

        if (hasModernColumns) {
          if (activeConversation.type === 'admin') {
            // Get all messages between student and admin
            const messagesResult = await pool.query(`
              SELECT 
                m.id,
                m.content,
                m.sender_id,
                m.receiver_id,
                m.sender_type,
                m.receiver_type,
                m.sender_name,
                m.created_at,
                CASE 
                  WHEN m.sender_type = 'student' THEN CONCAT(s.first_name, ' ', s.last_name)
                  WHEN m.sender_type = 'admin' THEN COALESCE(m.sender_name, 'Admin')
                  ELSE 'Unknown'
                END as sender_name_display
              FROM messages m
              LEFT JOIN students s ON s.id = m.sender_id AND m.sender_type = 'student'
              WHERE (
                (m.receiver_id = ? AND m.receiver_type = 'student' AND (m.sender_type = 'admin' OR m.sender_name = 'Admin'))
                OR (m.sender_id = ? AND m.sender_type = 'student' AND m.receiver_type = 'admin')
              )
              ORDER BY m.created_at ASC
            `, [studentId, studentId]).catch(() => ({ rows: [] }));

            activeMessages = messagesResult.rows.map(msg => ({
              ...msg,
              is_student: msg.sender_type === 'student',
              is_admin: msg.sender_type === 'admin' || msg.sender_name === 'Admin'
            }));

            // Mark admin messages as read
            await pool.query(`
              UPDATE messages
              SET \`read\` = 1
              WHERE receiver_id = ? AND receiver_type = 'student'
              AND (sender_type = 'admin' OR sender_name = 'Admin')
              AND (\`read\` = 0 OR \`read\` IS NULL)
            `, [studentId]).catch(() => {});
          } else {
            // Get all messages between student and officer
            const messagesResult = await pool.query(`
              SELECT 
                m.id,
                m.content,
                m.sender_id,
                m.receiver_id,
                m.sender_type,
                m.receiver_type,
                m.created_at,
                CASE 
                  WHEN m.sender_id = ? AND m.sender_type = 'student' THEN CONCAT(s.first_name, ' ', s.last_name)
                  WHEN m.sender_id = ? AND m.sender_type = 'officer' THEN CONCAT(o.first_name, ' ', o.last_name)
                  ELSE 'Unknown'
                END as sender_name
              FROM messages m
              LEFT JOIN students s ON s.id = m.sender_id AND m.sender_type = 'student'
              LEFT JOIN officers o ON o.id = m.sender_id AND m.sender_type = 'officer'
              WHERE ((m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?))
              AND (m.sender_type = 'student' OR m.sender_type = 'officer')
              AND (m.receiver_type = 'student' OR m.receiver_type = 'officer')
              ORDER BY m.created_at ASC
            `, [studentId, conversationId, studentId, conversationId, conversationId, studentId]).catch(() => ({ rows: [] }));

            activeMessages = messagesResult.rows.map(msg => ({
              ...msg,
              is_student: msg.sender_type === 'student',
              is_officer: msg.sender_type === 'officer'
            }));

            // Mark messages as read
            await pool.query(`
              UPDATE messages
              SET \`read\` = 1
              WHERE sender_id = ? AND receiver_id = ? 
              AND sender_type = 'officer' AND receiver_type = 'student'
              AND (\`read\` = 0 OR \`read\` IS NULL)
            `, [conversationId, studentId]).catch(() => {});
          }
        } else {
          // Fallback: return empty messages for now (table structure needs to be updated)
          activeMessages = [];
        }
      }
    }

    // Get announcements for notifications
    const announcementsResult = await pool.query(`
      SELECT id, subject as title, content as message, created_at
      FROM announcements
      WHERE audience = 'All Members' OR audience = 'All Students'
      ORDER BY created_at DESC
      LIMIT 20
    `).catch(() => ({ rows: [] }));
    
    const announcements = announcementsResult.rows || [];

    // Get unread messages count (from both officers and admin)
    let unreadMessagesCount = 0;
    try {
      const columnCheck = await pool.query(`
        SELECT COLUMN_NAME 
        FROM INFORMATION_SCHEMA.COLUMNS 
        WHERE TABLE_SCHEMA = DATABASE() 
        AND TABLE_NAME = 'messages' 
        AND COLUMN_NAME = 'receiver_id'
      `).catch(() => ({ rows: [] }));

      if (columnCheck.rows.length > 0) {
        const unreadResult = await pool.query(`
          SELECT COUNT(*) as count
          FROM messages
          WHERE receiver_id = ? AND receiver_type = 'student'
          AND (\`read\` = 0 OR \`read\` IS NULL)
        `, [studentId]).catch(() => ({ rows: [{ count: 0 }] }));
        unreadMessagesCount = Number(unreadResult.rows[0]?.count || 0);
      } else {
        // Count unread from conversations (includes admin)
        unreadMessagesCount = conversations.reduce((sum, conv) => sum + (conv.unread_count || 0), 0);
      }
    } catch (e) {
      unreadMessagesCount = 0;
    }

    res.render("student/messages", {
      title: "Messages | UniClub",
      student: student,
      conversations: conversations,
      activeConversation: activeConversation,
      activeMessages: activeMessages,
      clubs: clubs,
      announcements: announcements,
      unreadMessagesCount: unreadMessagesCount,
      csrfToken: (req.csrfToken && typeof req.csrfToken === 'function') ? req.csrfToken() : (res.locals.csrfToken || '')
    });
  } catch (error) {
    console.error("Error loading messages page:", error);
    res.status(500).render("errors/500", { title: "Server Error", error });
  }
});

// Send Message Route
router.post("/messages/send", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;
    const { conversation_id, message } = req.body;

    if (!studentId || !conversation_id || !message || !message.trim()) {
      return res.status(400).json({ success: false, error: "Missing required fields" });
    }

    // Ensure messages table has modern columns
    const columnsToAdd = [
      { name: 'sender_id', def: 'INT' },
      { name: 'receiver_id', def: 'INT' },
      { name: 'sender_type', def: "VARCHAR(20) DEFAULT 'student'" },
      { name: 'receiver_type', def: "VARCHAR(20) DEFAULT 'officer'" }
    ];

    for (const col of columnsToAdd) {
      try {
        await pool.query(`ALTER TABLE messages ADD COLUMN ${col.name} ${col.def}`);
      } catch (err) {
        // Ignore duplicate column errors
        if (err.code !== 'ER_DUP_FIELDNAME' && err.errno !== 1060) {
          console.warn(`Warning: Could not add column ${col.name}:`, err.message);
        }
      }
    }

    // Handle sending to admin or officer
    if (conversation_id === 'admin' || String(conversation_id) === 'admin') {
      // Send message to admin
      await pool.query(`
        INSERT INTO messages (sender_id, receiver_id, sender_type, receiver_type, content, \`read\`, created_at)
        VALUES (?, NULL, 'student', 'admin', ?, 0, NOW())
      `, [studentId, message.trim()]);
    } else {
      // Verify the conversation_id is a valid officer ID
      const officerCheck = await pool.query(`
        SELECT id FROM officers WHERE id = ?
      `, [conversation_id]).catch(() => ({ rows: [] }));

      if (officerCheck.rows.length === 0) {
        return res.status(404).json({ success: false, error: "Officer not found" });
      }

      // Insert message with modern structure
      await pool.query(`
        INSERT INTO messages (sender_id, receiver_id, sender_type, receiver_type, content, \`read\`, created_at)
        VALUES (?, ?, 'student', 'officer', ?, 0, NOW())
      `, [studentId, conversation_id, message.trim()]);
    }

    res.json({ success: true });
  } catch (error) {
    console.error("Error sending message:", error);
    res.status(500).json({ success: false, error: "Failed to send message" });
  }
});

// Student Settings/Profile Page
router.get("/profile", requireStudent, async (req, res) => {
  console.log("[Profile Route] GET /student/profile called");
  console.log("[Profile Route] Session student:", req.session.student ? { id: req.session.student.id, email: req.session.student.email } : "No student in session");
  
  try {
    const student = req.session.student;
    const studentId = student?.id;

    if (!studentId) {
      console.log("[Profile Route] No studentId, redirecting to login");
      return res.redirect("/student/login");
    }
    
    console.log("[Profile Route] Processing profile for studentId:", studentId);

    // Fetch student data - only query columns that definitely exist
    // This avoids errors if profile columns haven't been added yet
    const { rows } = await pool.query(
      `SELECT 
        id,
        first_name,
        last_name,
        email,
        studentid,
        department,
        program,
        year_level,
        birthdate,
        created_at,
        profile_picture
      FROM students 
      WHERE id = ?`,
      [studentId]
    );
    
    // Try to add profile columns if they don't exist (non-blocking)
    // Do this in the background so it doesn't slow down the request
    const columnsToAdd = [
      { name: 'bio', type: 'TEXT' },
      { name: 'phone', type: 'VARCHAR(20)' },
      { name: 'discord', type: 'VARCHAR(100)' },
      { name: 'skills', type: 'JSON' },
      { name: 'interests', type: 'JSON' },
      { name: 'social_links', type: 'JSON' },
      { name: 'profile_picture', type: 'MEDIUMTEXT' },
      { name: 'location', type: 'VARCHAR(255)' }
    ];
    
    // Add columns asynchronously (don't wait for it)
    Promise.all(columnsToAdd.map(async (col) => {
      try {
        await pool.query(`ALTER TABLE students ADD COLUMN ${col.name} ${col.type}`);
      } catch (err) {
        // Ignore "Duplicate column name" errors (column already exists)
        if (err.code !== 'ER_DUP_FIELDNAME' && err.errno !== 1060) {
          // Only log non-duplicate errors
          console.warn(`[Profile Route] Could not add column ${col.name}:`, err.message);
        }
      }
    })).catch(() => {}); // Don't let column creation errors affect the request

    let studentData = rows[0] || student;
    
    // Ensure studentData exists
    if (!studentData) {
      console.error("[Profile Route] No student data found");
      return res.status(404).render("errors/404", { 
        title: "Profile Not Found",
        error: "Student profile not found"
      });
    }
    
    // Initialize all profile fields with defaults (these columns may not exist yet)
    // The profile page will work fine with these defaults
    studentData.bio = studentData.bio || null;
    studentData.phone = studentData.phone || null;
    studentData.discord = studentData.discord || null;
    studentData.skills = studentData.skills || [];
    studentData.interests = studentData.interests || [];
    studentData.social_links = studentData.social_links || {};
    studentData.profile_picture = studentData.profile_picture || null;
    studentData.location = studentData.location || null;

    // Parse JSON fields
    if (studentData.skills && typeof studentData.skills === 'string') {
      try {
        studentData.skills = JSON.parse(studentData.skills);
      } catch (e) {
        studentData.skills = [];
      }
    }
    if (studentData.interests && typeof studentData.interests === 'string') {
      try {
        studentData.interests = JSON.parse(studentData.interests);
      } catch (e) {
        studentData.interests = [];
      }
    }
    if (studentData.social_links && typeof studentData.social_links === 'string') {
      try {
        studentData.social_links = JSON.parse(studentData.social_links);
      } catch (e) {
        studentData.social_links = {};
      }
    }

    // Get student stats
    let clubsJoined = 0;
    let eventsAttended = 0;
    let points = 0;
    let badges = 0;

    try {
      // Get clubs joined count (case-insensitive check for approved status)
      const clubsResult = await pool.query(`
        SELECT COUNT(*) as count
        FROM membership_applications
        WHERE student_id = ? AND LOWER(COALESCE(status, '')) = 'approved'
      `, [studentId]).catch(() => ({ rows: [{ count: 0 }] }));
      clubsJoined = Number(clubsResult.rows[0]?.count || 0);
      
      console.log(`[Profile] Student ${studentId} - clubsJoined count: ${clubsJoined}`);

      // Get events attended count
      const eventsResult = await pool.query(`
        SELECT COUNT(*) as count
        FROM event_attendance
        WHERE student_id = ?
      `, [studentId]).catch(() => ({ rows: [{ count: 0 }] }));
      eventsAttended = Number(eventsResult.rows[0]?.count || 0);

      // Get points - ensure table exists first
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
        `).catch((e) => {
          console.log("[Profile] Note: student_points table creation:", e.message);
        });
        
        // Debug: Check if table exists and has data
        const tableCheck = await pool.query(`
          SELECT COUNT(*) as count FROM student_points WHERE student_id = ?
        `, [studentId]).catch(() => ({ rows: [{ count: 0 }] }));
        console.log(`[Profile] Student ${studentId} has ${tableCheck.rows[0]?.count || 0} point records`);
        
      } catch (e) {
        console.error("[Profile] Error with student_points table:", e);
      }
      
      const pointsResult = await pool.query(`
        SELECT COALESCE(SUM(points), 0) as total
        FROM student_points
        WHERE student_id = ?
      `, [studentId]).catch((e) => {
        console.error("[Profile] Error fetching points:", e);
        return { rows: [{ total: 0 }] };
      });
      points = Number(pointsResult.rows[0]?.total || 0);
      console.log(`[Profile] Student ${studentId} total points: ${points}`);

      // Get badges (if there's a badges table)
      const badgesResult = await pool.query(`
        SELECT COUNT(*) as count
        FROM student_badges
        WHERE student_id = ?
      `, [studentId]).catch(() => ({ rows: [{ count: 0 }] }));
      badges = Number(badgesResult.rows[0]?.count || 0);
    } catch (e) {
      console.error("Error fetching student stats:", e);
    }

    // Add stats to studentData
    studentData.clubsJoined = clubsJoined;
    studentData.eventsAttended = eventsAttended;
    studentData.points = points;
    studentData.badges = badges;

    // Get student's clubs with details for the Clubs tab
    let myClubs = [];
    try {
      // First, debug: Check what applications exist and their statuses
      const debugQuery = await pool.query(`
        SELECT id, club_id, status, student_id, created_at
        FROM membership_applications
        WHERE student_id = ?
      `, [studentId]).catch(() => ({ rows: [] }));
      
      console.log(`[Profile Route] DEBUG: Student ${studentId} has ${debugQuery.rows.length} total applications`);
      debugQuery.rows.forEach(app => {
        console.log(`  - Application ${app.id}: club_id=${app.club_id}, status="${app.status}" (lowercase: "${String(app.status || '').toLowerCase()}")`);
      });
      
      // Get all approved applications first (matching the count query exactly)
      const approvedApps = await pool.query(`
        SELECT id, club_id, status, created_at
        FROM membership_applications
        WHERE student_id = ? AND LOWER(COALESCE(status, '')) = 'approved'
      `, [studentId]).catch(() => ({ rows: [] }));
      
      console.log(`[Profile Route] DEBUG: Found ${approvedApps.rows.length} approved applications`);
      
      if (approvedApps.rows.length > 0) {
        // Now get club details for each approved application
        const clubIds = approvedApps.rows.map(app => app.club_id).filter(id => id != null);
        console.log(`[Profile Route] DEBUG: Club IDs to fetch:`, clubIds);
        
        if (clubIds.length > 0) {
          // Fetch clubs and their details
          const placeholders = clubIds.map(() => '?').join(',');
          const myClubsResult = await pool.query(`
            SELECT 
              c.id,
              c.name,
              c.description,
              c.category,
              c.department,
              c.photo,
              c.status as club_status,
              COALESCE(member_counts.member_count, 0) as member_count,
              COALESCE(e_counts.event_count, 0) as event_count
            FROM clubs c
            LEFT JOIN (
              SELECT club_id, COUNT(*) as member_count
              FROM membership_applications
              WHERE LOWER(COALESCE(status, '')) = 'approved'
              GROUP BY club_id
            ) member_counts ON member_counts.club_id = c.id
            LEFT JOIN (
              SELECT club_id, COUNT(*) as event_count
              FROM events
              GROUP BY club_id
            ) e_counts ON e_counts.club_id = c.id
            WHERE c.id IN (${placeholders})
          `, clubIds).catch((err) => {
            console.error("[Profile Route] Error fetching club details:", err);
            return { rows: [] };
          });
          
          // Match clubs with their join dates
          myClubs = myClubsResult.rows.map(club => {
            const app = approvedApps.rows.find(a => a.club_id === club.id);
            return {
              id: club.id,
              name: club.name,
              description: club.description,
              category: club.category,
              department: club.department,
              photo: club.photo,
              member_count: club.member_count || 0,
              event_count: club.event_count || 0,
              joined_date: app ? app.created_at : null,
              application_status: app ? app.status : null,
              club_status: club.club_status
            };
          });
          
          console.log(`[Profile Route] Successfully fetched ${myClubs.length} clubs with details`);
        }
      }
    } catch (err) {
      console.error("[Profile Route] Error fetching student clubs:", err);
      console.error("[Profile Route] Error stack:", err.stack);
      myClubs = [];
    }

    // Get announcements for navbar
    let announcements = [];
    try {
      const announcementsResult = await pool.query(`
        SELECT id, title, message, content, created_at, audience
        FROM announcements
        WHERE (audience = 'All Members' OR audience = 'Students')
        ORDER BY created_at DESC
        LIMIT 10
      `).catch(() => ({ rows: [] }));
      announcements = announcementsResult.rows || [];
    } catch (err) {
      console.error("Error fetching announcements:", err);
    }

    console.log(`[Profile Route] Rendering profile page for student ${studentId}`);
    console.log(`[Profile Route] Student data:`, {
      id: studentData?.id,
      first_name: studentData?.first_name,
      last_name: studentData?.last_name,
      email: studentData?.email
    });
    console.log(`[Profile Route] Clubs data being passed to template:`, {
      clubsJoined: clubsJoined,
      myClubsCount: myClubs.length,
      myClubs: myClubs.map(c => ({ id: c.id, name: c.name }))
    });

    res.render("student/profile", {
      title: "Profile | UniClub",
      student: studentData,
      user: studentData, // profile.ejs expects both student and user
      announcements: announcements,
      myClubs: myClubs, // Clubs the student has joined
      clubsJoined: clubsJoined, // Total count
      activeTab: req.query.tab || 'about', // Get active tab from query or default to 'about'
      csrfToken: res.locals.csrfToken || req.csrfToken?.() || '',
      success: req.query.success || null,
      error: req.query.error || null,
    });
  } catch (error) {
    console.error("Error loading student profile:", error);
    console.error("Error stack:", error.stack);
    // Instead of redirecting, show error page or return error
    res.status(500).render("errors/500", { 
      title: "Error Loading Profile",
      error: error.message || "An error occurred while loading your profile"
    });
  }
});

// Update Student Profile
router.post("/profile", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;

    if (!studentId) {
      return res.redirect("/student/login");
    }

    const { first_name, last_name, email, department, program, year_level, birthdate } = req.body;

    // Validate names
    const firstNameValidation = validateName(first_name, "First name");
    if (!firstNameValidation.valid) {
      return res.redirect(`/student/profile?error=${encodeURIComponent(firstNameValidation.error)}`);
    }

    const lastNameValidation = validateName(last_name, "Last name");
    if (!lastNameValidation.valid) {
      return res.redirect(`/student/profile?error=${encodeURIComponent(lastNameValidation.error)}`);
    }

    // Validate email
    if (!email || !email.includes('@')) {
      return res.redirect(`/student/profile?error=${encodeURIComponent('Valid email is required')}`);
    }

    // Check for duplicate email (excluding current student)
    const emailCheck = await pool.query(
      `SELECT id FROM students WHERE email = ? AND id != ?`,
      [email.toLowerCase(), studentId]
    );
    if (emailCheck.rows.length > 0) {
      return res.redirect(`/student/profile?error=${encodeURIComponent('An account with this email already exists')}`);
    }

    // Update student profile
    await pool.query(
      `UPDATE students 
       SET first_name = ?, 
           last_name = ?, 
           email = ?, 
           department = ?, 
           program = ?, 
           year_level = ?, 
           birthdate = ?
       WHERE id = ?`,
      [
        firstNameValidation.value,
        lastNameValidation.value,
        email.toLowerCase(),
        department || null,
        program || null,
        year_level || null,
        birthdate || null,
        studentId
      ]
    );

    // Update session
    const { rows: updatedStudent } = await pool.query(
      `SELECT id, first_name, last_name, email, studentid, department, program, year_level, birthdate
       FROM students WHERE id = ?`,
      [studentId]
    );

    if (updatedStudent[0]) {
      req.session.student = {
        ...req.session.student,
        ...updatedStudent[0],
        name: `${updatedStudent[0].first_name} ${updatedStudent[0].last_name}`.trim()
      };
    }

    res.redirect("/student/profile?success=Profile updated successfully");
  } catch (error) {
    console.error("Error updating student profile:", error);
    res.redirect(`/student/profile?error=${encodeURIComponent('Failed to update profile. Please try again.')}`);
  }
});

// Change Password
router.post("/profile/password", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;

    if (!studentId) {
      return res.redirect("/student/login");
    }

    const { current_password, new_password, confirm_password } = req.body;

    // Validate passwords
    if (!current_password || !new_password || !confirm_password) {
      return res.redirect(`/student/profile?error=${encodeURIComponent('All password fields are required')}`);
    }

    if (new_password.length < 6) {
      return res.redirect(`/student/profile?error=${encodeURIComponent('New password must be at least 6 characters long')}`);
    }

    if (new_password !== confirm_password) {
      return res.redirect(`/student/profile?error=${encodeURIComponent('New passwords do not match')}`);
    }

    // Get current password
    const { rows } = await pool.query(
      `SELECT password FROM students WHERE id = ?`,
      [studentId]
    );

    if (!rows[0] || !rows[0].password) {
      return res.redirect(`/student/profile?error=${encodeURIComponent('Password not set. Please contact support.')}`);
    }

    // Verify current password
    const passwordMatch = await bcrypt.compare(current_password, rows[0].password);
    if (!passwordMatch) {
      return res.redirect(`/student/profile?error=${encodeURIComponent('Current password is incorrect')}`);
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(new_password, 10);

    // Update password
    await pool.query(
      `UPDATE students SET password = ? WHERE id = ?`,
      [hashedPassword, studentId]
    );

    res.redirect("/student/profile?success=Password changed successfully");
  } catch (error) {
    console.error("Error changing password:", error);
    res.redirect(`/student/profile?error=${encodeURIComponent('Failed to change password. Please try again.')}`);
  }
});

// Update Bio
router.post("/profile/bio", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;

    if (!studentId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    const { bio } = req.body;

    // Ensure bio column exists
    await pool.query(`
      ALTER TABLE students 
      ADD COLUMN IF NOT EXISTS bio TEXT
    `).catch(() => {});

    // Update bio
    await pool.query(
      `UPDATE students SET bio = ? WHERE id = ?`,
      [bio || null, studentId]
    );

    res.json({ success: true, message: "Bio updated successfully" });
  } catch (error) {
    console.error("Error updating bio:", error);
    res.status(500).json({ success: false, error: "Failed to update bio" });
  }
});

// Update Contact Info (phone, discord)
router.post("/profile/contact", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;

    if (!studentId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    const { phone, discord } = req.body;

    // Ensure columns exist
    await pool.query(`
      ALTER TABLE students 
      ADD COLUMN IF NOT EXISTS phone VARCHAR(20),
      ADD COLUMN IF NOT EXISTS discord VARCHAR(100)
    `).catch(() => {});

    // Update contact info
    await pool.query(
      `UPDATE students SET phone = ?, discord = ? WHERE id = ?`,
      [phone || null, discord || null, studentId]
    );

    res.json({ success: true, message: "Contact information updated successfully" });
  } catch (error) {
    console.error("Error updating contact info:", error);
    res.status(500).json({ success: false, error: "Failed to update contact information" });
  }
});

// Update Academic Info (program, year_level, department)
router.post("/profile/academic", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;

    if (!studentId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    const { program, year_level, department } = req.body;

    // Update academic info
    await pool.query(
      `UPDATE students SET program = ?, year_level = ?, department = ? WHERE id = ?`,
      [program || null, year_level || null, department || null, studentId]
    );

    res.json({ success: true, message: "Academic information updated successfully" });
  } catch (error) {
    console.error("Error updating academic info:", error);
    res.status(500).json({ success: false, error: "Failed to update academic information" });
  }
});

// Update Skills
router.post("/profile/skills", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;

    if (!studentId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    const { skills } = req.body;
    const skillsArray = Array.isArray(skills) ? skills : (skills ? JSON.parse(skills) : []);

    // Ensure skills column exists
    await pool.query(`
      ALTER TABLE students 
      ADD COLUMN IF NOT EXISTS skills JSON
    `).catch(() => {});

    // Update skills
    await pool.query(
      `UPDATE students SET skills = ? WHERE id = ?`,
      [JSON.stringify(skillsArray), studentId]
    );

    res.json({ success: true, message: "Skills updated successfully" });
  } catch (error) {
    console.error("Error updating skills:", error);
    res.status(500).json({ success: false, error: "Failed to update skills" });
  }
});

// Update Interests
router.post("/profile/interests", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;

    if (!studentId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    const { interests } = req.body;
    const interestsArray = Array.isArray(interests) ? interests : (interests ? JSON.parse(interests) : []);

    // Ensure interests column exists
    await pool.query(`
      ALTER TABLE students 
      ADD COLUMN IF NOT EXISTS interests JSON
    `).catch(() => {});

    // Update interests
    await pool.query(
      `UPDATE students SET interests = ? WHERE id = ?`,
      [JSON.stringify(interestsArray), studentId]
    );

    res.json({ success: true, message: "Interests updated successfully" });
  } catch (error) {
    console.error("Error updating interests:", error);
    res.status(500).json({ success: false, error: "Failed to update interests" });
  }
});

// Update Social Links
router.post("/profile/social", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;

    if (!studentId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    const { facebook, linkedin, twitter, instagram, github } = req.body;
    const socialLinks = {
      facebook: facebook || null,
      linkedin: linkedin || null,
      twitter: twitter || null,
      instagram: instagram || null,
      github: github || null
    };

    // Ensure social_links column exists
    await pool.query(`
      ALTER TABLE students 
      ADD COLUMN IF NOT EXISTS social_links JSON
    `).catch(() => {});

    // Update social links
    await pool.query(
      `UPDATE students SET social_links = ? WHERE id = ?`,
      [JSON.stringify(socialLinks), studentId]
    );

    res.json({ success: true, message: "Social links updated successfully" });
  } catch (error) {
    console.error("Error updating social links:", error);
    res.status(500).json({ success: false, error: "Failed to update social links" });
  }
});

// Update Profile Picture
router.post("/profile/picture", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;

    if (!studentId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    const { profile_picture } = req.body;

    // Validate profile picture (can be URL or base64 data URL)
    let pictureToStore = null;
    if (profile_picture && profile_picture.trim()) {
      const trimmed = profile_picture.trim();
      
      // Check if it's a base64 data URL (starts with data:image/)
      if (trimmed.startsWith('data:image/')) {
        // Store base64 data URL (supports up to 65KB for VARCHAR(255), but we'll use TEXT for base64)
        pictureToStore = trimmed;
      } else if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
        // Valid URL
        pictureToStore = trimmed;
      } else {
        return res.status(400).json({ success: false, error: "Invalid image format. Please use a valid URL or upload an image file." });
      }
    }

    // Ensure profile_picture column exists and is MEDIUMTEXT (supports larger data URLs / file paths)
    try {
      const colCheck = await pool.query(
        `SELECT DATA_TYPE 
           FROM information_schema.COLUMNS 
          WHERE TABLE_SCHEMA = DATABASE() 
            AND TABLE_NAME = 'students' 
            AND COLUMN_NAME = 'profile_picture'`
      );
      if (!colCheck.rows.length) {
        await pool.query(`ALTER TABLE students ADD COLUMN profile_picture MEDIUMTEXT`);
      } else {
        const dataType = (colCheck.rows[0]?.DATA_TYPE || '').toLowerCase();
        if (dataType !== 'mediumtext') {
          await pool.query(`ALTER TABLE students MODIFY COLUMN profile_picture MEDIUMTEXT`);
        }
      }
    } catch (err) {
      console.error('Column ensure/modify failed for profile_picture:', err.message);
    }

    // Update profile picture
    await pool.query(
      `UPDATE students SET profile_picture = ? WHERE id = ?`,
      [pictureToStore, studentId]
    );

    // Update session if it exists
    if (req.session.student) {
      req.session.student.profile_picture = pictureToStore;
    }

    res.json({ success: true, message: "Profile picture updated successfully" });
  } catch (error) {
    console.error("Error updating profile picture:", error);
    res.status(500).json({ success: false, error: "Failed to update profile picture" });
  }
});

// Settings page (GET)
router.get("/settings", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;

    if (!studentId) {
      return res.redirect("/student/login");
    }

    // Fetch student data
    const { rows } = await pool.query(
      `SELECT 
        id,
        first_name,
        last_name,
        email,
        studentid,
        department,
        program,
        year_level,
        created_at
      FROM students 
      WHERE id = ?`,
      [studentId]
    );

    if (rows.length === 0) {
      return res.redirect("/student/login");
    }

    const studentData = rows[0];

    // Fetch active sessions (mock data for now - can be enhanced with actual session tracking)
    const activeSessions = [
      {
        device: "Windows PC",
        browser: "Chrome",
        location: "Davao City, Philippines",
        lastActive: "Just now",
        isCurrent: true
      }
    ];

    // Fetch login history (mock data for now - can be enhanced with actual login tracking)
    const loginHistory = [
      {
        status: "success",
        date: new Date(),
        device: "Windows PC",
        browser: "Chrome",
        location: "Davao City, Philippines",
        ip: "192.168.1.100"
      }
    ];

    res.render("student/settings", {
      title: "Settings — UniClub",
      student: studentData,
      activeSessions: activeSessions,
      loginHistory: loginHistory,
      csrfToken: res.locals.csrfToken || req.csrfToken?.() || '',
      success: req.query.success || null,
      error: req.query.error || null,
    });
  } catch (error) {
    console.error("Error loading settings:", error);
    res.status(500).render("errors/500", { title: "Server Error", error: error });
  }
});

// Settings update (POST)
router.post("/settings", requireStudent, async (req, res) => {
  try {
    const student = req.session.student;
    const studentId = student?.id;

    if (!studentId) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    const { action, ...updateData } = req.body;

    if (action === "update-personal") {
      // Update personal information
      const { first_name, last_name, program, department } = updateData;
      
      await pool.query(
        `UPDATE students 
         SET first_name = ?, last_name = ?, program = ?, department = ?
         WHERE id = ?`,
        [first_name, last_name, program, department, studentId]
      );

      // Update session
      if (req.session.student) {
        req.session.student.first_name = first_name;
        req.session.student.last_name = last_name;
        req.session.student.program = program;
        req.session.student.department = department;
      }

      return res.redirect("/student/settings?success=personal_updated");
    } else if (action === "update-password") {
      // Update password
      const { current_password, new_password, confirm_password } = updateData;

      if (new_password !== confirm_password) {
        return res.redirect("/student/settings?error=password_mismatch");
      }

      if (new_password.length < 8) {
        return res.redirect("/student/settings?error=password_too_short");
      }

      // Verify current password
      const { rows } = await pool.query(
        `SELECT password FROM students WHERE id = ?`,
        [studentId]
      );

      if (rows.length === 0) {
        return res.status(404).json({ success: false, error: "Student not found" });
      }

      const isValid = await bcrypt.compare(current_password, rows[0].password);
      if (!isValid) {
        return res.redirect("/student/settings?error=invalid_current_password");
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(new_password, 10);

      await pool.query(
        `UPDATE students SET password = ? WHERE id = ?`,
        [hashedPassword, studentId]
      );

      return res.redirect("/student/settings?success=password_updated");
    }

    return res.redirect("/student/settings?error=invalid_action");
  } catch (error) {
    console.error("Error updating settings:", error);
    return res.redirect("/student/settings?error=update_failed");
  }
});

// Utility route to award points retroactively for existing approved memberships
// This can be called once to fix points for students who already joined clubs
router.post("/profile/award-retroactive-points", requireStudent, async (req, res) => {
  try {
    console.log("[Award Points] Request received");
    const student = req.session.student;
    const studentId = student?.id;

    if (!studentId) {
      console.log("[Award Points] No student ID found");
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }
    
    console.log(`[Award Points] Processing for student ${studentId}`);

    // Ensure student_points table exists
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
    `).catch(() => {});

    // Get all approved memberships for this student
    const approvedMemberships = await pool.query(`
      SELECT ma.id, ma.club_id, ma.created_at, c.name as club_name
      FROM membership_applications ma
      LEFT JOIN clubs c ON c.id = ma.club_id
      WHERE ma.student_id = ? 
      AND LOWER(COALESCE(ma.status, '')) = 'approved'
    `, [studentId]).catch(() => ({ rows: [] }));

    let pointsAwarded = 0;
    let newPoints = 0;

    for (const membership of approvedMemberships.rows) {
      // Check if points were already awarded for this application
      const existingPoints = await pool.query(
        `SELECT id FROM student_points 
         WHERE student_id = ? AND source = ? AND description LIKE ?`,
        [studentId, 'club_join', `%application_id:${membership.id}%`]
      ).catch(() => ({ rows: [] }));

      // Only award points if they haven't been awarded for this specific application
      if (existingPoints.rows.length === 0) {
        const clubName = membership.club_name || 'Club';
        
        await pool.query(
          `INSERT INTO student_points (student_id, points, source, description, created_at)
           VALUES (?, 5, 'club_join', ?, ?)`,
          [studentId, `Joined ${clubName} (application_id:${membership.id})`, membership.created_at || new Date()]
        );
        
        newPoints += 5;
        pointsAwarded++;
      }
    }

    // Get total points after awarding
    const pointsResult = await pool.query(`
      SELECT COALESCE(SUM(points), 0) as total
      FROM student_points
      WHERE student_id = ?
    `, [studentId]).catch(() => ({ rows: [{ total: 0 }] }));
    
    const totalPoints = Number(pointsResult.rows[0]?.total || 0);

    console.log(`[Award Points] ✅ Complete! Awarded ${newPoints} points for ${pointsAwarded} memberships. Total: ${totalPoints} points`);
    
    res.json({ 
      success: true, 
      message: `Awarded ${newPoints} points for ${pointsAwarded} club membership(s)`,
      newPoints: newPoints,
      totalPoints: totalPoints,
      membershipsProcessed: approvedMemberships.rows.length,
      pointsAwarded: pointsAwarded
    });
  } catch (error) {
    console.error("[Award Points] ❌ Error awarding retroactive points:", error);
    console.error("[Award Points] Error stack:", error.stack);
    res.status(500).json({ 
      success: false, 
      error: "Failed to award points",
      details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

export default router;
