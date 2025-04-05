const express = require("express");
const router = express.Router();
const crypto = require("crypto");
const db = require("../db");
const { authenticate, requireRole } = require("./authMiddleware");

// Generate QR Code
router.post("/generate-qr", authenticate, requireRole('teacher'), async (req, res) => {
  try {
    const { subject, class_id, teacher_id, section } = req.body;
    
    if (!class_id || !teacher_id) {
      return res.status(400).json({ 
        success: false, 
        message: "Class ID and Teacher ID are required" 
      });
    }
    
    // Generate a unique session ID
    const session_id = crypto.randomBytes(16).toString("hex");
    
    // Set expiration to 10 minutes from now
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 10 * 60 * 1000); // 10 minutes in UTC
    
    // Convert to UTC+8 for database storage
    const expiresAtUTC8 = new Date(expiresAt.getTime() + 8 * 60 * 60 * 1000);
    
    // Insert the session into the database
    const insertQuery = `
      INSERT INTO qr_sessions 
      (session_id, teacher_id, class_id, section, subject, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, NOW())
    `;
    
    await db.query(insertQuery, [
      session_id,
      teacher_id,
      class_id,
      section || null,
      subject,
      expiresAtUTC8
    ]);
    
    // Check if the session was created successfully
    const [sessionCheck] = await db.query(
      "SELECT * FROM qr_sessions WHERE session_id = ?",
      [session_id]
    );
    
    if (sessionCheck.length === 0) {
      return res.status(500).json({
        success: false,
        message: "Failed to create QR session"
      });
    }
    
    console.log(`QR session created: ${session_id} for class ${class_id}${section ? ', section ' + section : ''}, expires at ${expiresAtUTC8}`);
    
    // Build the QR code URL (this would be scanned by students)
    let baseUrl;
    
    // Check for specific headers that might indicate the frontend URL
    const frontendUrl = req.headers['x-forwarded-host'] || req.headers.origin;
    
    if (frontendUrl && frontendUrl.includes('netlify.app')) {
      // Use the Netlify URL as the base
      baseUrl = frontendUrl.startsWith('http') ? frontendUrl : `https://${frontendUrl}`;
      console.log(`Using frontend URL from headers: ${baseUrl}`);
    } else {
      // Fallback to the backend URL
      baseUrl = req.protocol + "://" + req.get("host");
      console.log(`Using backend URL as fallback: ${baseUrl}`);
    }
    
    // Include section in the QR code URL if provided
    const sectionParam = section ? `&section=${encodeURIComponent(section)}` : '';
    const qrCodeUrl = `${baseUrl}/attend?session=${session_id}&teacher=${teacher_id}&subject=${encodeURIComponent(subject || '')}${sectionParam}`;
    
    return res.json({
      success: true,
      sessionId: session_id,
      qrCodeUrl,
      section: section || null,
      expiresAt: expiresAtUTC8.toISOString()
    });
    
  } catch (error) {
    console.error("Error generating QR code:", error);
    return res.status(500).json({ 
      success: false, 
      message: "Failed to generate QR code",
      error: error.message
    });
  }
});

// Get active sessions for teacher
router.get("/sessions", authenticate, requireRole('teacher'), async (req, res) => {
  try {
    const [sessions] = await db.query(
      `SELECT 
        session_id as id,
        DATE_FORMAT(DATE_ADD(created_at, INTERVAL 8 HOUR), '%Y-%m-%d %H:%i:%s') as createdAt,
        DATE_FORMAT(DATE_ADD(expires_at, INTERVAL 8 HOUR), '%Y-%m-%d %H:%i:%s') as expiresAt,
        is_active,
        TIMESTAMPDIFF(SECOND, NOW(), expires_at) as secondsRemaining
       FROM qr_sessions 
       WHERE teacher_id = ? AND expires_at > NOW() AND is_active = TRUE
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json({ 
      success: true, 
      sessions,
      count: sessions.length 
    });

  } catch (error) {
    console.error("Session fetch error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Failed to fetch sessions." 
    });
  }
});

// Invalidate a session
router.delete("/sessions/:sessionId", authenticate, requireRole('teacher'), async (req, res) => {
  try {
    const [result] = await db.query(
      `UPDATE qr_sessions 
       SET expires_at = NOW(), is_active = FALSE
       WHERE session_id = ? AND teacher_id = ? AND expires_at > NOW() AND is_active = TRUE`,
      [req.params.sessionId, req.user.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        message: "Session not found or already expired." 
      });
    }

    res.json({ 
      success: true, 
      message: "Session invalidated successfully." 
    });

  } catch (error) {
    console.error("Session invalidation error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Failed to invalidate session." 
    });
  }
});

// Get classes for a teacher
router.get("/teacher-classes/:teacherId", authenticate, requireRole('teacher'), async (req, res) => {
  try {
    const teacherId = req.params.teacherId;
    
    // Verify the request is for the logged-in teacher
    if (parseInt(teacherId) !== req.user.id) {
      return res.status(403).json({ 
        success: false, 
        message: "You can only view your own classes" 
      });
    }
    
    // Check if class_records table exists, if not create it
    try {
      await db.query(`
        CREATE TABLE IF NOT EXISTS class_records (
          id INT AUTO_INCREMENT PRIMARY KEY,
          teacher_id INT NOT NULL,
          class_name VARCHAR(100) NOT NULL,
          subject VARCHAR(100) NOT NULL,
          description TEXT,
          is_active BOOLEAN DEFAULT TRUE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (teacher_id) REFERENCES teachers(id) ON DELETE CASCADE,
          INDEX idx_teacher_id (teacher_id)
        )
      `);
      console.log("class_records table checked/created");
    } catch (tableError) {
      console.log("Error with class_records table:", tableError);
    }
    
    // Get classes from the database
    const [classes] = await db.query(
      `SELECT id, class_name, subject, description, created_at
       FROM class_records 
       WHERE teacher_id = ? AND is_active = TRUE
       ORDER BY created_at DESC`,
      [teacherId]
    );
    
    console.log(`Found ${classes.length} classes for teacher ${teacherId}`);
    
    // Return the classes (even if empty)
    res.json({ 
      success: true, 
      classes,
      count: classes.length 
    });
  } catch (error) {
    console.error("Classes fetch error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Failed to fetch classes." 
    });
  }
});

// Add a new class
router.post("/classes", authenticate, requireRole('teacher'), async (req, res) => {
  try {
    const { name, subject, description } = req.body;
    const teacherId = req.user.id;
    
    // Validate input
    if (!name) {
      return res.status(400).json({
        success: false,
        message: "Class name is required"
      });
    }
    
    // Use name as subject if not provided
    const classSubject = subject || name;
    
    // Insert new class
    const [result] = await db.query(
      `INSERT INTO class_records (teacher_id, class_name, subject, description)
       VALUES (?, ?, ?, ?)`,
      [teacherId, name, classSubject, description || null]
    );
    
    if (result.affectedRows === 0) {
      throw new Error("Failed to insert new class");
    }
    
    res.json({
      success: true,
      message: "Class added successfully",
      classId: result.insertId,
      class: {
        id: result.insertId,
        class_name: name,
        subject: classSubject,
        description: description || null,
        teacher_id: teacherId
      }
    });
  } catch (error) {
    console.error("Class creation error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to create class",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Delete a class (hard delete)
router.delete("/classes/:classId", authenticate, requireRole('teacher'), async (req, res) => {
  try {
    const classId = req.params.classId;
    const teacherId = req.user.id;
    
    // Start a transaction to ensure data consistency
    await db.query('START TRANSACTION');
    
    // First check if the class exists and belongs to this teacher
    const [classCheck] = await db.query(
      `SELECT id FROM class_records
       WHERE id = ? AND teacher_id = ?`,
      [classId, teacherId]
    );
    
    if (classCheck.length === 0) {
      await db.query('ROLLBACK');
      return res.status(404).json({
        success: false,
        message: "Class not found or you don't have permission to delete it"
      });
    }
    
    // Check for related attendance records
    const [attendanceCheck] = await db.query(
      `SELECT COUNT(*) as count FROM qr_sessions
       WHERE class_id = ?`,
      [classId]
    );
    
    // If there are related records in qr_sessions, we need to clean those up first
    if (attendanceCheck[0].count > 0) {
      console.log(`Cleaning up ${attendanceCheck[0].count} related QR sessions`);
      
      // Get all session_ids for this class
      const [sessionIds] = await db.query(
        `SELECT session_id FROM qr_sessions WHERE class_id = ?`,
        [classId]
      );
      
      // Delete attendance records related to these sessions
      for (const session of sessionIds) {
        await db.query(
          `DELETE FROM attendance WHERE session_id = ?`,
          [session.session_id]
        );
      }
      
      // Delete the sessions themselves
      await db.query(
        `DELETE FROM qr_sessions WHERE class_id = ?`,
        [classId]
      );
    }
    
    // Finally, delete the class record
    const [result] = await db.query(
      `DELETE FROM class_records WHERE id = ?`,
      [classId]
    );
    
    // Commit the transaction
    await db.query('COMMIT');
    
    res.json({
      success: true,
      message: "Class and all related data permanently deleted",
      classId
    });
  } catch (error) {
    // Rollback in case of error
    await db.query('ROLLBACK');
    
    console.error("Class deletion error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to delete class",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get attendance records for a specific session
router.get("/attendance/:sessionId", authenticate, requireRole('teacher'), async (req, res) => {
  try {
    const sessionId = req.params.sessionId;
    const teacherId = req.user.id;
    
    console.log(`👨‍🏫 Fetching attendance for session: ${sessionId}, teacher: ${teacherId}`);
    
    // Fetch session details first to verify teacher has access
    // Try to find by either id or session_id
    const [sessionDetails] = await db.query(
      `SELECT id, session_id, teacher_id, class_id, subject, section 
       FROM qr_sessions 
       WHERE (session_id = ? OR id = ?)`,
      [sessionId, sessionId]
    );
    
    console.log(`👨‍🏫 Session details:`, sessionDetails);
    
    if (sessionDetails.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Session not found"
      });
    }
    
    // Verify the teacher has access to this session
    if (sessionDetails[0].teacher_id !== teacherId) {
      return res.status(403).json({
        success: false,
        message: "You don't have permission to access this session's attendance"
      });
    }
    
    // Use session_id for the lookup
    const actualSessionId = sessionDetails[0].session_id;
    console.log(`👨‍🏫 Using session_id: ${actualSessionId} for attendance lookup`);
    
    // Get the attendance records with UTC+8 time format using MySQL functions
    const [attendanceRecords] = await db.query(
      `SELECT 
        a.id,
        a.student_id,
        CONCAT(s.first_name, ' ', s.last_name) as student_name,
        s.student_id as student_number,
        DATE_FORMAT(DATE_ADD(a.recorded_at, INTERVAL 8 HOUR), '%Y-%m-%d %H:%i:%s') as timestamp
       FROM attendance a
       JOIN students s ON a.student_id = s.id
       WHERE a.session_id = ? AND a.teacher_id = ?
       ORDER BY a.recorded_at DESC`,
      [actualSessionId, teacherId]
    );
    
    console.log(`👨‍🏫 Found ${attendanceRecords.length} attendance records`);
    
    // Get class info if available
    let className = "Unknown Class";
    if (sessionDetails[0].class_id) {
      const [classInfo] = await db.query(
        `SELECT class_name FROM class_records WHERE id = ?`,
        [sessionDetails[0].class_id]
      );
      if (classInfo.length > 0) {
        className = classInfo[0].class_name;
      }
    }
    
    return res.json({
      success: true,
      sessionId: actualSessionId,
      className,
      subject: sessionDetails[0].subject || "Unknown Subject",
      section: sessionDetails[0].section || null,
      attendanceRecords,
      count: attendanceRecords.length
    });
    
  } catch (error) {
    console.error("Error fetching attendance records:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to fetch attendance records",
      error: error.message
    });
  }
});

// Get sessions for a specific class
router.get("/class-sessions/:classId", authenticate, requireRole('teacher'), async (req, res) => {
  try {
    const classId = req.params.classId;
    const teacherId = req.user.id;
    
    console.log(`👨‍🏫 Fetching DISTINCT DATES for class ID ${classId}, teacher ${teacherId}`);
    // console.log(`Auth method: ${req.user.headerAuth ? 'header-based' : 'session-based'}`);
    
    // // Additional validation for header-based auth
    // if (req.user.headerAuth) {
    //   console.log(`Using header auth values: ID=${req.headers['x-user-id']}, Role=${req.headers['x-user-role']}`);
    // }
    
    // Verify the class belongs to this teacher
    const [classCheck] = await db.query(
      `SELECT id, class_name FROM class_records WHERE id = ? AND teacher_id = ? AND is_active = TRUE`,
      [classId, teacherId]
    );
    
    if (classCheck.length === 0) {
      console.log(`❌ Class ${classId} not found or doesn't belong to teacher ${teacherId}`);
      return res.status(404).json({
        success: false,
        message: "Class not found or you don't have access to it"
      });
    }
    
    // console.log(`✅ Class verification successful: "${classCheck[0].class_name}" (ID: ${classId})`);
    
    // --- NEW QUERY ---
    // Get distinct dates (YYYY-MM-DD) on which sessions exist for this class/teacher
    const [distinctDates] = await db.query(
      `SELECT DISTINCT
         DATE_FORMAT(s.created_at, '%Y-%m-%d') as session_date
       FROM qr_sessions s
       WHERE s.teacher_id = ? AND s.class_id = ?
       ORDER BY session_date DESC`, // Order by most recent date first
      [teacherId, classId]
    );
    
    console.log(`👨‍🏫 Found ${distinctDates.length} distinct dates for class ${classId}`);
    
    // --- MODIFIED RESPONSE ---
    // Send back the list of date strings
    return res.json({
      success: true,
      // Rename 'sessions' to 'dates' for clarity
      dates: distinctDates.map(d => d.session_date), // Send only the date strings
      count: distinctDates.length,
      teacherId: teacherId, // Include teacherId for verification
      className: classCheck[0].class_name
    });
    
  } catch (error) {
    console.error("Error fetching distinct session dates:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to fetch session dates for this class",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get sections and session IDs for a specific class on a specific date
router.get("/sessions-on-date", authenticate, requireRole('teacher'), async (req, res) => {
  try {
    const { classId, date } = req.query; // Expect YYYY-MM-DD format
    const teacherId = req.user.id;

    if (!classId || !date) {
      return res.status(400).json({ success: false, message: "Class ID and Date are required." });
    }

    console.log(`Fetching sections for class ${classId} on date ${date} for teacher ${teacherId}`);

    // Query distinct sections and their corresponding session_id for that day
    // Use MIN(qs.session_id) to get one representative session_id per section group
    // Using DATE() function to compare only the date part of created_at
    const [sections] = await db.query(
      `SELECT 
         qs.section,
         MIN(qs.session_id) as session_id 
       FROM qr_sessions qs 
       WHERE qs.class_id = ? 
         AND qs.teacher_id = ? 
         AND DATE(qs.created_at) = ?
       GROUP BY qs.section
       ORDER BY qs.section`,
      [classId, teacherId, date]
    );

    console.log(`Found ${sections.length} sections:`, sections);

    res.json({ success: true, sections });

  } catch (error) {
    console.error("Error fetching sections for date:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch sections for the specified date.",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get recent attendance summary for teacher dashboard
router.get("/recent-attendance-summary", authenticate, requireRole('teacher'), async (req, res) => {
  try {
    const teacherId = req.user.id;
    console.log(`Fetching recent attendance summary for teacher ID: ${teacherId}`);
    
    try {
      // Fetch records including section and full timestamp
      const [records] = await db.query(
        `SELECT 
           cr.class_name,
           qs.section, -- Select the section
           DATE_FORMAT(qs.created_at, '%Y-%m-%d') as attendance_date, -- Keep the date part
           TIME_FORMAT(qs.created_at, '%h:%i:%s %p') as attendance_time, -- Get formatted time
           qs.created_at as full_timestamp, -- Keep original timestamp for sorting
           (SELECT COUNT(*) FROM attendance a WHERE a.session_id = qs.session_id) as present_count
         FROM qr_sessions qs
         JOIN class_records cr ON qs.class_id = cr.id
         WHERE qs.teacher_id = ?
         -- Group by all non-aggregated fields to ensure correctness
         GROUP BY cr.class_name, qs.section, attendance_date, attendance_time, qs.session_id, qs.created_at
         ORDER BY qs.created_at DESC`, // Order by the original timestamp
        [teacherId]
      );
      
      console.log(`Recent attendance summary query successful. Found ${records.length} records.`);
      
      // If no records found, return empty array
      if (records.length === 0) {
        console.log('No attendance records found for this teacher.');
        return res.json({
          success: true,
          records: []
        });
      }
      
      return res.json({
        success: true,
        records
      });
    } catch (sqlError) {
      console.error("SQL Error in attendance summary:", sqlError);
      console.error("Attempting fallback query...");
      
      // Instead of failing, try to see if tables exist
      const [tables] = await db.query(
        "SHOW TABLES"
      );
      
      // Send whatever we have
      return res.json({
        success: true,
        message: "SQL query failed but endpoint works",
        error: sqlError.message,
        availableTables: tables,
        records: []
      });
    }
  } catch (error) {
    console.error("Recent attendance summary error:", error);
    console.error("Error details:", error.stack);
    console.error("SQL state:", error.sqlState, "Code:", error.code);
    
    // Send a more detailed error response
    res.status(500).json({
      success: false,
      message: "Failed to fetch recent attendance summary",
      error: process.env.NODE_ENV === 'development' ? error.message : 'Database error',
      sqlState: error.sqlState,
      code: error.code
    });
  }
});

module.exports = router;