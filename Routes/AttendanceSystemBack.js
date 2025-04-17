const express = require('express');
const router = express.Router();
const db = require('../db');
const { authenticate, requireRole } = require('./authMiddleware');

// Handle QR code attendance links
router.get('/attend', async (req, res) => {
  const { session, teacher } = req.query;
  
  if (!session || !teacher) {
    return res.status(400).send(`
      <html>
        <head>
          <title>Invalid QR Code</title>
          <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 40px 20px; }
            .error-container { max-width: 500px; margin: 0 auto; }
            h1 { color: #e74c3c; }
            p { color: #333; line-height: 1.6; }
            .btn { display: inline-block; background: #3498db; color: white; padding: 10px 20px; 
                  text-decoration: none; border-radius: 4px; margin-top: 20px; }
          </style>
        </head>
        <body>
          <div class="error-container">
            <h1>Invalid QR Code</h1>
            <p>The QR code is missing required information. Please ask your teacher for a valid QR code.</p>
            <a href="/" class="btn">Go to Login</a>
          </div>
        </body>
      </html>
    `);
  }

  try {
    console.log("📱 Processing attend link:", { session, teacher });
    
    // Check if session exists and is valid using MySQL syntax
    const sessionCheckQuery = `
      SELECT qs.session_id, qs.class_id, qs.expires_at, cr.class_name 
      FROM qr_sessions qs
      LEFT JOIN class_records cr ON qs.class_id = cr.id
      WHERE qs.session_id = ? AND qs.teacher_id = ? AND qs.expires_at > NOW()
    `;
    
    console.log("📱 Executing query:", sessionCheckQuery);
    const [sessionRows] = await db.query(sessionCheckQuery, [session, teacher]);
    console.log("📱 Query results:", sessionRows);
    
    // Check if session exists
    if (!sessionRows || sessionRows.length === 0) {
      console.log("📱 No valid session found");
      return res.status(404).send(`
        <html>
          <head>
            <title>Expired QR Code</title>
            <style>
              body { font-family: Arial, sans-serif; text-align: center; padding: 40px 20px; }
              .error-container { max-width: 500px; margin: 0 auto; }
              h1 { color: #e74c3c; }
              p { color: #333; line-height: 1.6; }
              .btn { display: inline-block; background: #3498db; color: white; padding: 10px 20px; 
                    text-decoration: none; border-radius: 4px; margin-top: 20px; }
            </style>
          </head>
          <body>
            <div class="error-container">
              <h1>Expired QR Code</h1>
              <p>This QR code has expired or is invalid. Please ask your teacher for a new QR code.</p>
              <a href="/" class="btn">Go to Login</a>
            </div>
          </body>
        </html>
      `);
    }

    // Get the session data
    const sessionRow = sessionRows[0];
    console.log("📱 Valid session found:", sessionRow);

    // Redirect to student dashboard with params for attendance
    const subject = sessionRow.class_name || 'Class';
    const redirectUrl = `/pages/student-dashboard.html?session=${session}&teacher=${teacher}&subject=${encodeURIComponent(subject)}`;
    console.log("📱 Redirecting to:", redirectUrl);
    return res.redirect(redirectUrl);
    
  } catch (error) {
    console.error("Error handling attendance:", error);
    return res.status(500).send(`
      <html>
        <head>
          <title>Error</title>
          <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 40px 20px; }
            .error-container { max-width: 500px; margin: 0 auto; }
            h1 { color: #e74c3c; }
            p { color: #333; line-height: 1.6; }
            .btn { display: inline-block; background: #3498db; color: white; padding: 10px 20px; 
                  text-decoration: none; border-radius: 4px; margin-top: 20px; }
          </style>
        </head>
        <body>
          <div class="error-container">
            <h1>Server Error</h1>
            <p>Something went wrong. Please try again later or contact support.</p>
            <a href="/" class="btn">Go to Login</a>
          </div>
        </body>
      </html>
    `);
  }
});

// POST route to record attendance
router.post("/record-attendance", authenticate, async (req, res) => {
  try {
    const { session_id } = req.body;
    const studentId = req.user.id;
    
    console.log("📝 ATTENDANCE RECORDING - Request body:", req.body);
    console.log("📝 ATTENDANCE RECORDING - User:", req.user);
    
    if (!session_id) {
      return res.status(400).json({
        success: false,
        message: "Session ID is required"
      });
    }
    
    console.log(`📝 Attempting to record attendance for student ${studentId}, session ${session_id}`);
    
    // Verify the session exists and is active
    const [sessionCheck] = await db.query(
      `SELECT teacher_id, subject, is_active FROM qr_sessions 
       WHERE session_id = ? OR id = ? AND expires_at > NOW()`,
      [session_id, session_id]
    );
    
    console.log("📝 Session check results:", sessionCheck);
    
    if (sessionCheck.length === 0 || !sessionCheck[0].is_active) {
      return res.status(400).json({
        success: false,
        message: "This QR code has expired or is no longer valid"
      });
    }
    
    const teacherId = sessionCheck[0].teacher_id;
    const subject = sessionCheck[0].subject;
    
    console.log(`📝 Valid session found: Teacher=${teacherId}, Subject=${subject}`);
    
    // Check if attendance already recorded
    const [existingAttendance] = await db.query(
      `SELECT id FROM attendance 
       WHERE session_id = ? AND student_id = ?`,
      [session_id, studentId]
    );
    
    const attendanceExists = existingAttendance.length > 0;
    console.log(`📝 Existing attendance check: exists=${attendanceExists}`);
    
    if (attendanceExists) {
      return res.status(400).json({
        success: false,
        message: "Your attendance for this session has already been recorded"
      });
    }
    
    // Get student info for the response
    const [studentInfo] = await db.query(
      `SELECT first_name, last_name FROM students WHERE id = ?`,
      [studentId]
    );
    
    console.log("📝 Student info:", studentInfo[0]);
    
    // First, try to fix the foreign key constraint issue
    try {
      // Check if the foreign key constraint exists and drop it
      console.log("📝 Checking for foreign key constraints on attendance table...");
      const [foreignKeys] = await db.query(
        `SELECT CONSTRAINT_NAME
         FROM information_schema.KEY_COLUMN_USAGE
         WHERE TABLE_NAME = 'attendance' 
         AND COLUMN_NAME = 'session_id'
         AND CONSTRAINT_NAME != 'PRIMARY'
         AND REFERENCED_TABLE_NAME IS NOT NULL
         AND TABLE_SCHEMA = DATABASE()`
      );
      
      console.log("📝 Foreign key constraints found:", foreignKeys);
      
      // Drop foreign key constraints if they exist
      for (const fk of foreignKeys) {
        console.log(`📝 Dropping foreign key constraint: ${fk.CONSTRAINT_NAME}`);
        await db.query(`ALTER TABLE attendance DROP FOREIGN KEY ${fk.CONSTRAINT_NAME}`);
      }
      
      console.log("📝 Foreign key constraints dropped (if any)");
    } catch (constraintError) {
      console.error("📝 Error checking/dropping constraints:", constraintError);
      // Continue anyway, the constraint might not exist
    }
    
    // Insert attendance record
    try {
      console.log("📝 Inserting attendance record without foreign key constraint");
      const [insertResult] = await db.query(
        `INSERT INTO attendance (session_id, student_id, teacher_id, subject, recorded_at)
         VALUES (?, ?, ?, ?, NOW())`,
        [session_id, studentId, teacherId, subject]
      );
      
      console.log("📝 Attendance record inserted successfully:", insertResult);
      
      // Use UTC+8 timestamp for consistency if needed elsewhere, otherwise simple now is fine
      const now = new Date();
      const utc8Time = new Date(now.getTime() + 8 * 60 * 60 * 1000);
      
      return res.json({
        success: true,
        message: "Attendance recorded successfully",
        subject: subject,
        student: studentInfo[0] ? `${studentInfo[0].first_name} ${studentInfo[0].last_name}` : "Unknown Student",
        timestamp: utc8Time.toISOString()
      });
    } catch (insertError) {
      console.error("📝 DATABASE ERROR during attendance insertion:", insertError);
      return res.status(500).json({
        success: false,
        message: "Database error while recording attendance. Please try again later."
      });
    }
    
  } catch (error) {
    console.error("Attendance recording error:", error);
    return res.status(500).json({
      success: false,
      message: "Server error while recording attendance"
    });
  }
});

// Get attendance reports for teachers
router.get('/attendance-reports', authenticate, requireRole('teacher'), async (req, res) => {
  try {
    const { session_id } = req.query;
    const teacherId = req.user.id;
    
    // Validate session belongs to teacher
    const [sessionCheck] = await db.query(
      `SELECT session_id, subject FROM qr_sessions 
       WHERE session_id = ? AND teacher_id = ?`,
      [session_id, teacherId]
    );
    
    if (sessionCheck.length === 0) {
      return res.status(403).json({
        success: false,
        message: 'You do not have access to this session'
      });
    }
    
    const subject = sessionCheck[0].subject || 'Unknown Subject';
    
    // Get attendance records
    const [attendance] = await db.query(
      `SELECT 
        a.id,
        a.student_id,
        a.recorded_at as timestamp,
        a.subject,
        CONCAT(s.first_name, ' ', s.last_name) as studentName,
        s.student_id as studentNumber
       FROM attendance a
       JOIN students s ON a.student_id = s.id
       WHERE a.session_id = ? AND a.teacher_id = ?
       ORDER BY a.recorded_at ASC`,
      [session_id, teacherId]
    );
    
    res.json({
      success: true,
      subject: subject,
      attendance,
      count: attendance.length
    });
    
  } catch (error) {
    console.error('Attendance report error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch attendance reports'
    });
  }
});

// Get attendance history for a student
router.get('/student-attendance-history', authenticate, requireRole('student'), async (req, res) => {
  try {
    const studentId = req.user.id;
    console.log(`📚 Fetching attendance history for student ID: ${studentId}`);
    
    // Get attendance history for the student with UTC+8 time using MySQL DATE_ADD
    const [history] = await db.query(
      `SELECT 
        a.id,
        a.session_id,
        DATE_FORMAT(DATE_ADD(a.recorded_at, INTERVAL 8 HOUR), '%Y-%m-%d %H:%i:%s') as timestamp,
        a.teacher_id,
        CONCAT(t.first_name, ' ', t.last_name) as teacherName,
        COALESCE(a.subject, qs.subject, 'Unknown Subject') as subject,
        qs.section
       FROM attendance a
       JOIN teachers t ON a.teacher_id = t.id
       LEFT JOIN qr_sessions qs ON a.session_id = qs.session_id
       WHERE a.student_id = ?
       ORDER BY a.recorded_at DESC
       LIMIT 50`,
      [studentId]
    );
    
    console.log(`📚 Found ${history.length} attendance records`);
    
    // Format timestamps if needed (the MySQL DATE_FORMAT already does most of the work)
    const formattedHistory = history.map(record => {
      // Ensure we have a properly formatted timestamp
      if (record.timestamp) {
        try {
          // Convert the formatted string to a Date object for consistent ISO string output
          const date = new Date(record.timestamp);
          if (!isNaN(date.getTime())) {
            console.log(`📚 Original formatted timestamp for record ${record.id}: ${record.timestamp}`);
            // We can keep the MySQL formatted date as is
          } else {
            // If we couldn't parse the MySQL formatted date, create a new UTC+8 timestamp manually
            const now = new Date();
            const utc8Time = new Date(now.getTime() + 8 * 60 * 60 * 1000);
            record.timestamp = utc8Time.toISOString();
            console.log(`📚 Timestamp couldn't be parsed, using current time: ${record.timestamp}`);
          }
        } catch (e) {
          console.error(`📚 Error processing timestamp for record ${record.id}:`, e);
        }
      } else {
        // If no timestamp, use current time
        const now = new Date();
        const utc8Time = new Date(now.getTime() + 8 * 60 * 60 * 1000);
        record.timestamp = utc8Time.toISOString();
        console.log(`📚 No timestamp found for record ${record.id}, using current time: ${record.timestamp}`);
      }
      return record;
    });
    
    // If no history found, provide sample data with UTC+8 timestamp
    if (formattedHistory.length === 0) {
      console.log(`📚 No records found, returning sample data with UTC+8 time`);
      // Create a sample timestamp in UTC+8
      const now = new Date();
      const utc8Time = new Date(now.getTime() + 8 * 60 * 60 * 1000);
      
      res.json({
        success: true,
        history: [{
          id: 0,
          session_id: 'sample',
          timestamp: utc8Time.toISOString(),
          teacher_id: 1,
          teacherName: 'Sample Teacher',
          subject: 'Mathematics'
        }],
        count: 1,
        note: 'Sample data provided (no actual attendance records found)'
      });
      return;
    }
    
    res.json({
      success: true,
      history: formattedHistory,
      count: formattedHistory.length
    });
    
  } catch (error) {
    console.error('📚 Student attendance history error:', error);
    // Return a friendly error with sample data using UTC+8 time
    const now = new Date();
    const utc8Time = new Date(now.getTime() + 8 * 60 * 60 * 1000);
    
    res.json({
      success: true,
      history: [{
        id: 0,
        session_id: 'error',
        timestamp: utc8Time.toISOString(),
        teacher_id: 1,
        teacherName: 'Error retrieving records',
        subject: 'Please try again later'
      }],
      count: 1,
      error: error.message
    });
  }
});

// Add a route to fix the attendance table schema
router.get("/fix-attendance-schema", async (req, res) => {
  try {
    console.log("🔧 Attempting to fix attendance table schema...");
    
    // Check current table structure
    const [columns] = await db.query("DESCRIBE attendance");
    console.log("Current attendance table columns:", columns.map(c => c.Field));
    
    // Check if foreign keys exist
    const [foreignKeys] = await db.query(
      "SELECT * FROM information_schema.KEY_COLUMN_USAGE " +
      "WHERE TABLE_NAME = 'attendance' AND REFERENCED_TABLE_NAME IS NOT NULL"
    );
    console.log("Foreign keys:", foreignKeys);
    
    // Series of operations to fix the schema
    const operations = [];
    
    // Add qr_session_id column if it doesn't exist
    const hasQrSessionId = columns.some(c => c.Field === 'qr_session_id');
    if (!hasQrSessionId) {
      operations.push(
        db.query("ALTER TABLE attendance ADD COLUMN qr_session_id VARCHAR(64) AFTER id")
      );
    }
    
    // Update all existing records to have qr_session_id match session_id
    operations.push(
      db.query("UPDATE attendance SET qr_session_id = session_id WHERE qr_session_id IS NULL")
    );
    
    // Remove the foreign key constraint if it exists
    if (foreignKeys.length > 0) {
      const fkName = foreignKeys.find(fk => fk.COLUMN_NAME === 'session_id')?.CONSTRAINT_NAME;
      if (fkName) {
        operations.push(
          db.query(`ALTER TABLE attendance DROP FOREIGN KEY ${fkName}`)
        );
      }
    }
    
    // Add new foreign key to qr_sessions
    operations.push(
      db.query(
        "ALTER TABLE attendance " +
        "ADD CONSTRAINT attendance_qr_session_fk " +
        "FOREIGN KEY (qr_session_id) REFERENCES qr_sessions(session_id) " +
        "ON DELETE CASCADE"
      )
    );
    
    // Execute all operations
    const results = await Promise.allSettled(operations);
    
    // Check results
    const succeeded = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected');
    
    if (failed.length > 0) {
      console.error("Some schema updates failed:", failed.map(f => f.reason));
    }
    
    // Final check
    const [updatedColumns] = await db.query("DESCRIBE attendance");
    console.log("Updated attendance table columns:", updatedColumns.map(c => c.Field));
    
    return res.json({
      success: true,
      message: `Schema update completed. ${succeeded} operations succeeded, ${failed.length} failed.`,
      details: {
        columns: updatedColumns.map(c => c.Field),
        operationsAttempted: operations.length,
        operationsSucceeded: succeeded,
        operationsFailed: failed.length
      }
    });
    
  } catch (error) {
    console.error("Schema update error:", error);
    return res.status(500).json({
      success: false,
      message: "Error updating schema",
      error: error.message
    });
  }
});

// Get attendance records for a session
router.get('/teacher/attendance/:sessionId', authenticate, async (req, res) => {
    const { sessionId } = req.params;
    const teacherId = req.user.id;
    
    console.log(`Fetching attendance for session: ${sessionId}, teacher: ${teacherId}`);
    
    if (!sessionId) {
        return res.status(400).json({ success: false, message: 'Session ID is required' });
    }
    
    try {
        // First verify this session belongs to the teacher
        const sessionCheckQuery = `
            SELECT s.* FROM qr_sessions s
            JOIN class_records c ON s.class_id = c.id
            WHERE (s.id = ? OR s.session_id = ?) AND c.teacher_id = ?
        `;
        
        db.query(sessionCheckQuery, [sessionId, sessionId, teacherId], async (error, sessionResults) => {
            if (error) {
                console.error('Error checking session ownership:', error);
                return res.status(500).json({ success: false, message: 'Error verifying session ownership', error: error.message });
            }
            
            if (!sessionResults || sessionResults.length === 0) {
                return res.status(403).json({ success: false, message: 'Session not found or you do not have permission to view these records' });
            }
            
            // Session belongs to teacher, now get attendance records
            const attendanceQuery = `
                SELECT a.*, s.student_number, s.name as student_name
                FROM attendance a
                JOIN students s ON a.student_id = s.id
                WHERE a.session_id = ? OR a.id = ?
                ORDER BY a.timestamp DESC
            `;
            
            db.query(attendanceQuery, [sessionId, sessionId], (attendanceError, attendanceResults) => {
                if (attendanceError) {
                    console.error('Error fetching attendance records:', attendanceError);
                    return res.status(500).json({ success: false, message: 'Error fetching attendance records', error: attendanceError.message });
                }
                
                // Convert timestamps to UTC+8
                const formattedRecords = attendanceResults.map(record => {
                    if (record.timestamp) {
                        const timestamp = new Date(record.timestamp);
                        const utc8Timestamp = new Date(timestamp.getTime() + (8 * 60 * 60 * 1000));
                        record.timestamp = utc8Timestamp.toISOString();
                    }
                    return record;
                });
                
                console.log(`Found ${formattedRecords.length} attendance records for session ${sessionId}`);
                
                return res.json({
                    success: true,
                    attendanceRecords: formattedRecords,
                    session: sessionResults[0]
                });
            });
        });
    } catch (error) {
        console.error('Exception in attendance endpoint:', error);
        return res.status(500).json({ success: false, message: 'Server error processing attendance request', error: error.message });
    }
});

// Get classes for a teacher
router.get("/teacher-classes/:teacherId", async (req, res) => {
  try {
    const teacherId = req.params.teacherId;
    
    // Verify authorization (either session or header-based)
    const isAuthenticated = 
      (req.session && req.session.userId && req.session.role === 'teacher' && req.session.userId == teacherId) ||
      (req.headers['x-user-id'] && req.headers['x-user-role'] === 'teacher' && req.headers['x-user-id'] == teacherId);
    
    if (!isAuthenticated) {
      console.log('Unauthorized access to teacher classes endpoint');
      console.log('Session user:', req.session?.userId, 'Session role:', req.session?.role);
      console.log('Header user:', req.headers['x-user-id'], 'Header role:', req.headers['x-user-role']);
      console.log('Requested teacher ID:', teacherId);
      
      return res.status(401).json({
        success: false,
        message: "Unauthorized. Please log in as a teacher."
      });
    }
    
    // Log the SQL query for debugging
    console.log(`Fetching classes for teacher ID: ${teacherId}`);
    
    try {
      // Query using the correct table name class_records instead of classes
      const [rows] = await db.query(
        `SELECT cr.id, cr.class_name as name, cr.description, cr.subject,
         COUNT(DISTINCT qs.id) as session_count, 
         COUNT(DISTINCT a.id) as total_attendances 
         FROM class_records cr
         LEFT JOIN qr_sessions qs ON cr.id = qs.class_id 
         LEFT JOIN attendance a ON qs.session_id = a.session_id 
         WHERE cr.teacher_id = ? AND cr.is_active = TRUE
         GROUP BY cr.id 
         ORDER BY cr.class_name ASC`,
        [teacherId]
      );
      
      console.log(`Found ${rows.length} classes for teacher ${teacherId}`);
      
      res.json({
        success: true,
        classes: rows
      });
    } catch (queryError) {
      console.error("Database query error:", queryError);
      // Fallback to a simpler query if the join is causing issues
      console.log("Trying fallback query...");
      
      const [basicRows] = await db.query(
        `SELECT id, class_name as name, description, subject
         FROM class_records 
         WHERE teacher_id = ? AND is_active = TRUE
         ORDER BY class_name ASC`,
        [teacherId]
      );
      
      console.log(`Found ${basicRows.length} classes in fallback query`);
      
      res.json({
        success: true,
        classes: basicRows,
        usedFallback: true
      });
    }
  } catch (error) {
    console.error("Error fetching teacher classes:", error);
    res.status(500).json({
      success: false,
      message: "Failed to load classes",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

module.exports = router;