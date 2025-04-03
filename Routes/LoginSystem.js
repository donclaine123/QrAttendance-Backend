const express = require("express");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const db = require("../db");

const router = express.Router(); 


let bcrypt;
try {
  bcrypt = require('bcrypt');
} catch (err) {
  console.log('Falling back to bcryptjs');
  bcrypt = require('bcryptjs');
}


// 📌 Configure Nodemailer for sending emails
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// 📌 Updated Login Function
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check both tables
    const [[teachers], [students]] = await Promise.all([
      db.query("SELECT id, password_hash, first_name, last_name FROM teachers WHERE email = ? AND is_verified = TRUE", [email]),
      db.query("SELECT id, password_hash, first_name, last_name FROM students WHERE email = ? AND is_verified = TRUE", [email])
    ]);

    const user = teachers[0] || students[0];
    const role = teachers[0] ? 'teacher' : 'student';

    // Authentication checks
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: "Invalid credentials or account not verified" 
      });
    }
    
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ 
        success: false, 
        message: "Invalid credentials" 
      });
    }

    console.log(`User ${user.id} with role ${role} is logging in - session ID: ${req.sessionID}`);

    // IMPROVED SESSION MANAGEMENT: First invalidate any existing sessions for this user
    try {
      const [existingSessions] = await db.query(
        `SELECT session_id FROM sessions 
         WHERE user_id = ? AND role = ? AND is_active = TRUE`,
        [user.id, role]
      );
      
      if (existingSessions.length > 0) {
        console.log(`Found ${existingSessions.length} existing sessions for user ${user.id}. Marking as inactive.`);
        
        await db.query(
          `UPDATE sessions 
           SET is_active = FALSE, last_activity = NOW()
           WHERE user_id = ? AND role = ?`,
          [user.id, role]
        );
      }
    } catch (dbError) {
      console.error("Error handling existing sessions:", dbError);
      // Continue with login process, not critical
    }

    // Clear any existing session data
    req.session.regenerate(async function(err) {
      if (err) {
        console.error("Error regenerating session:", err);
        return res.status(500).json({ 
          success: false, 
          message: "Session regeneration failed", 
          error: err.message
        });
      }
      
      // Set session data
      req.session.userId = user.id;
      req.session.role = role;
      req.session.firstName = user.first_name;
      req.session.lastName = user.last_name;
      req.session.email = email;
      req.session.createdAt = new Date().toISOString();
      req.session.lastActivity = new Date().toISOString();
      
      // Ensure session record is created in database with proper expiration
      try {
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
        
        await db.query(
          `INSERT INTO sessions 
           (session_id, data, expires_at, user_id, role, is_active, created_at, last_activity)
           VALUES (?, ?, ?, ?, ?, TRUE, NOW(), NOW())
           ON DUPLICATE KEY UPDATE
           data = VALUES(data),
           expires_at = VALUES(expires_at),
           is_active = TRUE,
           last_activity = NOW()`,
          [
            req.sessionID,
            JSON.stringify(req.session),
            expiresAt,
            user.id,
            role
          ]
        );
        
        console.log(`Session record created in database: ${req.sessionID}`);
      } catch (dbError) {
        console.error("Error creating session record:", dbError);
        // Continue anyway, express-session will still work
      }
      
      // Save the session
      req.session.save(function(saveErr) {
        if (saveErr) {
          console.error("Error saving session:", saveErr);
          return res.status(500).json({ 
            success: false, 
            message: "Session save failed", 
            error: saveErr.message
          });
        }
        
        console.log(`✅ Session saved successfully for ${email}. Session ID:`, req.sessionID);
        
        // Set cookie manually with correct options based on environment
        const isProd = process.env.NODE_ENV === 'production';
        const cookieOptions = {
          httpOnly: true,
          path: '/',
          maxAge: 24 * 60 * 60 * 1000, // 24 hours
          secure: isProd, // true in production
          sameSite: isProd ? 'none' : 'lax' // 'none' in production
        };
        
        // Log cookie settings for debugging
        console.log("🍪 Setting cookie with options:", {
          secure: cookieOptions.secure,
          sameSite: cookieOptions.sameSite,
          httpOnly: cookieOptions.httpOnly,
          origin: req.headers.origin
        });
        
        res.cookie('qr_attendance_sid', req.sessionID, cookieOptions);
        
        // Return user data and session info
        return res.json({ 
      success: true,
      role,
      user: {
        id: user.id,
        firstName: user.first_name,
            lastName: user.last_name,
            email: email
      },
          sessionId: req.sessionID,
          redirect: role === 'teacher' ? '/pages/teacher-dashboard.html' : '/pages/student-dashboard.html'
        });
      });
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Login failed",
      error: error.message
    });
  }
});

// 📌 Updated logout endpoint
router.post('/logout', async (req, res) => {
  console.log('Logout requested - Session ID:', req.sessionID);
  
  if (req.session) {
    // Capture user info and session ID for database deletion
    const userId = req.session.userId;
    const role = req.session.role;
    const sessionId = req.sessionID; // Store session ID before destroying
    // Destroy the session
    await new Promise((resolve, reject) => {
    req.session.destroy(err => {
      if (err) {
        console.error('Session destruction error:', err);
          reject(err);
        } else {
          resolve();
        }
      });
    });
    
    console.log(`✅ Session destroyed for user ${userId} (${role})`);
    
    // Clear the cookie with proper options for production/development
    const isProd = process.env.NODE_ENV === 'production';
    const cookieOptions = {
        path: '/',
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'none' : 'lax'
    };
    
    console.log(`Clearing cookie with options:`, cookieOptions);
    
    // Clear both cookie domains to ensure it's properly removed
    res.clearCookie('qr_attendance_sid', cookieOptions);
    
    // Delete from the database directly to ensure it's gone
    try {
      console.log(`Deleting session ${sessionId} from database`);
      await db.query('DELETE FROM sessions WHERE session_id = ?', [sessionId]);
      console.log(`Session successfully deleted from database`);
    } catch (dbError) {
      console.error('Error deleting session from database:', dbError);
      // Non-critical error, continue
    }
      
      return res.json({
        success: true,
        message: 'Logged out successfully'
    });
  } else {
    console.log('No session found during logout attempt');
    res.json({
      success: true,
      message: 'Already logged out'
    });
  }
});

// 📌 Session Validation Middleware
const authenticate = async (req, res, next) => {
  try {
    // First try cookie-based session
    const sessionId = req.cookies.qr_attendance_sid;
    let isAuthenticated = false;

    if (sessionId) {
      // Check if this session exists and is active in the database
      const [sessions] = await db.query(
        `SELECT * FROM sessions 
         WHERE session_id = ? AND is_active = TRUE AND expires_at > NOW()`,
        [sessionId]
      );

      if (sessions.length > 0) {
        const sessionData = JSON.parse(sessions[0].data);
        req.user = {
          id: sessions[0].user_id,
          role: sessions[0].role,
          firstName: sessionData.firstName,
          lastName: sessionData.lastName
        };
        
        // Update last activity
        await db.query(
          `UPDATE sessions SET last_activity = NOW() WHERE session_id = ?`,
          [sessionId]
        );
        
        isAuthenticated = true;
      }
    }

    // If cookie auth failed, try header-based auth
    if (!isAuthenticated) {
      const userId = req.headers['x-user-id'];
      const userRole = req.headers['x-user-role'];

      if (userId && userRole) {
        // Look up the most recent active session for this user
        const [sessions] = await db.query(
          `SELECT * FROM sessions 
           WHERE user_id = ? AND role = ? AND is_active = TRUE AND expires_at > NOW()
           ORDER BY last_activity DESC, created_at DESC LIMIT 1`,
          [userId, userRole]
        );

        if (sessions.length > 0) {
          const sessionData = JSON.parse(sessions[0].data);
          req.user = {
            id: parseInt(userId),
            role: userRole,
            firstName: sessionData.firstName,
            lastName: sessionData.lastName
          };

          // Update last activity
          await db.query(
            `UPDATE sessions SET last_activity = NOW() WHERE session_id = ?`,
            [sessions[0].session_id]
          );

          // Set the cookie to maintain the session
          const isProd = process.env.NODE_ENV === 'production';
          res.cookie('qr_attendance_sid', sessions[0].session_id, {
            httpOnly: true,
            secure: isProd,
            sameSite: isProd ? 'none' : 'lax',
            path: '/',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
          });

          isAuthenticated = true;
        }
      }
    }

    if (!isAuthenticated) {
      return res.status(401).json({ 
        success: false, 
        message: "Authentication required" 
      });
    }

    next();
  } catch (error) {
    console.error("Authentication error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Server error during authentication" 
    });
  }
};

// Role-based authorization middleware
const requireRole = (role) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        success: false, 
        message: "Authentication required" 
      });
    }

    if (req.user.role !== role) {
      return res.status(403).json({ 
        success: false, 
        message: `Access denied. ${role} role required.` 
      });
    }

    next();
  };
};

// 📌 Register User
router.post("/register", async (req, res) => {
  const { role, email, firstName, lastName, password, studentId } = req.body;

  try {
    // 🔹 Check if email already exists
    const [teacherRows] = await db.query("SELECT id FROM teachers WHERE email = ?", [email]);
    if (teacherRows.length > 0) {
      return res.status(400).json({ success: false, message: "Email already registered as a teacher." });
    }

    const [studentRows] = await db.query("SELECT id FROM students WHERE email = ?", [email]);
    if (studentRows.length > 0) {
      return res.status(400).json({ success: false, message: "Email already registered as a student." });
    }

    // 🔹 Hash password and generate verification token
    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(32).toString("hex");

    let userId;
    if (role === "teacher") {
      const [result] = await db.query(
        "INSERT INTO teachers (email, password_hash, first_name, last_name, verification_token, is_verified) VALUES (?, ?, ?, ?, ?, ?)",
        [email, hashedPassword, firstName, lastName, verificationToken, false] // Use BOOLEAN for is_verified
      );
      userId = result.insertId;
    } else if (role === "student") {
      const [result] = await db.query(
        "INSERT INTO students (email, password_hash, first_name, last_name, student_id, verification_token, is_verified) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [email, hashedPassword, firstName, lastName, studentId, verificationToken, false]
      );
      userId = result.insertId;
    } else {
      return res.status(400).json({ success: false, message: "Invalid role" });
    }

    // 🔹 Send verification email
    const verifyUrl = `http://localhost:5000/auth/verify?token=${verificationToken}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Verify Your Email",
      html: `<p>Click <a href="${verifyUrl}">VERIFY</a> to verify your email.</p>`,
    });

    res.json({ 
      success: true, 
      message: "Registration successful! Check your email for verification.",
      userId: userId
    });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ 
      success: false, 
      message: "Registration failed",
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});


// 📌 Verify Email
router.get("/verify", async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json({ 
      success: false, 
      message: "Missing verification token" 
    });
  }

  try {
    // 🔹 Check teachers table
    const [teacherRows] = await db.query("SELECT id FROM teachers WHERE verification_token = ?", [token]);
    if (teacherRows.length > 0) {
      await db.query(
        "UPDATE teachers SET is_verified = TRUE, verification_token = NULL WHERE id = ?",
        [teacherRows[0].id]
      );
      return res.json({ 
        success: true, 
        message: "Email verified! You can now log in.",
        redirectUrl: "/index.html"
      });
    }

    // 🔹 Check students table
    const [studentRows] = await db.query("SELECT id FROM students WHERE verification_token = ?", [token]);
    if (studentRows.length > 0) {
      await db.query(
        "UPDATE students SET is_verified = TRUE, verification_token = NULL WHERE id = ?",
        [studentRows[0].id]
      );
      return res.json({ 
        success: true, 
        message: "Email verified! You can now log in.",
        redirectUrl: "/index.html"
      });
    }

    // 🔹 If no matching token
    res.status(400).json({ 
      success: false, 
      message: "Invalid or expired verification token.",
      redirectUrl: "/index.html"
    });
  } catch (err) {
    console.error("Verification error:", err);
    res.status(500).json({ 
      success: false, 
      message: "Verification failed due to a server error. Please try again.",
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// 📌 Update check-auth endpoint
router.get('/check-auth', async (req, res) => {
  try {
    const sessionId = req.cookies.qr_attendance_sid;

    // First check if we have a valid session cookie
    if (sessionId) {
      // Verify the session in the database
      const [sessions] = await db.query(
        `SELECT * FROM sessions 
         WHERE session_id = ? AND is_active = TRUE AND expires_at > NOW()`,
        [sessionId]
      );

      if (sessions.length > 0) {
        const sessionData = JSON.parse(sessions[0].data);
        
        // Update last activity
        await db.query(
          `UPDATE sessions SET last_activity = NOW() WHERE session_id = ?`,
          [sessionId]
        );

      return res.json({
        authenticated: true,
          user: {
            id: sessions[0].user_id,
            role: sessions[0].role,
            firstName: sessionData.firstName,
            lastName: sessionData.lastName
          }
        });
      } else {
        // Invalid session - clear the cookie
        res.clearCookie('qr_attendance_sid', {
          path: '/',
          httpOnly: true,
          secure: true,
          sameSite: 'none'
        });
      }
    }

    // If we reach here, check headers as absolute last resort
    const userId = req.headers['x-user-id'];
    const userRole = req.headers['x-user-role'];

    if (userId && userRole) {
      // Look up the most recent active session for this user
      const [sessions] = await db.query(
        `SELECT * FROM sessions 
         WHERE user_id = ? AND role = ? AND is_active = TRUE AND expires_at > NOW()
         ORDER BY last_activity DESC, created_at DESC LIMIT 1`,
        [userId, userRole]
      );

      if (sessions.length > 0) {
          const sessionData = JSON.parse(sessions[0].data);
        
        // Set the cookie to the existing session
        res.cookie('qr_attendance_sid', sessions[0].session_id, {
          httpOnly: true,
          secure: true,
          sameSite: 'none',
          path: '/',
          maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });

          return res.json({
            authenticated: true,
            user: {
            id: sessions[0].user_id,
            role: sessions[0].role,
            firstName: sessionData.firstName,
            lastName: sessionData.lastName
          }
        });
      }
    }

    // No valid session found
    res.json({
      authenticated: false,
      message: "Session expired. Please log in again."
    });

  } catch (error) {
    console.error('Auth check error:', error);
    res.status(500).json({
      authenticated: false,
      message: "Error checking authentication status"
    });
  }
});

// 📌 Debug route to check session information
router.get("/debug-session", (req, res) => {
  console.log("Session ID:", req.sessionID);
  console.log("Session data:", req.session);
  
  res.json({
    sessionId: req.sessionID,
    sessionExists: !!req.session,
    sessionData: req.session ? {
      userId: req.session.userId,
      role: req.session.role,
      firstName: req.session.firstName,
      lastName: req.session.lastName
    } : null
  });
});

// 📌 Test endpoint for setting a cookie
router.get("/test-cookie", (req, res) => {
  // Set a test cookie directly using the response object
  res.cookie('testCookie', 'cookie-value', {
    maxAge: 900000, // 15 minutes
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    path: '/'
  });
  
  // Set a value in the session
  if (!req.session.test) {
    req.session.test = { timestamp: new Date().toISOString() };
    // Add temporary userId and role for testing session store
    req.session.userId = -999; // Using negative ID to indicate test user
    req.session.role = 'test';
    console.log("Set test session value with userId and role");
  } else {
    console.log("Test session already exists:", req.session.test);
  }
  
  // Save session explicitly
  req.session.save((err) => {
    if (err) {
      console.error("Error saving test session:", err);
    }
    
    res.json({
      success: true,
      message: "Test cookie set",
      sessionId: req.sessionID,
      sessionData: req.session
    });
  });
});

// 📌 Debug route to check cookies
router.get("/debug-cookies", (req, res) => {
  console.log("Cookies received:", req.cookies);
  
  // Don't create or use req.sessionID which can create a new session
  const sessionCookie = req.cookies.qr_attendance_sid || null;
  
  res.json({
    cookies: req.cookies,
    sessionExists: !!sessionCookie,
    sessionId: sessionCookie // Return the actual cookie value, not req.sessionID
  });
});

// 📌 Updated Direct Teacher Login
router.post('/direct-teacher-login', async (req, res) => {
  try {
    const { teacher_id, key } = req.body;
    
    // Validate input
    if (!teacher_id || !key) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }
    
    // Check the direct login key is valid
    const [[rows]] = await db.query(
      'SELECT id, first_name, last_name FROM teachers WHERE id = ? AND direct_login_key = ? AND is_verified = TRUE',
      [teacher_id, key]
    );
    
    if (!rows.length) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    const teacher = rows[0];
    console.log(`Teacher ${teacher.id} using direct login - session ID: ${req.sessionID}`);
    
    // Regenerate session to ensure a clean state
    req.session.regenerate(function(err) {
      if (err) {
        console.error("Error regenerating session:", err);
        return res.status(500).json({ 
          success: false, 
          message: "Session creation failed", 
          error: process.env.NODE_ENV === 'development' ? err.message : undefined 
        });
      }
      
      // Set session data after regeneration
      req.session.userId = teacher.id;
      req.session.role = 'teacher';
      req.session.firstName = teacher.first_name;
      req.session.lastName = teacher.last_name;
      req.session.createdAt = new Date();
      
      // Save session explicitly once
      req.session.save(function(saveErr) {
        if (saveErr) {
          console.error("Error saving session:", saveErr);
          return res.status(500).json({ 
            success: false, 
            message: "Session save failed", 
            error: process.env.NODE_ENV === 'development' ? saveErr.message : undefined
          });
        }
        
        console.log("✅ Session saved successfully. ID:", req.sessionID);
        
        // Ensure cookie is set with the current session ID
        if (req.sessionID) {
          res.cookie('qr_attendance_sid', req.sessionID, {
            httpOnly: true,
            path: '/',
            maxAge: 24 * 60 * 60 * 1000,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
          });
        }
        
        res.json({
          success: true,
          role: 'teacher',
          user: {
            id: teacher.id,
            firstName: teacher.first_name,
            lastName: teacher.last_name
          },
          sessionId: req.sessionID,
          redirect: '/teacher-dashboard'
        });
      });
    });
  } catch (error) {
    console.error('Direct teacher login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error', 
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Debug route to check request headers
router.get("/debug-headers", (req, res) => {
  console.log("====== DEBUG HEADERS ======");
  console.log("Headers:", req.headers);
  console.log("Origin:", req.headers.origin);
  console.log("Referer:", req.headers.referer);
  console.log("Host:", req.headers.host);
  console.log("User-Agent:", req.headers['user-agent']);
  console.log("Cookie:", req.headers.cookie);
  console.log("===========================");
  
  res.json({
    success: true,
    headers: req.headers,
    cookies: req.cookies,
    sessionID: req.sessionID,
    session: req.session ? {
      userId: req.session.userId,
      role: req.session.role
    } : null
  });
});

// Add a test-cookie endpoint to help debug cookie issues
router.get('/test-cookie', async (req, res) => {
  console.log('Test cookie endpoint called');
  
  try {
    // Set a test cookie
    res.cookie('test_cookie', 'working', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 3600000 // 1 hour
    });
    
    // Log request headers for debugging
    console.log('Request headers:', req.headers);
    console.log('Cookies received:', req.cookies);
    
    res.json({
      success: true,
      message: 'Test cookie set',
      time: new Date().toISOString(),
      cookiesReceived: req.cookies ? Object.keys(req.cookies) : [],
      headers: {
        host: req.headers.host,
        origin: req.headers.origin,
        referer: req.headers.referer,
        'user-agent': req.headers['user-agent'],
        cookie: req.headers.cookie
      }
    });
  } catch (error) {
    console.error('Error in test-cookie endpoint:', error);
    res.status(500).json({
      success: false,
      message: 'Error setting test cookie',
      error: error.message
    });
  }
});

// Add a debug-cookies endpoint to help inspect cookies
router.get('/debug-cookies', (req, res) => {
  console.log('Debug cookies endpoint called');
  console.log('Cookies received:', req.cookies);
  
  // Don't create or use req.sessionID which can create a new session
  const sessionCookie = req.cookies.qr_attendance_sid || null;
  
  res.json({
    success: true,
    cookies: req.cookies || {},
    sessionExists: !!sessionCookie,
    sessionId: sessionCookie // Return the actual cookie value, not req.sessionID
  });
});

// 📌 Test session creation and storage
router.get('/test-session-store', async (req, res) => {
  console.log('Test session storage endpoint called');
  console.log('Current session ID:', req.sessionID);
  console.log('Session exists:', !!req.session);
  
  // Create a test value in the session
  if (!req.session.test) {
    req.session.test = {
      created: new Date().toISOString(),
      random: Math.random()
    };
    req.session.testCount = 1;
    console.log('Created new test session data');
  } else {
    req.session.testCount = (req.session.testCount || 0) + 1;
    req.session.test.lastAccessed = new Date().toISOString();
    console.log('Updated existing test session data');
  }
  
  // Add temporary userId and role for testing (if they don't exist)
  if (!req.session.userId) {
    req.session.userId = -999;
    req.session.role = 'test-user';
    console.log('Added test user ID and role');
  }
  
  // Save session explicitly
  await new Promise((resolve, reject) => {
    req.session.save((err) => {
      if (err) {
        console.error('Error saving test session:', err);
        reject(err);
      } else {
        console.log('Session saved successfully');
        resolve();
      }
    });
  });
  
  // Check if session exists in database
  try {
    const [sessions] = await db.query(
      `SELECT * FROM sessions WHERE session_id = ?`,
      [req.sessionID]
    );
    
    const sessionExists = sessions.length > 0;
    console.log('Session exists in database:', sessionExists);
    
    if (sessionExists) {
      console.log('Session record:', {
        id: sessions[0].session_id,
        userId: sessions[0].user_id,
        role: sessions[0].role,
        expires: sessions[0].expires_at,
        isActive: sessions[0].is_active
      });
    }
    
    res.json({
      success: true,
      message: 'Test session ' + (req.session.testCount === 1 ? 'created' : 'updated'),
      sessionId: req.sessionID,
      testCount: req.session.testCount,
      testData: req.session.test,
      storedInDatabase: sessionExists,
      databaseRecord: sessionExists ? {
        userId: sessions[0].user_id,
        role: sessions[0].role,
        expires: sessions[0].expires_at,
        isActive: sessions[0].is_active === 1
      } : null
    });
  } catch (error) {
    console.error('Error checking session in database:', error);
    res.status(500).json({
      success: false,
      message: 'Error checking session storage',
      sessionId: req.sessionID,
      error: error.message
    });
  }
});

// 📌 Session re-authentication endpoint for LocalStorage fallback
router.post("/reauth", async (req, res) => {
  const { userId, role } = req.body;
  
  if (!userId || !role) {
    return res.status(400).json({
      success: false,
      message: "Missing userId or role"
    });
  }
  
  try {
    console.log(`Re-authentication attempt for user ${userId} (${role})`);
    
    // First check if there's already an active session for this user
    const [existingSessions] = await db.query(
      `SELECT session_id, data FROM sessions 
       WHERE user_id = ? AND role = ? AND is_active = TRUE AND expires_at > NOW()
       ORDER BY created_at DESC LIMIT 1`,
      [userId, role]
    );
    
    // If an active session exists, use it instead of creating a new one
    if (existingSessions.length > 0) {
      const existingSessionId = existingSessions[0].session_id;
      console.log(`Found existing active session ${existingSessionId} for user ${userId}, reusing instead of creating new one`);
      
      // Update the session data
      req.session.userId = userId;
      req.session.role = role;
      
      // Get name information from database
      const [userInfo] = await db.query(
        `SELECT first_name, last_name FROM ${role}s WHERE id = ?`,
        [userId]
      );
      
      if (userInfo.length > 0) {
        req.session.firstName = userInfo[0].first_name;
        req.session.lastName = userInfo[0].last_name;
      }
      
      // Update last activity
      await db.query(
        `UPDATE sessions SET last_activity = NOW() WHERE session_id = ?`,
        [existingSessionId]
      );
      
      // Set the session cookie explicitly
      const isProd = process.env.NODE_ENV === 'production';
      const cookieOptions = {
        httpOnly: true,
        path: '/',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        secure: isProd,
        sameSite: isProd ? 'none' : 'lax'
      };
      
      res.cookie('qr_attendance_sid', existingSessionId, cookieOptions);
      
      return res.json({
        success: true,
        message: "Session reestablished",
        sessionId: existingSessionId,
        user: {
          id: userId,
          role: role,
          firstName: req.session.firstName,
          lastName: req.session.lastName
        }
      });
    }
    
    // If no active session, create a new one
    // Verify the user exists in the database
    let userExists = false;
    let firstName = null;
    let lastName = null;
    
    if (role === 'teacher') {
      const [teachers] = await db.query(
        "SELECT id, first_name, last_name FROM teachers WHERE id = ? AND is_verified = TRUE",
        [userId]
      );
      if (teachers.length > 0) {
        userExists = true;
        firstName = teachers[0].first_name;
        lastName = teachers[0].last_name;
      }
    } else if (role === 'student') {
      const [students] = await db.query(
        "SELECT id, first_name, last_name FROM students WHERE id = ? AND is_verified = TRUE",
        [userId]
      );
      if (students.length > 0) {
        userExists = true;
        firstName = students[0].first_name;
        lastName = students[0].last_name;
      }
    }
    
    if (!userExists) {
      return res.status(400).json({
        success: false,
        message: "Invalid user ID or role"
      });
    }
    
    // Clear any existing session data and create a new one
    req.session.regenerate((err) => {
      if (err) {
        console.error("Session regeneration failed:", err);
        return res.status(500).json({ 
          success: false, 
          message: "Failed to create new session" 
        });
      }
      
      // Set session data
      req.session.userId = userId;
      req.session.role = role;
      req.session.firstName = firstName;
      req.session.lastName = lastName;
      
      // Save session
      req.session.save((saveErr) => {
        if (saveErr) {
          console.error("Session save failed:", saveErr);
          return res.status(500).json({ 
            success: false, 
            message: "Failed to save session" 
          });
        }
        
        console.log(`Created new session ${req.sessionID} for user ${userId}`);
        
        // Set cookie with proper environment settings
        const isProd = process.env.NODE_ENV === 'production';
        const cookieOptions = {
          httpOnly: true,
          path: '/',
          maxAge: 24 * 60 * 60 * 1000, // 24 hours
          secure: isProd,
          sameSite: isProd ? 'none' : 'lax'
        };
        
        res.cookie('qr_attendance_sid', req.sessionID, cookieOptions);
        
        return res.json({
      success: true, 
          message: "Session created",
          sessionId: req.sessionID,
          user: {
            id: userId,
            role: role,
            firstName: firstName,
            lastName: lastName
          }
        });
      });
    });
  } catch (error) {
    console.error("Re-authentication error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Server error during re-authentication" 
    });
  }
});

module.exports = router;

