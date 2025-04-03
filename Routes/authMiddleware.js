const db = require("../db");

// Main authentication middleware
const authenticate = async (req, res, next) => {
  // Special handling for check-auth endpoint
  if (req.path === '/check-auth') {
    // This path is handled separately in the LoginSystem.js route
    return next();
  }
  
  // Skip authentication checks for login path
  if (req.path === '/login') {
    return next();
  }
  
  // Only log auth once per request to reduce duplicate output
  if (!req._authLogged) {
    req._authLogged = true;
    console.log(`\n[AUTH] ${req.method} ${req.path}`);
  }
  
  try {
    // STEP 1: Check if we have a valid session via req.session
    if (req.session && req.session.userId && req.session.role) {
      const shouldLog = process.env.DEBUG || (!req.path.includes('health') && !req.path.includes('debug'));
      
      // Validate session exists in database
      const [sessions] = await db.query(
        `SELECT 
          user_id, 
          role,
          expires_at > NOW() AS is_active,
          created_at,
          last_activity
         FROM sessions 
         WHERE session_id = ? AND is_active = TRUE AND expires_at > NOW()`,
        [req.sessionID]
      );
      
      if (sessions.length > 0 && sessions[0].is_active) {
        if (shouldLog) {
          console.log("✅ Authenticated via session:", req.sessionID);
        }
        
        // Update last activity
        await db.query(
          "UPDATE sessions SET last_activity = NOW() WHERE session_id = ?",
          [req.sessionID]
        );
        
        // Attach user context to the request
        req.user = {
          id: sessions[0].user_id,
          role: sessions[0].role,
          sessionCreated: sessions[0].created_at,
          lastActivity: sessions[0].last_activity
        };
        
        return next();
      } else if (shouldLog) {
        console.log("⚠️ Session in request but not valid in database:", req.sessionID);
      }
    }
    
    // STEP 2: Check session cookie directly like in check-auth
    const sessionCookie = req.cookies?.qr_attendance_sid || (req.headers.cookie || '')
      .split(';')
      .map(c => c.trim())
      .find(c => c.startsWith('qr_attendance_sid='))
      ?.split('=')[1];
    
    if (sessionCookie) {
      console.log(`🍪 Found session cookie: ${sessionCookie}`);
      
      // Check if this session exists in the database
      const [sessionRows] = await db.query(
        "SELECT * FROM sessions WHERE session_id = ? AND expires_at > NOW() AND is_active = TRUE", 
        [sessionCookie]
      );
      
      if (sessionRows && sessionRows.length > 0) {
        console.log(`📝 Session found in database: ${sessionCookie}`);
        
        // Use the user_id and role from the verified session
        const userId = sessionRows[0].user_id;
        const role = sessionRows[0].role;
        
        // Attach user to the request
        req.user = { 
          id: userId, 
          role: role,
          sessionCreated: sessionRows[0].created_at,
          lastActivity: sessionRows[0].last_activity
        };
        
        // Also populate session for consistency
        req.session = req.session || {};
        req.session.userId = userId;
        req.session.role = role;
        
        // Update last activity
        await db.query(
          "UPDATE sessions SET last_activity = NOW() WHERE session_id = ?",
          [sessionCookie]
        );
        
        return next();
      } else {
        console.log(`⚠️ Session cookie ${sessionCookie} not found in database or expired`);
      }
    }
    
    // STEP 3: Check header-based authentication as fallback
    const headerUserId = req.headers['x-user-id'];
    const headerUserRole = req.headers['x-user-role'];
    
    if (headerUserId && headerUserRole) {
      console.log(`🔑 Header-based auth detected: User ${headerUserId} (${headerUserRole})`);
      
      // Validate the user exists
      let userExists = false;
      
      if (headerUserRole === 'teacher') {
        const [teachers] = await db.query(
          "SELECT id FROM teachers WHERE id = ?",
          [headerUserId]
        );
        userExists = teachers.length > 0;
      } else if (headerUserRole === 'student') {
        const [students] = await db.query(
          "SELECT id FROM students WHERE id = ?",
          [headerUserId]
        );
        userExists = students.length > 0;
      }
      
      if (userExists) {
        console.log(`✅ Header-based auth successful for ${headerUserId}`);
        
        // Attach user to the request
        req.user = { 
          id: parseInt(headerUserId), 
          role: headerUserRole,
          headerAuth: true
        };
        
        // Create a session for this user to improve future requests
        if (!req.session) {
          req.session = {};
        }
        
        req.session.userId = parseInt(headerUserId);
        req.session.role = headerUserRole;
        
        return next();
      } else {
        console.log(`❌ Invalid user ID or role in headers: ${headerUserId} (${headerUserRole})`);
      }
    }
    
    // No valid authentication found
    console.log("❌ Authentication failed - no valid session, cookie, or headers");
    return res.status(401).json({ 
      success: false, 
      message: "Authentication required. Please log in.",
      code: "AUTH_REQUIRED" 
    });
  } catch (error) {
    console.error("Authentication middleware error:", error);
    return res.status(500).json({ 
      success: false, 
      message: "Server error during authentication",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

// Role-based access control middleware
const requireRole = (role) => {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({ 
        success: false, 
        message: `Access restricted to ${role}s only.`,
        code: "ROLE_REQUIRED"
      });
    }
    next();
  };
};

// Session cleanup middleware (optional, can be run periodically)
const cleanupExpiredSessions = async () => {
  try {
    const [result] = await db.query(
      "DELETE FROM sessions WHERE expires_at <= NOW()"
    );
    console.log(`Cleaned up ${result.affectedRows} expired sessions`);
  } catch (error) {
    console.error("Session cleanup error:", error);
  }
};

module.exports = { 
  authenticate, 
  requireRole,
  cleanupExpiredSessions 
};

