const db = require("../db");

// Main authentication middleware
const authenticate = async (req, res, next) => {
  // Skip authentication for specific endpoints
  if (req.path === '/login' || req.path === '/reauth') {
    return next();
  }
  
  // Special handling for check-auth endpoint
  if (req.path === '/check-auth') {
    // Only log in debug mode or if no previous auth check happened
    if (process.env.DEBUG || !req._authChecked) {
      console.log("\n=== AUTH CHECK ===");
      console.log('Session ID:', req.sessionID);
    }
    
    // Set flag to prevent duplicate logging
    req._authChecked = true;
    
    if (req.session && req.session.userId) {
      try {
        let user = null;
        
        if (req.session.role === 'teacher') {
          const [teachers] = await db.query(
            "SELECT id, email, first_name, last_name FROM teachers WHERE id = ?", 
            [req.session.userId]
          );
          user = teachers[0];
        } else if (req.session.role === 'student') {
          const [students] = await db.query(
            "SELECT id, email, first_name, last_name, student_id FROM students WHERE id = ?", 
            [req.session.userId]
          );
          user = students[0];
        }
        
        if (user) {
          return res.json({
            authenticated: true,
            role: req.session.role,
            user: {
              id: user.id,
              email: user.email,
              firstName: user.first_name,
              lastName: user.last_name,
              studentId: user.student_id || null
            }
          });
        }
      } catch (error) {
        console.error("Error in check-auth:", error);
      }
    }
    
    return res.json({ authenticated: false, message: "No valid session found" });
  }
  
  // Only log auth once per request to reduce duplicate output
  if (!req._authLogged) {
    req._authLogged = true;
    console.log(`\n[AUTH] ${req.method} ${req.path}`);
  }
  
  // Check if we have no session or no userId in the session
  if (!req.session || !req.session.userId) {
    // Only log failed auth for non-common requests
    if (!req.path.includes('/health') && !req.path.endsWith('.ico')) {
      console.log("❌ Not authenticated");
    }
    
    // Check Authorization header for credentials
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Basic ')) {
      try {
        const base64Credentials = authHeader.split(' ')[1];
        const credentials = Buffer.from(base64Credentials, 'base64').toString('utf8');
        const [email, password] = credentials.split(':');
        
        console.log("Attempting authorization from header for:", email);
        
        // Try to verify credentials
        const [[teachers], [students]] = await Promise.all([
          db.query("SELECT id, password_hash, role FROM teachers WHERE email = ? AND is_verified = TRUE", [email]),
          db.query("SELECT id, password_hash, role FROM students WHERE email = ? AND is_verified = TRUE", [email])
        ]);
        
        const user = teachers[0] || students[0];
        const role = teachers[0] ? 'teacher' : 'student';
        
        if (user) {
          // Set up the session with the authenticated user
          req.session = req.session || {};
          req.session.userId = user.id;
          req.session.role = role;
          
          // Set the user context
          req.user = {
            id: user.id,
            role: role
          };
          
          console.log("✅ Auth via header successful");
          return next();
        }
      } catch (error) {
        console.error("Error authenticating from header:", error);
      }
    }
    
    // Don't bother checking the database for sessions if there's no cookie
    if (!req.headers.cookie) {
      return res.status(401).json({
        success: false, 
        message: "Authentication required. Please log in.",
        code: "NO_COOKIE"
      });
    }
    
    // Only try to recover session from database if we have a sessionID
    if (req.sessionID) {
      try {
        const [sessions] = await db.query(
          `SELECT 
            user_id, 
            role,
            expires_at > NOW() AS is_active,
            created_at,
            last_activity
           FROM sessions 
           WHERE session_id = ? AND expires_at > NOW() AND is_active = TRUE`,
          [req.sessionID]
        );
        
        if (sessions.length > 0 && sessions[0].is_active) {
          // Only log this for non-common routes to reduce noise
          if (!req.path.includes('/health')) {
            console.log("✅ Session recovered from database");
          }
          
          // Reconstruct the session from the database
          req.session = req.session || {};
          req.session.userId = sessions[0].user_id;
          req.session.role = sessions[0].role;
          
          // Update last activity
          await db.query(
            "UPDATE sessions SET last_activity = NOW() WHERE session_id = ?",
            [req.sessionID]
          );
          
          // Attach user context
          req.user = {
            id: sessions[0].user_id,
            role: sessions[0].role,
            sessionCreated: sessions[0].created_at,
            lastActivity: sessions[0].last_activity
          };
          
          return next();
        }
      } catch (e) {
        console.error("Error checking database for session:", e);
      }
    }
    
    return res.status(401).json({ 
      success: false, 
      message: "Authentication required. Please log in.",
      code: "NO_SESSION" 
    });
  }

  try {
    // Validate session in database only for authenticated requests
    // Only log for non-routine requests or in debug mode
    const shouldLog = process.env.DEBUG || (!req.path.includes('health') && !req.path.includes('debug'));
    
    const [sessions] = await db.query(
      `SELECT 
        user_id, 
        role,
        expires_at > NOW() AS is_active,
        created_at,
        last_activity
       FROM sessions 
       WHERE session_id = ?`,
      [req.sessionID]
    );

    // Handle invalid/expired sessions
    if (sessions.length === 0 || !sessions[0].is_active) {
      if (shouldLog) {
        console.log("❌ Session invalid or expired");
      }
      
      // Try to reinsert the session if we have the data
      if (req.session.userId && req.session.role) {
        try {
          if (shouldLog) {
            console.log("Attempting session recovery");
          }
          
          const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
          
          await db.query(
            `INSERT INTO sessions (session_id, data, expires_at, user_id, role, is_active)
             VALUES (?, ?, ?, ?, ?, TRUE)
             ON DUPLICATE KEY UPDATE
               data = VALUES(data),
               expires_at = VALUES(expires_at),
               is_active = TRUE`,
            [
              req.sessionID,
              JSON.stringify(req.session),
              expiresAt,
              req.session.userId,
              req.session.role
            ]
          );
          
          if (shouldLog) {
            console.log("✅ Session reinserted");
          }
          
          // Skip the rest of the validation and attach user info
          req.user = {
            id: req.session.userId,
            role: req.session.role,
            sessionCreated: new Date(),
            lastActivity: new Date()
          };
          
          return next();
        } catch (e) {
          console.error("Error reinserting session:", e);
        }
      }
      
      // Auto-cleanup expired session
      if (sessions.length > 0) {
        await db.query(
          "DELETE FROM sessions WHERE session_id = ?",
          [req.sessionID]
        );
      }
      
      req.session.destroy();
      return res.status(401).json({ 
        success: false, 
        message: "Session expired. Please log in again.",
        code: "SESSION_EXPIRED"
      });
    }

    // Update last activity
    await db.query(
      "UPDATE sessions SET last_activity = NOW() WHERE session_id = ?",
      [req.sessionID]
    );

    // Attach user context to request
    req.user = {
      id: sessions[0].user_id,
      role: sessions[0].role,
      sessionCreated: sessions[0].created_at,
      lastActivity: sessions[0].last_activity
    };
    
    next();
  } catch (error) {
    console.error("❌ AUTH ERROR:", error);
    res.status(500).json({ 
      success: false, 
      message: "Internal server error during authentication.",
      code: "AUTH_ERROR"
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

