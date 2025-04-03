const db = require("../db");

/**
 * Authentication middleware for protected routes
 * Checks if a valid session exists and attaches user data to the request
 */
const authenticate = async (req, res, next) => {
  console.log('🔒 Auth check - Session ID:', req.sessionID);
  console.log('🔒 Auth check - Cookies:', req.cookies ? Object.keys(req.cookies).join(', ') : 'none');
  
  // STEP 1: Check if session data exists in req.session (express-session)
  if (req.session && req.session.userId && req.session.role) {
    console.log(`Session authentication successful (ID: ${req.sessionID})`);
    
    // Attach user data to request
    req.user = { 
      id: req.session.userId, 
      role: req.session.role,
      firstName: req.session.firstName,
      lastName: req.session.lastName
    };
    
    // Update last_activity in database
    try {
      await db.query(
        `UPDATE sessions SET last_activity = NOW() WHERE session_id = ?`,
        [req.sessionID]
      );
    } catch (dbError) {
      console.log('Non-critical: Error updating session last activity:', dbError);
      // Continue anyway, not critical
    }
    
    return next();
  }
  
  // STEP 2: Check if session cookie exists and is valid
  const sessionId = req.cookies?.qr_attendance_sid;
  if (sessionId) {
    console.log(`Found session cookie: ${sessionId}, checking validity`);
    
    try {
      // Check if this session exists in database
      const [sessions] = await db.query(
        `SELECT user_id, role, data FROM sessions 
         WHERE session_id = ? AND expires_at > NOW() AND is_active = TRUE`,
        [sessionId]
      );

      if (sessions.length > 0) {
        console.log(`Valid session found in database for cookie ${sessionId}`);
        
        // Store user data from database
        const userId = sessions[0].user_id;
        const role = sessions[0].role;
        
        // Try to parse any stored session data
        let firstName = null;
        let lastName = null;
        
        try {
          const sessionData = JSON.parse(sessions[0].data || '{}');
          firstName = sessionData.firstName;
          lastName = sessionData.lastName;
        } catch (parseError) {
          console.error("Error parsing session data:", parseError);
          // Continue with basic info
        }
        
        // If missing name info, get from database
        if (!firstName || !lastName) {
          try {
            const tableName = role === 'teacher' ? 'teachers' : 'students';
            const [userRows] = await db.query(
              `SELECT first_name, last_name FROM ${tableName} WHERE id = ?`,
              [userId]
            );
            
            if (userRows.length > 0) {
              firstName = userRows[0].first_name;
              lastName = userRows[0].last_name;
            }
          } catch (userError) {
            console.error("Error getting user data:", userError);
            // Continue with what we have
          }
        }
        
        // Restore session data
        req.session.userId = userId;
        req.session.role = role;
        req.session.firstName = firstName;
        req.session.lastName = lastName;
        
        // Attach user to request
        req.user = { 
          id: userId, 
          role: role,
          firstName: firstName,
          lastName: lastName
        };
        
        // Update session activity
        await db.query(
          `UPDATE sessions SET last_activity = NOW() WHERE session_id = ?`,
          [sessionId]
        );
        
        return next();
      } else {
        console.log(`Session cookie ${sessionId} is invalid or expired`);
        // Invalid session, continue to check headers
      }
    } catch (error) {
      console.error("Database error during session check:", error);
      // Continue to check headers as fallback
    }
  }
  
  // STEP 3: Check for header-based authentication
  const userId = req.headers['x-user-id'];
  const role = req.headers['x-user-role'];
  
  if (userId && role) {
    console.log(`Attempting header-based auth for user ${userId} (${role})`);
    
    try {
      // Verify user exists in appropriate table
      const tableName = role === 'teacher' ? 'teachers' : 'students';
      const [userRows] = await db.query(
        `SELECT id, first_name, last_name FROM ${tableName} WHERE id = ? AND is_verified = TRUE`,
        [userId]
      );
      
      if (userRows.length > 0) {
        console.log(`Header-based auth successful for ${userId} (${role})`);
        
        // Set user in session and request
        req.session.userId = userId;
        req.session.role = role;
        req.session.firstName = userRows[0].first_name;
        req.session.lastName = userRows[0].last_name;
        
        // Attach user to request
        req.user = {
          id: userId,
          role: role,
          firstName: userRows[0].first_name,
          lastName: userRows[0].last_name
        };
        
        // Explicitly save session to ensure cookie is sent
        await new Promise((resolve, reject) => {
          req.session.save(err => {
            if (err) {
              console.error("Error saving session:", err);
              reject(err);
            } else {
              resolve();
            }
          });
        });
        
        return next();
      }
    } catch (error) {
      console.error("Error during header-based auth:", error);
      // Continue to unauthorized response
    }
  }
  
  // No valid authentication method found
  console.log('❌ Authentication failed');
  return res.status(401).json({ 
    success: false, 
    message: "Unauthorized - Please log in again" 
  });
};

/**
 * Role-based middleware for restricting access by role
 */
const requireRole = (role) => {
  return (req, res, next) => {
    // User must be authenticated first
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }
    
    // Check if user has the required role
    if (req.user.role !== role) {
      console.log(`🚫 Role check failed: User is ${req.user.role}, needs to be ${role}`);
      return res.status(403).json({
        success: false,
        message: `Access denied: ${role} role required`
      });
    }
    
    // Role check passed
    console.log(`✅ ${role} role verified for user ${req.user.id}`);
    next();
  };
};

// Specific role middleware helpers
const requireTeacher = (req, res, next) => {
  return requireRole('teacher')(req, res, next);
};

const requireStudent = (req, res, next) => {
  return requireRole('student')(req, res, next);
};

// Export the middleware
module.exports = {
  authenticate,
  requireRole,
  requireTeacher,
  requireStudent
}; 