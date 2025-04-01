const checkAuth = (req, res, next) => {
  // Log the session ID and cookie header for debugging
  console.log("🔐 Auth check - Session ID:", req.sessionID);
  console.log("🍪 Cookie header:", req.headers.cookie);

  // Simple session check - must have userId and role
  if (!req.session || !req.session.userId || !req.session.role) {
    console.log("❌ Auth failed - No valid session found");
    return res.status(401).json({ 
      success: false, 
      message: "Authentication required" 
    });
  }

  // Session is valid
  console.log(`✅ Auth successful - user ${req.session.userId} (${req.session.role})`);
  next();
};

// Role-specific middleware
const checkTeacher = (req, res, next) => {
  checkAuth(req, res, () => {
    if (req.session.role !== 'teacher') {
      console.log("❌ Not a teacher");
      return res.status(403).json({ 
        success: false, 
        message: "Teacher access required" 
      });
    }
    console.log("✅ Teacher verified");
    next();
  });
};

const checkStudent = (req, res, next) => {
  checkAuth(req, res, () => {
    if (req.session.role !== 'student') {
      console.log("❌ Not a student");
      return res.status(403).json({ 
        success: false, 
        message: "Student access required" 
      });
    }
    console.log("✅ Student verified");
    next();
  });
};

module.exports = {
  checkAuth,
  checkTeacher,
  checkStudent
}; 