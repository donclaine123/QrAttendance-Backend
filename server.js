const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const cookieParser = require('cookie-parser');
const db = require("./db");
const loginSystem = require("./Routes/LoginSystem");
const attendanceSystem = require("./Routes/AttendanceSystemBack");
const session = require('express-session');
const CustomMySQLStore = require('./Routes/CustomSessionStore');
const qrSystem = require("./Routes/QrSystem");
const crypto = require('crypto');


const app = express();
const PORT = process.env.PORT || 5000;


// Initialize store with error handling
let sessionStore;
try {
  // Ensure we use the 'new' keyword here
  sessionStore = new CustomMySQLStore();
  
  // Prevent max listeners warning
  if (sessionStore.setMaxListeners) {
    sessionStore.setMaxListeners(20);
  }
  
  console.log("Session store initialized successfully");
} catch (err) {
  console.error('Failed to initialize session store:', err);
  process.exit(1);
}

// Body parsing - must be before session middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// Configure CORS with very permissive settings for development
app.use(
  cors({
    origin: function(origin, callback) {
      const allowedOrigins = [
        "http://localhost:5500", 
        "http://localhost:3000", 
        "http://127.0.0.1:5500", 
        "https://splendorous-paprenjak-09a988.netlify.app"
      ];
      
      // Allow requests with no origin (like mobile apps, curl, etc)
      if (!origin || allowedOrigins.indexOf(origin) !== -1) {
        callback(null, origin);
      } else {
        console.log(`Origin ${origin} not allowed by CORS`);
        callback(null, false);
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With", "Accept", "Cache-Control", "X-User-ID", "X-User-Role"],
    exposedHeaders: ["Set-Cookie"],
    preflightContinue: false
  })
);

// Add CORS headers directly for more compatibility
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && (origin.includes('localhost') || origin.includes('127.0.0.1') || origin.includes('netlify.app'))) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, Cache-Control, X-User-ID, X-User-Role');
    res.header('Access-Control-Expose-Headers', 'Set-Cookie');
    
    // Handle OPTIONS preflight request
    if (req.method === 'OPTIONS') {
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      return res.status(200).end();
    }
  }
  next();
});

// Configure session middleware
const sessionMiddleware = session({
  key: 'qr_attendance_sid',
  secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    // Set security based on environment
    secure: true, // Set to true for proper cross-origin cookies
    sameSite: 'none' // Critical for cross-origin cookies
  }
});

// Add session collision protection
app.use((req, res, next) => {
  if (req.session && !req.session.initialized) {
    req.session.destroy(err => {
      if (err) console.error('Session destruction error:', err);
      next();
    });
    return;
  }
  next();
});

// Check if we're in development or production
const isDev = process.env.NODE_ENV !== 'production';

// Log only important session events in development
if (isDev) {
  console.log("✅ Running in development mode");
}

// Apply session middleware
app.use((req, res, next) => {
  // Skip session for OPTIONS requests (preflight)
  if (req.method === 'OPTIONS') {
    return next();
  }
  
  // Skip logging for health check endpoints
  const isHealthCheck = req.path.includes('/health') || req.path.includes('/favicon');
  
  // Store original end method to intercept responses
  const originalEnd = res.end;
  
  if (isDev && !isHealthCheck) {
    const reqId = Math.random().toString(36).substring(2, 8);
    console.log(`\n🔄 ${reqId} | ${req.method} ${req.path}`);
    
    // Override end method to log response status
    res.end = function(...args) {
      console.log(`✅ ${reqId} | Status: ${res.statusCode}`);
      return originalEnd.apply(this, args);
    };
  }
  
  sessionMiddleware(req, res, next);
});

// Store original cookie function to avoid recursion
const originalCookie = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(app.response), 'cookie').value;

// Override cookie method to set appropriate cookie settings
Object.defineProperty(app.response, 'cookie', {
  value: function(name, value, options) {
    // Get request headers from the request object
    const req = this.req;
    
    // Default cookie options
    const cookieOptions = {
      ...options,
      path: '/'
    };
    
    // Determine if we're in production
    const isProd = process.env.NODE_ENV === 'production';
    
    // Set secure and sameSite for all cookies in production
    if (isProd) {
      cookieOptions.secure = true;
      cookieOptions.sameSite = 'none';
      // Set domain to allow cross-site cookies if in production
      // This helps with Netlify to Railway communication
      if (req.headers.origin && req.headers.origin.includes('netlify.app')) {
        // Don't set domain for cross-origin cookies, just ensure SameSite is none
        console.log(`Setting cross-origin cookie for origin: ${req.headers.origin}`);
      }
    } else if (req.headers.origin && (req.headers.origin.includes('localhost') || req.headers.origin.includes('127.0.0.1'))) {
      // Local development settings
      cookieOptions.secure = false;
      cookieOptions.sameSite = 'lax';
    }
    
    // Log cookie settings for debugging
    console.log(`🍪 Setting cookie ${name} (SameSite=${cookieOptions.sameSite}, Secure=${cookieOptions.secure})`);
    
    return originalCookie.call(this, name, value, cookieOptions);
  },
  configurable: true,
  writable: true
});

// Add connection cleanup on server close
process.on('SIGTERM', () => {
  if (sessionStore && sessionStore.pool) {
    sessionStore.pool.end();
    console.log('MySQL connection pool closed');
  }
});

// Session cleanup routine
async function cleanupExpiredSessions() {
  try {
    // Delete any sessions that have expired
    const [deleteResult] = await db.query(
      `DELETE FROM sessions WHERE expires_at < NOW() OR is_active = FALSE`
    );
    
    if (deleteResult.affectedRows > 0) {
      console.log(`🧹 Cleaned up ${deleteResult.affectedRows} expired/inactive sessions`);
    }
    
    // Check for duplicate active sessions for the same user (keep only the newest)
    const [duplicateUsers] = await db.query(`
      SELECT user_id, role, COUNT(*) as session_count
      FROM sessions 
      WHERE is_active = TRUE
      GROUP BY user_id, role
      HAVING COUNT(*) > 1
    `);
    
    for (const user of duplicateUsers) {
      console.log(`⚠️ Found ${user.session_count} duplicate sessions for user ${user.user_id} (${user.role})`);
      
      // Get all sessions for this user, ordered by created_at
      const [userSessions] = await db.query(`
        SELECT session_id, created_at
        FROM sessions
        WHERE user_id = ? AND role = ? AND is_active = TRUE
        ORDER BY created_at DESC
      `, [user.user_id, user.role]);
      
      // Keep only the newest session
      if (userSessions.length > 1) {
        const keepSessionId = userSessions[0].session_id;
        const sessionsToInvalidate = userSessions.slice(1).map(s => s.session_id);
        
        console.log(`Keeping session ${keepSessionId}, invalidating ${sessionsToInvalidate.length} sessions`);
        
        // Invalidate all but the newest session
        await db.query(`
          UPDATE sessions
          SET is_active = FALSE, expires_at = NOW()
          WHERE session_id IN (?)
        `, [sessionsToInvalidate]);
      }
    }
    
    // Count remaining sessions
    const [countResult] = await db.query(
      `SELECT COUNT(*) AS total FROM sessions WHERE is_active = TRUE`
    );
    
    if (countResult[0]?.total > 0) {
      console.log(`ℹ️ Current active sessions: ${countResult[0].total}`);
    }
  } catch (error) {
    console.error('❌ Error cleaning up sessions:', error);
  }
  
  // Schedule next cleanup
  setTimeout(cleanupExpiredSessions, 30 * 60 * 1000); // Every 30 minutes
}

// Add function to clean up duplicate sessions on startup
async function cleanupDuplicateSessions() {
  try {
    console.log("🧹 Starting cleanup of duplicate sessions...");
    
    // Find all users with multiple active sessions
    const [users] = await db.query(`
      SELECT user_id, role, COUNT(*) as session_count 
      FROM sessions 
      WHERE is_active = TRUE 
      GROUP BY user_id, role 
      HAVING COUNT(*) > 1
    `);
    
    console.log(`Found ${users.length} users with multiple active sessions`);
    
    for (const user of users) {
      console.log(`User ${user.user_id} (${user.role}) has ${user.session_count} active sessions`);
      
      // Get all sessions for this user
      const [sessions] = await db.query(`
        SELECT session_id, created_at
        FROM sessions
        WHERE user_id = ? AND role = ? AND is_active = TRUE
        ORDER BY created_at DESC
      `, [user.user_id, user.role]);
      
      if (sessions.length > 1) {
        // Keep only the newest session
        const keepSessionId = sessions[0].session_id;
        const sessionsToInvalidate = sessions.slice(1).map(s => s.session_id);
        
        console.log(`Keeping newest session ${keepSessionId}, invalidating ${sessionsToInvalidate.length} older sessions`);
        
        if (sessionsToInvalidate.length > 0) {
          await db.query(`
            UPDATE sessions
            SET is_active = FALSE, expires_at = NOW()
            WHERE session_id IN (?)
          `, [sessionsToInvalidate]);
          
          console.log(`Successfully invalidated older sessions for user ${user.user_id}`);
        }
      }
    }
    
    console.log("✅ Duplicate session cleanup completed");
  } catch (error) {
    console.error("❌ Error cleaning up duplicate sessions:", error);
  }
}

// Run cleanup on server startup
console.log("Running session cleanup on startup...");
cleanupExpiredSessions().then(() => {
  cleanupDuplicateSessions().then(() => {
    console.log("Initial session cleanup completed");
  });
});

// Add function to completely reset all sessions for a user
async function resetAllSessionsForUser(userId, role) {
  try {
    const [result] = await db.query(`
      UPDATE sessions
      SET is_active = FALSE, expires_at = NOW()
      WHERE user_id = ? AND role = ?
    `, [userId, role]);
    
    return { 
      success: true, 
      invalidatedCount: result.affectedRows,
      message: `Invalidated ${result.affectedRows} sessions for user ${userId} (${role})`
    };
  } catch (error) {
    console.error('Error resetting sessions:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

// Add an endpoint to force reset all sessions for debug purposes
app.post('/auth/reset-all-sessions', async (req, res) => {
  const { userId, role, secretKey } = req.body;
  
  // Basic protection to prevent unauthorized resets
  if (secretKey !== process.env.ADMIN_SECRET) {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized: Invalid secret key'
    });
  }
  
  if (!userId || !role) {
    return res.status(400).json({
      success: false,
      message: 'Missing required parameters: userId and role'
    });
  }
  
  try {
    const result = await resetAllSessionsForUser(userId, role);
    res.json(result);
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
});

// API routes
app.use("/auth", loginSystem);  
app.use("/auth", attendanceSystem);
app.use("/auth", qrSystem);
// Add teacher routes with proper path
app.use("/teacher", qrSystem);

// Around the CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Content-Length', 'X-Session-Id']
}));

// Forward /attend route to /auth/attend
app.get('/attend', (req, res) => {
  console.log("⏩ Forwarding /attend to /auth/attend with params:", req.query);
  const redirectUrl = `/auth/attend?${new URLSearchParams(req.query).toString()}`;
  console.log("⏩ Redirect URL:", redirectUrl);
  res.redirect(redirectUrl);
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date(),
    dbConnected: !!db.connection,
    sessionID: req.sessionID
  });
});

// Debug cookie settings endpoint
app.get('/auth/debug-cookies', (req, res) => {
  // Log all cookies from the request
  console.log('Cookies received:', req.cookies);
  console.log('Cookie header:', req.headers.cookie);
  console.log('Origin:', req.headers.origin);
  console.log('Host:', req.headers.host);
  
  // Set a test cookie with current settings
  const testCookieName = 'debug_test_cookie';
  const isCrossDomainLocalhost = 
    (req.headers.origin && req.headers.origin.includes('127.0.0.1')) && 
    (req.headers.host && req.headers.host.includes('localhost')) ||
    (req.headers.origin && req.headers.origin.includes('localhost')) && 
    (req.headers.host && req.headers.host.includes('127.0.0.1'));
    
  const isLocalDev = process.env.NODE_ENV !== 'production';
  
  // Set a test cookie that matches our current environment settings
  if (isCrossDomainLocalhost) {
    res.cookie(testCookieName, 'cross_domain_test', {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      path: '/',
      maxAge: 60000 // 1 minute
    });
  } else if (isLocalDev) {
    res.cookie(testCookieName, 'local_dev_test', {
      httpOnly: false, // Make visible to JS for debugging
      secure: false,
      sameSite: 'lax',
      path: '/',
      maxAge: 60000 // 1 minute
    });
  }
  
  res.json({
    receivedCookies: req.cookies,
    cookieHeader: req.headers.cookie,
    sessionID: req.sessionID,
    currentSettings: {
      origin: req.headers.origin,
      host: req.headers.host,
      isCrossDomainLocalhost,
      isLocalDev,
      cookieSettings: isCrossDomainLocalhost ? {
        secure: true,
        sameSite: 'none'
      } : {
        secure: false,
        sameSite: 'lax'
      }
    }
  });
});

// Debug headers endpoint for troubleshooting CORS issues
app.get('/auth/debug-headers', (req, res) => {
  // Get all headers from the request
  const requestHeaders = req.headers;
  
  // Return a response with all the useful debugging info
  res.json({
    success: true,
    headers: {
      origin: req.headers.origin,
      referer: req.headers.referer,
      host: req.headers.host,
      userAgent: req.headers['user-agent'],
      contentType: req.headers['content-type'],
      accept: req.headers.accept,
      authorization: req.headers.authorization ? 'present' : 'not present',
      cookieHeader: req.headers.cookie
    },
    cookies: req.cookies,
    sessionID: req.sessionID,
    session: req.session ? {
      userId: req.session.userId,
      role: req.session.role,
      isAuthenticated: !!req.session.userId
    } : 'No session',
    env: {
      nodeEnv: process.env.NODE_ENV || 'not set'
    }
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Server error:', err.message);
  res.status(500).json({ error: 'Internal Server Error' });
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
}).on('error', (err) => {
  console.error('Server failed to start:', err);
  process.exit(1);
});