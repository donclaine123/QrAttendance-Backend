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

// Configure CORS with production settings
app.use(
  cors({
    origin: [
      "http://localhost:5500", 
      "http://localhost:3000", 
      "http://127.0.0.1:5500",
      "https://splendorous-paprenjak-09a988.netlify.app"
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With", "Accept", "Cache-Control"],
    exposedHeaders: ["Set-Cookie"],
    preflightContinue: false
  })
);

// Add CORS headers directly for more compatibility
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && (
    origin.includes('localhost') || 
    origin.includes('127.0.0.1') || 
    origin === 'https://splendorous-paprenjak-09a988.netlify.app'
  )) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, Cache-Control');
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
    secure: !isDev, // Enable secure in production
    sameSite: isDev ? 'lax' : 'none', // Proper SameSite for cross-origin in production
    maxAge: parseInt(process.env.SESSION_LIFETIME) || 24 * 60 * 60 * 1000, // Use env variable or default to 24 hours
    path: '/'
  },
  name: 'qr_attendance_sid' // Consistent cookie name
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
    
    // Handle cross-origin cookies
    if (req.headers.origin) {
      const origin = req.headers.origin;
      
      // Handle cross-origin cases
      if (origin && origin !== `${req.protocol}://${req.headers.host}`) {
        // Check if we're in development mode - localhost special case
        if (isDev && (origin.includes('localhost') || origin.includes('127.0.0.1'))) {
          cookieOptions.sameSite = 'lax';
          cookieOptions.secure = false;
        } else {
          cookieOptions.sameSite = 'none';
          cookieOptions.secure = true;
        }
      }
    }
    
    // Log only important cookie events in development
    if (isDev && name === 'qr_attendance_sid' && !value.includes('health')) {
      console.log(`🍪 Setting cookie: ${name.substring(0, 15)}... (SameSite=${cookieOptions.sameSite}, Secure=${cookieOptions.secure})`);
    }
    
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

// API routes
app.use("/auth", loginSystem);  
app.use("/auth", attendanceSystem);
app.use("/auth", qrSystem);
// Add teacher routes with proper path
app.use("/teacher", qrSystem);

// Security headers
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Access-Control-Allow-Origin': req.headers.origin || '*',
    'Access-Control-Allow-Credentials': 'true'
  });
  next();
});

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

// Error handling
app.use((err, req, res, next) => {
  console.error('Server error:', err.message);
  res.status(500).json({ error: 'Internal Server Error' });
});

// Start server with proper error handling
const server = app.listen(PORT, () => {
  console.log(`
🚀 Server is running in ${process.env.NODE_ENV} mode
📡 Listening on port ${PORT}
🔗 Frontend URL: ${process.env.FRONTEND_URL}
🌐 API URL: ${process.env.API_URL}
  `);
});

// Handle server errors
server.on('error', (error) => {
  if (error.syscall !== 'listen') {
    throw error;
  }

  const bind = typeof PORT === 'string'
    ? 'Pipe ' + PORT
    : 'Port ' + PORT;

  // Handle specific listen errors with friendly messages
  switch (error.code) {
    case 'EACCES':
      console.error(bind + ' requires elevated privileges');
      process.exit(1);
      break;
    case 'EADDRINUSE':
      console.error(bind + ' is already in use');
      process.exit(1);
      break;
    default:
      throw error;
  }
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('Unhandled Promise Rejection:', err);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  // Give the server time to finish current requests
  server.close(() => {
    process.exit(1);
  });
});