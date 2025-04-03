require("dotenv").config(); // Load environment variables from .env file
const mysql = require("mysql2/promise");
const fs = require('fs');

// Create a connection pool with better error handling
const pool = mysql.createPool({
  host: process.env.DB_HOST || "ballast.proxy.rlwy.net",
  port: process.env.DB_PORT || 41598,
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 10000, // 10 seconds
  enableKeepAlive: true,
  keepAliveInitialDelay: 0
});

// Test the connection with better error handling
const testConnection = async () => {
  let conn;
  try {
    conn = await pool.getConnection();
    const [rows] = await conn.query("SELECT 1 + 1 AS result");
    console.log("✓ Database connection successful. Result:", rows[0].result);
  } catch (error) {
    console.error("✗ Database connection failed:", error.message);
    if (error.code === 'PROTOCOL_CONNECTION_LOST') {
      console.error("Connection was lost. Please check your database credentials and connection.");
    } else if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      console.error("Access denied. Please check your username and password.");
    } else if (error.code === 'ECONNREFUSED') {
      console.error("Connection refused. Please check if the database server is running.");
    }
    throw error;
  } finally {
    if (conn) conn.release();
  }
};

// Test connection immediately
testConnection().catch(err => {
  console.error("Failed to establish database connection:", err);
  process.exit(1);
});

// Function to enforce one active session per user
async function enforceUniqueActiveSessions() {
  try {
    console.log('Checking database for single active session enforcement...');
    
    // First check if we need to set up the unique constraint enforcement
    const [tables] = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_name = 'active_sessions_view'
    `);
    
    if (tables.length === 0) {
      console.log('Setting up active session enforcement...');
      
      // Create view for active sessions - this will be used for lookup
      await pool.query(`
        CREATE OR REPLACE VIEW active_sessions_view AS
        SELECT user_id, role, MAX(last_activity) as latest_activity, COUNT(*) as session_count
        FROM sessions
        WHERE is_active = TRUE
        GROUP BY user_id, role
      `);
      
      // Create stored procedure to enforce one active session per user
      await pool.query(`
        CREATE PROCEDURE IF NOT EXISTS enforce_one_active_session(IN p_user_id INT, IN p_role VARCHAR(20))
        BEGIN
          DECLARE latest_session_id VARCHAR(128);
          
          -- Find the most recently active session
          SELECT session_id INTO latest_session_id
          FROM sessions
          WHERE user_id = p_user_id AND role = p_role AND is_active = TRUE
          ORDER BY last_activity DESC, created_at DESC
          LIMIT 1;
          
          -- Deactivate all other sessions
          IF latest_session_id IS NOT NULL THEN
            UPDATE sessions
            SET is_active = FALSE, expires_at = NOW()
            WHERE user_id = p_user_id AND role = p_role AND session_id != latest_session_id AND is_active = TRUE;
          END IF;
        END
      `);
      
      // Create trigger to automatically enforce one active session when updating sessions
      await pool.query(`
        CREATE TRIGGER IF NOT EXISTS enforce_active_sessions_after_insert
        AFTER INSERT ON sessions
        FOR EACH ROW
        BEGIN
          IF NEW.is_active = TRUE THEN
            CALL enforce_one_active_session(NEW.user_id, NEW.role);
          END IF;
        END
      `);
      
      await pool.query(`
        CREATE TRIGGER IF NOT EXISTS enforce_active_sessions_after_update
        AFTER UPDATE ON sessions
        FOR EACH ROW
        BEGIN
          IF NEW.is_active = TRUE AND (OLD.is_active = FALSE OR OLD.is_active IS NULL) THEN
            CALL enforce_one_active_session(NEW.user_id, NEW.role);
          END IF;
        END
      `);
      
      console.log('✅ Session enforcement setup complete');
      
      // Run initial cleanup of existing duplicates
      const [duplicates] = await pool.query(`
        SELECT user_id, role FROM active_sessions_view
        WHERE session_count > 1
      `);
      
      if (duplicates.length > 0) {
        console.log(`Found ${duplicates.length} users with duplicate active sessions. Running cleanup...`);
        
        for (const user of duplicates) {
          await pool.query(`CALL enforce_one_active_session(?, ?)`, [user.user_id, user.role]);
          console.log(`- Enforced single active session for user ${user.user_id} (${user.role})`);
        }
      }
    } else {
      console.log('✅ Single active session enforcement already configured');
    }
    
    return true;
  } catch (error) {
    console.error('❌ Error setting up session enforcement:', error);
    return false;
  }
}

// Run the test connection when the module is loaded
testConnection();

// Export pool for use in other modules
module.exports = pool;
// Also export the query function directly for convenience
module.exports.query = function() {
  return pool.query.apply(pool, arguments);
};
module.exports.testConnection = testConnection;
module.exports.enforceUniqueActiveSessions = enforceUniqueActiveSessions;