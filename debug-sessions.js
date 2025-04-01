require("dotenv").config();
const db = require("./db");

// Query to check active sessions
async function checkSessions() {
  try {
    console.log("Checking active sessions in the database...");
    
    // Get a connection from the pool
    const conn = await db.getConnection();
    
    // Check database connection
    const [connectionTest] = await conn.query("SELECT 1 + 1 AS result");
    console.log("Database connection test:", connectionTest[0].result);
    
    // Query active sessions
    const [sessions] = await conn.query(
      `SELECT 
        session_id, 
        user_id, 
        role, 
        data,
        created_at,
        expires_at,
        is_active,
        expires_at > NOW() as is_valid
       FROM sessions 
       WHERE expires_at > NOW() AND is_active = TRUE
       ORDER BY created_at DESC
       LIMIT 10`
    );
    
    console.log("Active sessions count:", sessions.length);
    
    // Display each session
    sessions.forEach((session, index) => {
      console.log(`\n--- Session ${index + 1} ---`);
      console.log("Session ID:", session.session_id);
      console.log("User ID:", session.user_id);
      console.log("Role:", session.role);
      console.log("Created:", session.created_at);
      console.log("Expires:", session.expires_at);
      console.log("Is Valid:", session.is_valid ? "Yes" : "No");
      
      // Parse the data JSON if available
      if (session.data) {
        try {
          const data = JSON.parse(session.data);
          console.log("Session Data:", JSON.stringify(data, null, 2));
        } catch (e) {
          console.log("Could not parse session data:", session.data);
        }
      }
    });
    
    // Count all sessions regardless of expiration
    const [totalSessions] = await conn.query(
      `SELECT COUNT(*) as count FROM sessions`
    );
    console.log(`\nTotal sessions in database: ${totalSessions[0].count}`);
    
    // Release the connection
    conn.release();
    
  } catch (error) {
    console.error("Error checking sessions:", error);
  } finally {
    // Close the pool when done
    db.end();
  }
}

// Run the check
checkSessions(); 