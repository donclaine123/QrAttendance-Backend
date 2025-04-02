/**
 * Session cleanup script to address multiple session issues
 * 
 * This script will:
 * 1. Find duplicate active sessions for the same user
 * 2. Keep only the most recent session active
 * 3. Mark all others as inactive
 * 4. Provide a detailed report of actions taken
 */

const db = require("./db");

async function cleanupDuplicateSessions() {
  console.log("\n🧹 Starting session cleanup script...");
  
  try {
    // First, get all active sessions grouped by user
    const [activeSessions] = await db.query(`
      SELECT user_id, role, COUNT(*) as session_count, 
             GROUP_CONCAT(session_id) as session_ids,
             GROUP_CONCAT(last_activity) as activities,
             GROUP_CONCAT(created_at) as created_dates
      FROM sessions
      WHERE is_active = TRUE
      GROUP BY user_id, role
      HAVING COUNT(*) > 1
      ORDER BY user_id
    `);
    
    console.log(`\nFound ${activeSessions.length} users with multiple active sessions`);
    
    // Process each user with multiple sessions
    for (const userSessions of activeSessions) {
      const userId = userSessions.user_id;
      const role = userSessions.role;
      const sessionCount = userSessions.session_count;
      
      console.log(`\n👤 User ID: ${userId} (${role}) has ${sessionCount} active sessions`);
      
      // Get all sessions for this user, ordered by last activity (most recent first)
      const [sessions] = await db.query(`
        SELECT session_id, data, last_activity, created_at
        FROM sessions
        WHERE user_id = ? AND role = ? AND is_active = TRUE
        ORDER BY last_activity DESC
      `, [userId, role]);
      
      if (sessions.length > 0) {
        // Keep the most recent session active
        const mostRecentSession = sessions[0];
        const sessionsToInvalidate = sessions.slice(1);
        
        console.log(`✅ Keeping most recent session: ${mostRecentSession.session_id.substring(0, 8)} (last active: ${mostRecentSession.last_activity})`);
        
        if (sessionsToInvalidate.length > 0) {
          const sessionIds = sessionsToInvalidate.map(s => s.session_id);
          
          console.log(`❌ Invalidating ${sessionsToInvalidate.length} older sessions:`);
          sessionsToInvalidate.forEach(s => {
            console.log(`   - ${s.session_id.substring(0, 8)} (last active: ${s.last_activity})`);
          });
          
          // Mark older sessions as inactive
          const [result] = await db.query(`
            UPDATE sessions
            SET is_active = FALSE, 
                expires_at = NOW(),
                data = JSON_SET(data, '$.cleanup', 'Marked inactive by cleanup script')
            WHERE session_id IN (?)
          `, [sessionIds]);
          
          console.log(`✅ Successfully invalidated ${result.affectedRows} sessions`);
        }
      }
    }
    
    console.log("\n🧮 Cleanup Summary:");
    
    // Count remaining active sessions
    const [activeCount] = await db.query(`
      SELECT COUNT(*) as count FROM sessions WHERE is_active = TRUE
    `);
    
    console.log(`   - Active sessions remaining: ${activeCount[0].count}`);
    
    // Count inactive sessions
    const [inactiveCount] = await db.query(`
      SELECT COUNT(*) as count FROM sessions WHERE is_active = FALSE
    `);
    
    console.log(`   - Inactive sessions: ${inactiveCount[0].count}`);
    
    // Count sessions by user
    const [userCounts] = await db.query(`
      SELECT user_id, role, COUNT(*) as count 
      FROM sessions 
      WHERE is_active = TRUE 
      GROUP BY user_id, role
    `);
    
    console.log("\n👥 Active sessions per user:");
    userCounts.forEach(uc => {
      console.log(`   - User ${uc.user_id} (${uc.role}): ${uc.count} active sessions`);
    });
    
    console.log("\n✅ Session cleanup completed successfully");
  } catch (error) {
    console.error("❌ Error during session cleanup:", error);
  } finally {
    // Close the database connection
    if (db.end) {
      await db.end();
      console.log("Database connection closed");
    }
  }
}

// Run the cleanup function
cleanupDuplicateSessions(); 