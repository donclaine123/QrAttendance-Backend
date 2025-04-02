const mysql = require('mysql2/promise');
const expressSession = require('express-session');
const Store = expressSession.Store;
const EventEmitter = require('events');
const db = require('../db'); // Import the existing pool

class CustomMySQLStore extends Store {
  constructor(options = {}) {
    super(options);
    
    // Use the existing pool instead of creating a new one
    this.pool = db;
    
    // Set max listeners to avoid warnings
    if (this.pool instanceof EventEmitter) {
      this.pool.setMaxListeners(20);
    }
    
    this.testConnection();
  }

  async testConnection() {
    let conn;
    try {
      conn = await this.pool.getConnection();
      const [rows] = await conn.query('SELECT 1 + 1 AS result');
      console.log('✓ Session Store connected to Railway MySQL. Result:', rows[0].result);
    } catch (err) {
      console.error('✗ Session Store connection failed:', err.message);
      // Don't throw error, just log it
      console.error('Session store will retry connections as needed');
    } finally {
      if (conn) conn.release();
    }
  }

  async get(sid, callback) {
    // Only log in development mode and exclude health check sessions
    const shouldLog = process.env.NODE_ENV !== 'production' && 
                     !sid.includes('health') && 
                     sid !== 'no-session';
                     
    if (shouldLog) {
      console.log(`GET session ${sid.substring(0, 8)}...`);
    }
    
    let conn;
    try {
      conn = await this.pool.getConnection();
      const [rows] = await conn.query(
        'SELECT data FROM sessions WHERE session_id = ? AND expires_at > NOW()',
        [sid]
      );
      
      // Reduce logging noise
      if (rows[0] && shouldLog) {
        console.log("✅ Session found in store");
      } else if (shouldLog && process.env.DEBUG) {
        // Only show detailed logs in debug mode
        console.log("❌ Session not found in store");
      }
      
      callback(null, rows[0] ? JSON.parse(rows[0].data) : null);
    } catch (err) {
      console.error("❌ Error getting session:", err.message);
      callback(err);
    } finally {
      if (conn) conn.release();
    }
  }

  async set(sid, session, callback) {
    // Skip storing unauthenticated sessions to reduce database load
    if (!session.userId || sid === 'no-session') {
      // Only log in debug mode
      if (process.env.DEBUG) {
        console.log("⏭️ Skipping unauthenticated session store");
      }
      return callback(null);
    }
    
    // Log all session operations in production during debugging
    const shouldLog = true;
    
    if (shouldLog) {
      console.log(`💾 Storing session ${sid.substring(0, 8)}... for user ${session.userId} (${session.role})`);
    }
    
    let conn;
    try {
      conn = await this.pool.getConnection();
      
      // Start a transaction for atomicity
      await conn.beginTransaction();
      const expiresAt = new Date(Date.now() + session.cookie.maxAge);

      // For non-authenticated sessions, skip storage entirely
      if (!session.userId || !session.role || session.userId < 0) {
        // Don't store non-authenticated sessions
        await conn.commit();
        callback(null);
        return;
      }

      // Check if this exact session already exists to avoid duplicate work
      const [existingSession] = await conn.query(
        `SELECT session_id FROM sessions 
         WHERE session_id = ? AND user_id = ?`,
        [sid, session.userId]
      );
      
      // If the session already exists for this user, just update it
      if (existingSession.length > 0) {
        if (shouldLog) {
          console.log(`⚡ Updating existing session: ${sid.substring(0, 8)}`);
        }
        
        await conn.query(
          `UPDATE sessions 
           SET data = ?, expires_at = ?, is_active = TRUE, last_activity = NOW()
           WHERE session_id = ?`,
          [
            JSON.stringify(session),
            expiresAt,
            sid
          ]
        );
        
        // Commit transaction
        await conn.commit();
        if (shouldLog) {
          console.log("✅ Session updated");
        }
        callback(null);
        return;
      }

      // Count total active sessions for this user
      const [existingActiveSessions] = await conn.query(
        `SELECT session_id FROM sessions 
         WHERE user_id = ? AND role = ? AND is_active = TRUE`,
        [session.userId, session.role]
      );
      
      if (shouldLog) {
        console.log(`Found ${existingActiveSessions.length} existing active sessions for user ${session.userId}`);
      }

      // Invalidate all previous sessions for this user in a single atomic operation
      if (existingActiveSessions.length > 0) {
        console.log(`⚠️ IMPORTANT: Invalidating ${existingActiveSessions.length} previous sessions for user ${session.userId}`);
        
        // Log session IDs for debugging
        console.log("Sessions being invalidated:", 
          existingActiveSessions.map(s => s.session_id.substring(0, 8)).join(', ')
        );
        
        await conn.query(
          `UPDATE sessions 
           SET expires_at = NOW(), is_active = FALSE, 
           data = JSON_SET(data, '$.invalidated', true, '$.invalidatedAt', ?)
           WHERE user_id = ? AND role = ? AND is_active = TRUE`,
          [new Date().toISOString(), session.userId, session.role]
        );
      }
      
      // Create the new session
      if (shouldLog) {
        console.log(`Creating new session ${sid.substring(0, 8)} for user ${session.userId}`);
      }
      
      await conn.query(
        `INSERT INTO sessions (session_id, data, expires_at, user_id, role, is_active)
         VALUES (?, ?, ?, ?, ?, TRUE)
         ON DUPLICATE KEY UPDATE
           data = VALUES(data),
           expires_at = VALUES(expires_at),
           is_active = TRUE`,
        [
          sid,
          JSON.stringify(session),
          expiresAt,
          session.userId,
          session.role
        ]
      );
      
      // Commit the transaction
      await conn.commit();
      if (shouldLog) {
        console.log("✅ Session saved");
      }
      callback(null);
    } catch (err) {
      // Rollback transaction on error
      if (conn) {
        try {
          await conn.rollback();
          console.log("❌ Transaction rolled back due to error");
        } catch (rollbackErr) {
          console.error("❌ Error rolling back transaction:", rollbackErr);
        }
      }
      console.error('❌ Session store set error:', err);
      callback(err);
    } finally {
      if (conn) conn.release();
    }
  }

  async destroy(sid, callback) {
    // Only log if not a health check session
    const shouldLog = !sid.includes('health');
    
    if (shouldLog) {
      console.log(`🗑️ Destroying session ${sid.substring(0, 8)}...`);
    }
    
    let conn;
    try {
      conn = await this.pool.getConnection();
      await conn.query('DELETE FROM sessions WHERE session_id = ?', [sid]);
      
      if (shouldLog && process.env.DEBUG) {
        console.log("✅ Session destroyed");
      }
      callback(null);
    } catch (err) {
      console.error("❌ Error destroying session:", err.message);
      callback(err);
    } finally {
      if (conn) conn.release();
    }
  }

  async touch(sid, session, callback) {
    // Skip touching unauthenticated sessions
    if (!session.userId) {
      return callback(null);
    }
    
    // Only log in debug mode
    const shouldLog = process.env.DEBUG && !sid.includes('health');
    
    if (shouldLog) {
      console.log(`👆 Touching session ${sid.substring(0, 8)}...`);
    }
    
    let conn;
    try {
      conn = await this.pool.getConnection();
      const expiresAt = new Date(Date.now() + session.cookie.maxAge);
      await conn.query(
        'UPDATE sessions SET expires_at = ? WHERE session_id = ?',
        [expiresAt, sid]
      );
      
      if (shouldLog) {
        console.log("✅ Session expiry updated");
      }
      callback(null);
    } catch (err) {
      console.error("❌ Error touching session:", err.message);
      callback(err);
    } finally {
      if (conn) conn.release();
    }
  }
}

module.exports = CustomMySQLStore;