// Script to fix the sessions table constraints
const db = require('../db');

async function fixSessionsTable() {
  let conn;
  try {
    conn = await db.getConnection();
    console.log("Connected to database");
    
    // Step 1: Get information about current foreign keys
    console.log("Checking foreign key constraints...");
    const [fkResults] = await conn.query(`
      SELECT CONSTRAINT_NAME
      FROM information_schema.TABLE_CONSTRAINTS
      WHERE TABLE_NAME = 'sessions' 
      AND CONSTRAINT_TYPE = 'FOREIGN KEY'
      AND TABLE_SCHEMA = DATABASE();
    `);
    
    console.log("Found foreign key constraints:", fkResults);
    
    // Step 2: Drop the foreign key constraints
    if (fkResults.length > 0) {
      for (const fk of fkResults) {
        console.log(`Dropping foreign key: ${fk.CONSTRAINT_NAME}`);
        await conn.query(`ALTER TABLE sessions DROP FOREIGN KEY ${fk.CONSTRAINT_NAME}`);
      }
      console.log("✅ Dropped all foreign key constraints");
    } else {
      console.log("No foreign key constraints found");
    }
    
    // Step 3: Modify the user_id and role columns to allow NULL values
    console.log("Modifying columns to allow NULL values...");
    await conn.query(`
      ALTER TABLE sessions 
      MODIFY COLUMN user_id INT NULL,
      MODIFY COLUMN role VARCHAR(20) NULL
    `);
    console.log("✅ Modified columns to allow NULL values");
    
    console.log("✅ Sessions table fixed successfully!");
  } catch (error) {
    console.error("❌ Error fixing sessions table:", error);
  } finally {
    if (conn) conn.release();
    process.exit(0);
  }
}

// Run the function
fixSessionsTable(); 