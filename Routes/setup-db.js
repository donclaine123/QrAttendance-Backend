// Database setup script for sessions table
const db = require('../db');

async function setupSessionsTable() {
  try {
    console.log('Checking if sessions table exists...');
    
    // Check if the 'data' column exists
    const [dataColumnCheck] = await db.query(`
      SELECT COLUMN_NAME 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = 'sessions' 
      AND COLUMN_NAME = 'data'
    `);
    
    if (dataColumnCheck.length === 0) {
      console.log('Adding data column to sessions table...');
      await db.query(`
        ALTER TABLE sessions 
        ADD COLUMN data TEXT NOT NULL AFTER session_id
      `);
      console.log('✅ Added data column');
    } else {
      console.log('data column already exists');
    }
    
    // Check if the 'is_active' column exists
    const [isActiveColumnCheck] = await db.query(`
      SELECT COLUMN_NAME 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = 'sessions' 
      AND COLUMN_NAME = 'is_active'
    `);
    
    if (isActiveColumnCheck.length === 0) {
      console.log('Adding is_active column to sessions table...');
      await db.query(`
        ALTER TABLE sessions 
        ADD COLUMN is_active BOOLEAN DEFAULT TRUE AFTER role
      `);
      console.log('✅ Added is_active column');
    } else {
      console.log('is_active column already exists');
    }
    
    console.log('✅ Sessions table updated successfully');
    
  } catch (error) {
    console.error('❌ Error updating sessions table:', error);
  } finally {
    process.exit(0);
  }
}

// Run the setup
setupSessionsTable(); 