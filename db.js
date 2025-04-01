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

// Export the pool for use in other files
module.exports = pool;