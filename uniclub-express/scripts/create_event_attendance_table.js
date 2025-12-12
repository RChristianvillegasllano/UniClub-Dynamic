// Script to create event_attendance table
import "dotenv/config";
import mysql from "mysql2/promise";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function createEventAttendanceTable() {
  let connection;
  
  try {
    // Create connection
    const connectionConfig = {
      host: process.env.MAIN_DB_HOST || process.env.DB_HOST || 'localhost',
      user: process.env.MAIN_DB_USER || process.env.DB_USER || 'root',
      password: process.env.MAIN_DB_PASSWORD || process.env.DB_PASSWORD || '',
      database: process.env.MAIN_DB_NAME || process.env.DB_NAME || 'Uniclub',
      port: process.env.MAIN_DB_PORT || process.env.DB_PORT || 3306,
      multipleStatements: true
    };

    connection = await mysql.createConnection(connectionConfig);
    console.log("✅ Connected to database");

    // Read and execute SQL file
    const sqlPath = join(__dirname, '../sql/create_event_attendance_table.sql');
    const sql = readFileSync(sqlPath, 'utf8');
    
    // Remove USE statement if present (we'll use the connection database)
    const cleanedSql = sql.replace(/USE\s+\w+;?/gi, '');
    
    await connection.query(cleanedSql);
    console.log("✅ event_attendance table created successfully");
    
    // Verify the table was created
    const [tables] = await connection.query(
      "SHOW TABLES LIKE 'event_attendance'"
    );
    
    if (tables.length > 0) {
      console.log("✅ Verification: event_attendance table exists");
      
      // Show table structure
      const [columns] = await connection.query(
        "DESCRIBE event_attendance"
      );
      console.log("\n📋 Table structure:");
      console.table(columns);
    } else {
      console.log("⚠️  Warning: Table verification failed");
    }
    
  } catch (error) {
    console.error("❌ Error creating event_attendance table:", error.message);
    if (error.code === 'ER_TABLE_EXISTS_ERROR' || error.errno === 1050) {
      console.log("ℹ️  Table already exists. This is okay.");
    } else {
      process.exit(1);
    }
  } finally {
    if (connection) {
      await connection.end();
      console.log("✅ Database connection closed");
    }
  }
}

createEventAttendanceTable();








