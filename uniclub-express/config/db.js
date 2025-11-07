// config/db.js
import pkg from "pg";
import dotenv from "dotenv";
const { Pool } = pkg;

// Load environment variables
dotenv.config();

// Create connection pool using Neon.tech connection string
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // Required for Neon
  },
});

pool
  .connect()
  .then(() => console.log("✅ Connected to Neon.tech PostgreSQL"))
  .catch((err) => console.error("❌ Database connection error:", err.message));

export default pool;
