// createAdmin.js
import bcrypt from "bcryptjs";
import pool from "./config/db.js";
import dotenv from "dotenv";
dotenv.config();

const createAdmin = async () => {
  try {
    const username = "admin";
    const password = "admin123";
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO admins (username, password) VALUES ($1, $2) RETURNING *",
      [username, hashedPassword]
    );

    console.log("✅ Admin created:", result.rows[0]);
    process.exit();
  } catch (err) {
    console.error("❌ Error creating admin:", err);
    process.exit(1);
  }
};

createAdmin();
