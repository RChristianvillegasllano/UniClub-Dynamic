// Script to create an admin account
// Usage: node scripts/createAdmin.js [username] [password]

import "dotenv/config";
import bcrypt from "bcrypt";
import { adminPool } from "../config/db.js";
import readline from "readline";

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function question(query) {
  return new Promise(resolve => rl.question(query, resolve));
}

async function createAdmin() {
  try {
    console.log("🔐 Admin Account Creation Script");
    console.log("================================\n");

    // Get username and password from command line args or prompt
    let username = process.argv[2];
    let password = process.argv[3];

    if (!username) {
      username = await question("Enter admin username: ");
    }

    if (!password) {
      password = await question("Enter admin password: ");
    }

    if (!username || !username.trim()) {
      console.error("❌ Error: Username is required");
      process.exit(1);
    }

    if (!password || password.length < 6) {
      console.error("❌ Error: Password must be at least 6 characters");
      process.exit(1);
    }

    // Check if admin already exists
    const existingAdmin = await adminPool.query(
      "SELECT id, username FROM admins WHERE username = ?",
      [username.trim()]
    );

    if (existingAdmin.rows.length > 0) {
      console.log(`\n⚠️  Admin with username "${username}" already exists!`);
      const overwrite = await question("Do you want to update the password? (y/n): ");
      
      if (overwrite.toLowerCase() !== 'y' && overwrite.toLowerCase() !== 'yes') {
        console.log("❌ Operation cancelled.");
        rl.close();
        process.exit(0);
      }

      // Update existing admin password
      const hashedPassword = await bcrypt.hash(password, 10);
      await adminPool.query(
        "UPDATE admins SET password = ? WHERE username = ?",
        [hashedPassword, username.trim()]
      );
      
      console.log(`\n✅ Successfully updated password for admin: ${username}`);
      console.log(`\n📋 Login Credentials:`);
      console.log(`   Username: ${username}`);
      console.log(`   Password: ${password}`);
      console.log(`\n⚠️  Please save these credentials securely!`);
    } else {
      // Create new admin
      const hashedPassword = await bcrypt.hash(password, 10);
      
      await adminPool.query(
        "INSERT INTO admins (username, password, created_at) VALUES (?, ?, NOW())",
        [username.trim(), hashedPassword]
      );

      console.log(`\n✅ Successfully created admin account!`);
      console.log(`\n📋 Login Credentials:`);
      console.log(`   Username: ${username}`);
      console.log(`   Password: ${password}`);
      console.log(`\n⚠️  Please save these credentials securely!`);
      console.log(`\n🔗 Login URL: /admin/login`);
    }

    rl.close();
    process.exit(0);
  } catch (error) {
    console.error("\n❌ Error creating admin account:", error.message);
    console.error(error);
    rl.close();
    process.exit(1);
  }
}

// Run the script
createAdmin();

