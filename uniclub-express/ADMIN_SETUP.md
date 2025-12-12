# Admin Account Setup Guide

This guide will help you create your first admin account to access the UniClub admin panel.

## Quick Start

### Option 1: Using npm (Easiest)

```bash
cd uniclub-express
npm run create-admin
```

### Option 2: Direct Node Command

```bash
cd uniclub-express
node scripts/createAdmin.js
```

### Option 3: With Arguments

```bash
cd uniclub-express
node scripts/createAdmin.js admin myPassword123
```

## What the Script Does

1. ✅ Connects to your database
2. ✅ Checks if an admin with that username already exists
3. ✅ Creates a new admin account (or updates password if exists)
4. ✅ Hashes the password securely using bcrypt
5. ✅ Displays your login credentials

## Example Output

```
🔐 Admin Account Creation Script
================================

Enter admin username: admin
Enter admin password: ********

✅ Successfully created admin account!

📋 Login Credentials:
   Username: admin
   Password: myPassword123

⚠️  Please save these credentials securely!

🔗 Login URL: /admin/login
```

## After Creating Admin Account

1. **Save your credentials** - Write them down in a secure location
2. **Login** - Go to `/admin/login` in your browser
3. **Change password** - Consider changing it after first login for security

## Default Admin Credentials (Example)

If you want to create a default admin, you can use:

```bash
node scripts/createAdmin.js admin admin123
```

⚠️ **Important:** Change the default password immediately after first login!

## Troubleshooting

### Error: "Cannot find module"
- Make sure you're in the `uniclub-express` directory
- Run `npm install` if you haven't already

### Error: "Database connection error"
- Check your `.env` file has correct database credentials
- Ensure your MySQL database is running
- Verify the database name matches your configuration

### Error: "Table 'admins' doesn't exist"
- Run the SQL migration file: `sql/Uniclub.sql`
- Or create the table manually:
  ```sql
  CREATE TABLE IF NOT EXISTS admins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  ```

## Security Best Practices

1. ✅ Use a strong password (at least 12 characters, mix of letters, numbers, symbols)
2. ✅ Don't share admin credentials
3. ✅ Change default passwords immediately
4. ✅ Use different passwords for different environments (dev/prod)
5. ✅ Regularly review admin accounts and remove unused ones

## Need Help?

If you encounter any issues:
1. Check the `scripts/README.md` for detailed documentation
2. Verify your database connection settings in `.env`
3. Check the server logs for detailed error messages

