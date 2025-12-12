# Admin Setup Scripts

## Creating an Admin Account

To create an admin account for the UniClub system, use the `createAdmin.js` script.

### Method 1: Using npm script (Recommended)

```bash
npm run create-admin
```

The script will prompt you for:
- Username
- Password (must be at least 6 characters)

### Method 2: Direct command with arguments

```bash
node scripts/createAdmin.js [username] [password]
```

Example:
```bash
node scripts/createAdmin.js admin mySecurePassword123
```

### Method 3: Interactive mode

```bash
node scripts/createAdmin.js
```

Then enter the username and password when prompted.

## Features

- ✅ Creates a new admin account with hashed password
- ✅ Updates password if admin already exists (with confirmation)
- ✅ Validates password length (minimum 6 characters)
- ✅ Secure password hashing using bcrypt
- ✅ Displays login credentials after creation

## Important Notes

⚠️ **Security Warning:**
- Save the credentials securely after creation
- Change the default password after first login
- Do not share admin credentials publicly
- The script displays the password in plain text - make sure to clear your terminal history if needed

## Login

After creating an admin account, you can log in at:
- URL: `/admin/login`
- Use the username and password you created

## Troubleshooting

If you encounter errors:
1. Make sure your database is running and accessible
2. Check your `.env` file has correct database credentials
3. Ensure the `admins` table exists in your database
4. Verify you have the required dependencies installed (`bcrypt`)

