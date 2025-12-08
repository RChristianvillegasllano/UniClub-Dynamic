# Finance Tables Migration Guide

## Overview
This migration creates the necessary database tables for the officer dashboard financial features, including expenses, budget tracking, financial reports, compliance issues, and audit logs.

## Running the Migration

### Option 1: Using MySQL Command Line
```bash
mysql -u your_username -p your_database_name < create_finance_tables.sql
```

### Option 2: Using MySQL Workbench or phpMyAdmin
1. Open your database management tool
2. Select your database
3. Open and execute the `create_finance_tables.sql` file

### Option 3: Using Node.js Script
You can create a simple script to run the migration:

```javascript
const fs = require('fs');
const mysql = require('mysql2/promise');

async function runMigration() {
  const connection = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'Uniclub',
    multipleStatements: true
  });

  const sql = fs.readFileSync('./sql/create_finance_tables.sql', 'utf8');
  await connection.query(sql);
  console.log('✅ Finance tables created successfully!');
  await connection.end();
}

runMigration().catch(console.error);
```

## Tables Created

1. **expenses** - Stores expense/receipt submissions
2. **budget** - Tracks club budgets by fiscal year
3. **financial_reports** - Manages financial report deadlines
4. **compliance_issues** - Tracks compliance flags and issues
5. **audit_logs** - Records all audit actions and changes

## Verification

After running the migration, verify the tables were created:

```sql
SHOW TABLES LIKE '%expenses%';
SHOW TABLES LIKE '%budget%';
SHOW TABLES LIKE '%financial_reports%';
SHOW TABLES LIKE '%compliance_issues%';
SHOW TABLES LIKE '%audit_logs%';
```

## Notes

- All tables include proper foreign key constraints
- Indexes are created for performance
- Tables are safe to create multiple times (uses `CREATE TABLE IF NOT EXISTS`)
- Foreign keys reference `clubs` and `officers` tables

