/**
 * Database Restore Script
 * Restores database from backup file
 * 
 * Usage:
 *   node scripts/restore-database.js <backup-file>
 * 
 * Example:
 *   node scripts/restore-database.js backups/backup-Uniclub-2024-01-15T10-30-00.sql.gz
 * 
 * WARNING: This will overwrite the current database!
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { exec } from 'child_process';
import { promisify } from 'util';
import readline from 'readline';
import dotenv from 'dotenv';

dotenv.config();

const execAsync = promisify(exec);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Parse database URL
function parseDatabaseUrl(url) {
  if (!url) {
    throw new Error('DATABASE_URL or MAIN_DATABASE_URL must be set');
  }
  
  const match = url.match(/mysql:\/\/([^:]+):([^@]+)@([^:]+):(\d+)\/(.+)/);
  if (!match) {
    return {
      user: process.env.MAIN_DB_USER || process.env.DB_USER || 'root',
      password: process.env.MAIN_DB_PASSWORD || process.env.DB_PASSWORD || '',
      host: process.env.MAIN_DB_HOST || process.env.DB_HOST || 'localhost',
      port: process.env.MAIN_DB_PORT || process.env.DB_PORT || 3306,
      database: process.env.MAIN_DB_NAME || process.env.DB_NAME || 'Uniclub'
    };
  }
  
  return {
    user: match[1],
    password: match[2],
    host: match[3],
    port: parseInt(match[4]),
    database: match[5]
  };
}

function askQuestion(query) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise(resolve => rl.question(query, ans => {
    rl.close();
    resolve(ans);
  }));
}

async function restoreDatabase(backupFile) {
  try {
    // Validate backup file
    if (!fs.existsSync(backupFile)) {
      throw new Error(`Backup file not found: ${backupFile}`);
    }
    
    const dbConfig = parseDatabaseUrl(process.env.DATABASE_URL || process.env.MAIN_DATABASE_URL);
    
    console.log('⚠️  WARNING: This will overwrite the current database!');
    console.log(`Database: ${dbConfig.database}`);
    console.log(`Host: ${dbConfig.host}:${dbConfig.port}`);
    console.log(`Backup file: ${backupFile}`);
    
    // Confirm restore
    const answer = await askQuestion('\nType "RESTORE" to confirm: ');
    if (answer !== 'RESTORE') {
      console.log('Restore cancelled.');
      process.exit(0);
    }
    
    // Check if file is compressed
    let sqlFile = backupFile;
    if (backupFile.endsWith('.gz')) {
      console.log('Decompressing backup file...');
      const decompressedFile = backupFile.replace('.gz', '');
      await execAsync(`gunzip -c ${backupFile} > ${decompressedFile}`);
      sqlFile = decompressedFile;
    }
    
    console.log(`\nStarting restore from: ${sqlFile}`);
    
    // Build mysql command
    const mysqlCmd = [
      'mysql',
      `-h${dbConfig.host}`,
      `-P${dbConfig.port}`,
      `-u${dbConfig.user}`,
      `-p${dbConfig.password}`,
      dbConfig.database,
      `< ${sqlFile}`
    ].join(' ');
    
    // Execute restore
    await execAsync(mysqlCmd, { shell: true });
    
    // Clean up decompressed file if it was created
    if (sqlFile !== backupFile && fs.existsSync(sqlFile)) {
      fs.unlinkSync(sqlFile);
    }
    
    console.log('✅ Database restore completed successfully!');
    
    return {
      success: true,
      database: dbConfig.database,
      backupFile: backupFile,
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    console.error('❌ Restore failed:', error.message);
    throw error;
  }
}

// Run restore if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const backupFile = process.argv[2];
  
  if (!backupFile) {
    console.error('Usage: node scripts/restore-database.js <backup-file>');
    console.error('Example: node scripts/restore-database.js backups/backup-Uniclub-2024-01-15T10-30-00.sql.gz');
    process.exit(1);
  }
  
  restoreDatabase(backupFile)
    .then((result) => {
      console.log('Restore process completed successfully');
      process.exit(0);
    })
    .catch((error) => {
      console.error('Restore process failed:', error);
      process.exit(1);
    });
}

export { restoreDatabase };

