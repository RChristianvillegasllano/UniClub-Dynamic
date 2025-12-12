/**
 * Database Backup Script
 * Creates automated backups of the MySQL database
 * 
 * Usage:
 *   node scripts/backup-database.js
 * 
 * Environment Variables:
 *   BACKUP_DIR - Directory to store backups (default: ./backups)
 *   BACKUP_RETENTION_DAYS - Days to keep backups (default: 30)
 *   DATABASE_URL - Database connection string
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { exec } from 'child_process';
import { promisify } from 'util';
import dotenv from 'dotenv';

dotenv.config();

const execAsync = promisify(exec);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const BACKUP_DIR = process.env.BACKUP_DIR || path.join(__dirname, '..', 'backups');
const RETENTION_DAYS = parseInt(process.env.BACKUP_RETENTION_DAYS || '30');
const DATABASE_URL = process.env.DATABASE_URL || process.env.MAIN_DATABASE_URL;

// Parse database URL
function parseDatabaseUrl(url) {
  if (!url) {
    throw new Error('DATABASE_URL or MAIN_DATABASE_URL must be set');
  }
  
  // MySQL URL format: mysql://user:password@host:port/database
  const match = url.match(/mysql:\/\/([^:]+):([^@]+)@([^:]+):(\d+)\/(.+)/);
  if (!match) {
    // Fallback to individual env vars
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

async function createBackup() {
  try {
    const dbConfig = parseDatabaseUrl(DATABASE_URL);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFileName = `backup-${dbConfig.database}-${timestamp}.sql`;
    const backupPath = path.join(BACKUP_DIR, backupFileName);
    
    // Create backup directory if it doesn't exist
    if (!fs.existsSync(BACKUP_DIR)) {
      fs.mkdirSync(BACKUP_DIR, { recursive: true });
      console.log(`Created backup directory: ${BACKUP_DIR}`);
    }
    
    // Build mysqldump command
    const mysqldumpCmd = [
      'mysqldump',
      `-h${dbConfig.host}`,
      `-P${dbConfig.port}`,
      `-u${dbConfig.user}`,
      `-p${dbConfig.password}`,
      '--single-transaction',
      '--routines',
      '--triggers',
      '--events',
      dbConfig.database,
      `> ${backupPath}`
    ].join(' ');
    
    console.log(`Starting backup: ${backupFileName}`);
    console.log(`Database: ${dbConfig.database}`);
    console.log(`Host: ${dbConfig.host}:${dbConfig.port}`);
    
    // Execute backup
    await execAsync(mysqldumpCmd, { shell: true });
    
    // Compress backup (optional - requires gzip)
    try {
      await execAsync(`gzip ${backupPath}`);
      console.log(`Backup compressed: ${backupFileName}.gz`);
    } catch (err) {
      console.warn('Compression failed (gzip not available), keeping uncompressed backup');
    }
    
    const finalBackupPath = fs.existsSync(`${backupPath}.gz`) ? `${backupPath}.gz` : backupPath;
    const stats = fs.statSync(finalBackupPath);
    const sizeMB = (stats.size / 1024 / 1024).toFixed(2);
    
    console.log(`✅ Backup completed: ${finalBackupPath} (${sizeMB} MB)`);
    
    // Clean up old backups
    await cleanupOldBackups();
    
    return {
      success: true,
      file: finalBackupPath,
      size: stats.size,
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    console.error('❌ Backup failed:', error.message);
    throw error;
  }
}

async function cleanupOldBackups() {
  try {
    const files = fs.readdirSync(BACKUP_DIR);
    const now = Date.now();
    const retentionMs = RETENTION_DAYS * 24 * 60 * 60 * 1000;
    
    let deletedCount = 0;
    
    for (const file of files) {
      if (!file.startsWith('backup-')) continue;
      
      const filePath = path.join(BACKUP_DIR, file);
      const stats = fs.statSync(filePath);
      const age = now - stats.mtimeMs;
      
      if (age > retentionMs) {
        fs.unlinkSync(filePath);
        console.log(`Deleted old backup: ${file}`);
        deletedCount++;
      }
    }
    
    if (deletedCount > 0) {
      console.log(`Cleaned up ${deletedCount} old backup(s)`);
    }
  } catch (error) {
    console.error('Error cleaning up old backups:', error.message);
  }
}

// Run backup if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  createBackup()
    .then((result) => {
      console.log('Backup process completed successfully');
      process.exit(0);
    })
    .catch((error) => {
      console.error('Backup process failed:', error);
      process.exit(1);
    });
}

export { createBackup, cleanupOldBackups };

