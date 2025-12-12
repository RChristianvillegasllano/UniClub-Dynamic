/**
 * Production Readiness Verification Script
 * Checks if system is ready for production deployment
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { exec } from 'child_process';
import { promisify } from 'util';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const checks = {
  passed: [],
  failed: [],
  warnings: []
};

function check(name, condition, message) {
  if (condition) {
    checks.passed.push({ name, message });
    console.log(`✅ ${name}: ${message}`);
  } else {
    checks.failed.push({ name, message });
    console.log(`❌ ${name}: ${message}`);
  }
}

function warn(name, message) {
  checks.warnings.push({ name, message });
  console.log(`⚠️  ${name}: ${message}`);
}

async function verifyEnvironment() {
  console.log('\n📋 Checking Environment Variables...\n');
  
  const isProduction = process.env.NODE_ENV === 'production';
  
  // Check SESSION_SECRET
  const sessionSecret = process.env.SESSION_SECRET;
  check(
    'SESSION_SECRET',
    sessionSecret && sessionSecret !== 'change-me-development-only',
    isProduction 
      ? 'SESSION_SECRET is set and not default'
      : 'SESSION_SECRET is set (use strong secret in production)'
  );
  
  if (isProduction && sessionSecret && sessionSecret.length < 32) {
    warn('SESSION_SECRET', 'SESSION_SECRET should be at least 32 characters in production');
  }
  
  // Check Database Configuration
  const hasDatabaseUrl = !!process.env.DATABASE_URL || !!process.env.MAIN_DATABASE_URL;
  const hasDbConfig = !!(
    process.env.MAIN_DB_HOST || 
    process.env.MAIN_DB_USER || 
    process.env.DB_HOST
  );
  
  check(
    'Database Configuration',
    hasDatabaseUrl || hasDbConfig,
    'Database configuration found'
  );
  
  // Check NODE_ENV
  if (isProduction) {
    check('NODE_ENV', true, 'Running in production mode');
  } else {
    warn('NODE_ENV', 'Not set to production - ensure this is set in production');
  }
}

async function verifySecurity() {
  console.log('\n🔒 Checking Security Configuration...\n');
  
  // Check if .env is in .gitignore
  try {
    const gitignore = fs.readFileSync(path.join(__dirname, '..', '.gitignore'), 'utf8');
    check(
      '.env in .gitignore',
      gitignore.includes('.env'),
      '.env file is excluded from git'
    );
  } catch (err) {
    warn('.gitignore', '.gitignore file not found');
  }
  
  // Check for hardcoded secrets
  const secretPatterns = [
    /password\s*=\s*['"][^'"]+['"]/i,
    /secret\s*=\s*['"][^'"]+['"]/i,
    /api[_-]?key\s*=\s*['"][^'"]+['"]/i
  ];
  
  let foundSecrets = false;
  try {
    const files = fs.readdirSync(path.join(__dirname, '..', 'routes'));
    for (const file of files) {
      if (file.endsWith('.js')) {
        const content = fs.readFileSync(path.join(__dirname, '..', 'routes', file), 'utf8');
        for (const pattern of secretPatterns) {
          if (pattern.test(content) && !content.includes('process.env')) {
            foundSecrets = true;
            break;
          }
        }
      }
    }
  } catch (err) {
    // Ignore
  }
  
  check(
    'No hardcoded secrets',
    !foundSecrets,
    foundSecrets ? 'Potential hardcoded secrets found - review code' : 'No hardcoded secrets detected'
  );
  
  // Check security middleware files exist
  const securityFiles = [
    'middleware/advancedSecurity.js',
    'middleware/authorization.js',
    'middleware/inputValidation.js'
  ];
  
  for (const file of securityFiles) {
    const filePath = path.join(__dirname, '..', file);
    check(
      `Security file: ${file}`,
      fs.existsSync(filePath),
      fs.existsSync(filePath) ? 'File exists' : 'File missing'
    );
  }
}

async function verifyDependencies() {
  console.log('\n📦 Checking Dependencies...\n');
  
  try {
    const execAsync = promisify(exec);
    const { stdout } = await execAsync('npm audit --json', { 
      cwd: path.join(__dirname, '..'),
      maxBuffer: 1024 * 1024 * 10 // 10MB
    });
    
    const audit = JSON.parse(stdout);
    const vulnerabilities = audit.vulnerabilities || {};
    const critical = vulnerabilities.critical || 0;
    const high = vulnerabilities.high || 0;
    const moderate = vulnerabilities.moderate || 0;
    
    check(
      'No critical vulnerabilities',
      critical === 0,
      critical === 0 ? 'No critical vulnerabilities' : `${critical} critical vulnerabilities found`
    );
    
    check(
      'No high vulnerabilities',
      high === 0,
      high === 0 ? 'No high vulnerabilities' : `${high} high vulnerabilities found`
    );
    
    if (moderate > 0) {
      warn('Moderate vulnerabilities', `${moderate} moderate vulnerabilities found - review npm audit`);
    }
  } catch (error) {
    warn('npm audit', 'Could not run npm audit - check manually');
  }
}

async function verifyBackups() {
  console.log('\n💾 Checking Backup Configuration...\n');
  
  const backupScript = path.join(__dirname, 'backup-database.js');
  check(
    'Backup script exists',
    fs.existsSync(backupScript),
    fs.existsSync(backupScript) ? 'Backup script found' : 'Backup script missing'
  );
  
  const restoreScript = path.join(__dirname, 'restore-database.js');
  check(
    'Restore script exists',
    fs.existsSync(restoreScript),
    fs.existsSync(restoreScript) ? 'Restore script found' : 'Restore script missing'
  );
}

async function verifyDocumentation() {
  console.log('\n📚 Checking Documentation...\n');
  
  const docs = [
    'DEPLOYMENT_CHECKLIST.md',
    'SECURITY.md',
    'SECURITY_ENHANCEMENTS.md',
    'SECRETS_MANAGEMENT.md',
    'INCIDENT_RESPONSE.md'
  ];
  
  for (const doc of docs) {
    const docPath = path.join(__dirname, '..', doc);
    check(
      `Documentation: ${doc}`,
      fs.existsSync(docPath),
      fs.existsSync(docPath) ? 'Document exists' : 'Document missing'
    );
  }
}

async function verifyLogging() {
  console.log('\n📊 Checking Logging Configuration...\n');
  
  const loggingConfig = path.join(__dirname, '..', 'config', 'logging.js');
  check(
    'Logging configuration',
    fs.existsSync(loggingConfig),
    fs.existsSync(loggingConfig) ? 'Logging config found' : 'Logging config missing'
  );
  
  const logDir = process.env.LOG_DIR || path.join(__dirname, '..', 'logs');
  check(
    'Log directory',
    true,
    `Log directory: ${logDir}`
  );
}

function printSummary() {
  console.log('\n' + '='.repeat(60));
  console.log('📊 PRODUCTION READINESS SUMMARY');
  console.log('='.repeat(60));
  
  console.log(`\n✅ Passed: ${checks.passed.length}`);
  console.log(`❌ Failed: ${checks.failed.length}`);
  console.log(`⚠️  Warnings: ${checks.warnings.length}`);
  
  if (checks.failed.length > 0) {
    console.log('\n❌ FAILED CHECKS (Must fix before production):');
    checks.failed.forEach(({ name, message }) => {
      console.log(`   - ${name}: ${message}`);
    });
  }
  
  if (checks.warnings.length > 0) {
    console.log('\n⚠️  WARNINGS (Review before production):');
    checks.warnings.forEach(({ name, message }) => {
      console.log(`   - ${name}: ${message}`);
    });
  }
  
  const isReady = checks.failed.length === 0;
  
  console.log('\n' + '='.repeat(60));
  if (isReady) {
    console.log('✅ SYSTEM IS READY FOR PRODUCTION');
    console.log('   (Review warnings and complete deployment checklist)');
  } else {
    console.log('❌ SYSTEM IS NOT READY FOR PRODUCTION');
    console.log('   Fix failed checks before deploying');
  }
  console.log('='.repeat(60) + '\n');
  
  return isReady;
}

async function main() {
  console.log('🚀 Production Readiness Verification\n');
  console.log('='.repeat(60));
  
  await verifyEnvironment();
  await verifySecurity();
  await verifyDependencies();
  await verifyBackups();
  await verifyDocumentation();
  await verifyLogging();
  
  const isReady = printSummary();
  process.exit(isReady ? 0 : 1);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(error => {
    console.error('Verification failed:', error);
    process.exit(1);
  });
}

export { verifyEnvironment, verifySecurity, verifyDependencies, verifyBackups, verifyDocumentation, verifyLogging };

