/**
 * Centralized Logging Configuration
 * Supports multiple log outputs (console, file, external services)
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const LOG_DIR = process.env.LOG_DIR || path.join(__dirname, '..', 'logs');
const NODE_ENV = process.env.NODE_ENV || 'development';

// Ensure log directory exists
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

// Log levels
const LOG_LEVELS = {
  error: 0,
  warn: 1,
  info: 2,
  debug: 3
};

class Logger {
  constructor(service = 'app') {
    this.service = service;
    this.logLevel = LOG_LEVELS[LOG_LEVEL] || LOG_LEVELS.info;
  }

  formatMessage(level, message, meta = {}) {
    const timestamp = new Date().toISOString();
    return {
      timestamp,
      level: level.toUpperCase(),
      service: this.service,
      message,
      ...meta,
      environment: NODE_ENV
    };
  }

  writeLog(level, message, meta = {}) {
    if (LOG_LEVELS[level] > this.logLevel) return;

    const logEntry = this.formatMessage(level, message, meta);
    const logLine = JSON.stringify(logEntry) + '\n';

    // Console output (formatted for readability)
    if (NODE_ENV === 'development') {
      const colors = {
        error: '\x1b[31m', // Red
        warn: '\x1b[33m',  // Yellow
        info: '\x1b[36m',  // Cyan
        debug: '\x1b[90m'  // Gray
      };
      const reset = '\x1b[0m';
      console.log(`${colors[level] || ''}[${logEntry.timestamp}] [${logEntry.level}] ${message}${reset}`, meta);
    } else {
      console.log(logLine.trim());
    }

    // File output (for errors and warnings)
    if (level === 'error' || level === 'warn') {
      const logFile = path.join(LOG_DIR, `${level}-${new Date().toISOString().split('T')[0]}.log`);
      fs.appendFileSync(logFile, logLine, 'utf8');
    }

    // Security events log
    if (meta.securityEvent || level === 'error') {
      const securityLogFile = path.join(LOG_DIR, `security-${new Date().toISOString().split('T')[0]}.log`);
      fs.appendFileSync(securityLogFile, logLine, 'utf8');
    }
  }

  error(message, meta = {}) {
    this.writeLog('error', message, meta);
  }

  warn(message, meta = {}) {
    this.writeLog('warn', message, meta);
  }

  info(message, meta = {}) {
    this.writeLog('info', message, meta);
  }

  debug(message, meta = {}) {
    this.writeLog('debug', message, meta);
  }

  security(event, details = {}) {
    this.writeLog('warn', `[SECURITY] ${event}`, { securityEvent: true, ...details });
  }
}

// Request logging middleware
export function requestLogger(req, res, next) {
  const startTime = Date.now();
  const logger = new Logger('http');

  // Log request
  logger.info(`${req.method} ${req.path}`, {
    ip: req.ip,
    userAgent: req.get('user-agent'),
    userId: req.session?.admin?.id || req.session?.officer?.id || req.session?.student?.id
  });

  // Log response
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const level = res.statusCode >= 400 ? 'warn' : 'info';
    
    logger[level](`${req.method} ${req.path} ${res.statusCode}`, {
      duration: `${duration}ms`,
      statusCode: res.statusCode,
      ip: req.ip
    });
  });

  next();
}

// Security event logger
export function securityLogger(type, details, req) {
  const logger = new Logger('security');
  logger.security(type, {
    ...details,
    ip: req?.ip || req?.connection?.remoteAddress,
    userAgent: req?.get('user-agent'),
    path: req?.path,
    method: req?.method,
    userId: req?.session?.admin?.id || req?.session?.officer?.id || req?.session?.student?.id
  });
}

// Export logger instance
export const logger = new Logger();
export default Logger;

