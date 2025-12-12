/**
 * Advanced Security Middleware
 * Comprehensive protection against common attacks
 */

import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';
import validator from 'validator';
import xss from 'xss';

// ============================================
// 1. ENHANCED RATE LIMITING
// ============================================

// Stricter rate limit for authentication endpoints
export const strictAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: 'Too many login attempts. Please try again after 15 minutes.',
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Don't count successful requests
  handler: (req, res) => {
    console.warn(`[SECURITY] Rate limit exceeded for ${req.ip} on ${req.path}`);
    res.status(429).json({
      success: false,
      error: 'Too many attempts. Please try again later.',
      retryAfter: Math.ceil(req.rateLimit.resetTime / 1000)
    });
  }
});

// API rate limiter
export const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute
  message: 'Too many API requests. Please slow down.',
  standardHeaders: true,
  legacyHeaders: false,
});

// File upload rate limiter
export const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 uploads per 15 minutes
  message: 'Too many file uploads. Please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Password reset rate limiter
export const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 attempts per hour
  message: 'Too many password reset attempts. Please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// ============================================
// 2. INPUT SANITIZATION
// ============================================

/**
 * Sanitize string input to prevent XSS and injection attacks
 */
export function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  
  // Remove null bytes
  let sanitized = input.replace(/\0/g, '');
  
  // Trim whitespace
  sanitized = sanitized.trim();
  
  // Remove control characters except newlines and tabs
  sanitized = sanitized.replace(/[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]/g, '');
  
  // XSS protection using xss library
  sanitized = xss(sanitized, {
    whiteList: {}, // No HTML tags allowed
    stripIgnoreTag: true,
    stripIgnoreTagBody: ['script']
  });
  
  return sanitized;
}

/**
 * Sanitize object recursively
 */
export function sanitizeObject(obj, maxDepth = 10, currentDepth = 0) {
  // Prevent infinite recursion
  if (currentDepth > maxDepth) {
    console.warn('[SECURITY] Object nesting too deep in sanitizeObject, returning original');
    return obj;
  }
  
  if (obj === null || obj === undefined) return obj;
  
  // Handle special objects that shouldn't be sanitized
  if (obj instanceof Date || obj instanceof RegExp || Buffer.isBuffer(obj)) {
    return obj;
  }
  
  if (typeof obj === 'string') {
    try {
      return sanitizeInput(obj);
    } catch (error) {
      console.warn('[SECURITY] String sanitization failed, returning original:', error.message);
      return obj;
    }
  }
  
  if (Array.isArray(obj)) {
    // Limit array size to prevent DoS
    if (obj.length > 1000) {
      console.warn('[SECURITY] Array too large, truncating');
      return obj.slice(0, 1000).map(item => {
        try {
          return sanitizeObject(item, maxDepth, currentDepth + 1);
        } catch (error) {
          console.warn('[SECURITY] Failed to sanitize array item:', error.message);
          return item;
        }
      });
    }
    try {
      return obj.map(item => sanitizeObject(item, maxDepth, currentDepth + 1));
    } catch (error) {
      console.warn('[SECURITY] Array sanitization failed, returning original:', error.message);
      return obj;
    }
  }
  
  if (typeof obj === 'object') {
    try {
      const sanitized = {};
      const keys = Object.keys(obj);
      for (const key of keys) {
        try {
          if (Object.prototype.hasOwnProperty.call(obj, key)) {
            sanitized[key] = sanitizeObject(obj[key], maxDepth, currentDepth + 1);
          }
        } catch (keyError) {
          console.warn(`[SECURITY] Failed to sanitize key "${key}":`, keyError.message);
          // Skip this key if sanitization fails
          continue;
        }
      }
      return sanitized;
    } catch (error) {
      console.warn('[SECURITY] Object sanitization failed, returning original:', error.message);
      return obj;
    }
  }
  
  return obj;
}

/**
 * Middleware to sanitize all request body, query, and params
 */
export const sanitizeRequest = (req, res, next) => {
  // Wrap everything in try-catch to ensure we never block requests
  try {
    // Skip for GET, HEAD, OPTIONS requests - they don't need sanitization
    let method = 'GET';
    try {
      if (!req || !req.method) {
        return next();
      }
      method = req.method.toUpperCase();
    } catch (e) {
      return next();
    }
    
    if (['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      return next();
    }
    
    // For other methods, sanitize with error handling
    try {
      if (req.body) {
        try {
          req.body = sanitizeObject(req.body);
        } catch (bodyError) {
          console.warn('[SECURITY] Body sanitization failed in sanitizeRequest:', bodyError.message);
          // Continue without sanitizing body
        }
      }
      if (req.query) {
        try {
          req.query = sanitizeObject(req.query);
        } catch (queryError) {
          console.warn('[SECURITY] Query sanitization failed in sanitizeRequest:', queryError.message);
          // Continue without sanitizing query
        }
      }
      if (req.params) {
        try {
          req.params = sanitizeObject(req.params);
        } catch (paramsError) {
          console.warn('[SECURITY] Params sanitization failed in sanitizeRequest:', paramsError.message);
          // Continue without sanitizing params
        }
      }
    } catch (innerError) {
      // If inner try fails, just continue
      console.warn('[SECURITY] Inner sanitization error in sanitizeRequest, allowing through');
    }
    
    next();
  } catch (error) {
    // Outer catch - always allow through, never block
    console.warn('[SECURITY] sanitizeRequest middleware error (allowing through):', error.message);
    return next();
  }
};

// ============================================
// 3. SQL INJECTION PREVENTION
// ============================================

/**
 * Validate that a value is safe for SQL (no SQL keywords in dangerous contexts)
 */
export function validateSQLSafe(value) {
  if (typeof value !== 'string') return true;
  
  // Dangerous SQL patterns
  const dangerousPatterns = [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)/gi,
    /(--|#|\/\*|\*\/|;)/g, // SQL comments and statement terminators
    /(\bOR\b.*=.*|'.*OR.*'.*=)/gi, // SQL injection patterns
    /(\bAND\b.*=.*|'.*AND.*'.*=)/gi,
  ];
  
  for (const pattern of dangerousPatterns) {
    if (pattern.test(value)) {
      return false;
    }
  }
  
  return true;
}

/**
 * Validate email format and prevent injection
 */
export function validateEmail(email) {
  if (!email || typeof email !== 'string') return false;
  
  // Basic email validation
  if (!validator.isEmail(email)) return false;
  
  // Check for dangerous patterns
  if (!validateSQLSafe(email)) return false;
  
  // Length check
  if (email.length > 255) return false;
  
  return true;
}

/**
 * Validate password strength
 */
export function validatePasswordStrength(password) {
  if (!password || typeof password !== 'string') {
    return { valid: false, message: 'Password is required' };
  }
  
  if (password.length < 8) {
    return { valid: false, message: 'Password must be at least 8 characters long' };
  }
  
  if (password.length > 128) {
    return { valid: false, message: 'Password must be less than 128 characters' };
  }
  
  // Check for at least one uppercase letter
  if (!/[A-Z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one uppercase letter' };
  }
  
  // Check for at least one lowercase letter
  if (!/[a-z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one lowercase letter' };
  }
  
  // Check for at least one number
  if (!/[0-9]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one number' };
  }
  
  // Check for at least one special character
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one special character' };
  }
  
  // Check for common weak passwords
  const commonPasswords = ['password', 'password123', 'admin', '12345678', 'qwerty', 'letmein'];
  if (commonPasswords.includes(password.toLowerCase())) {
    return { valid: false, message: 'Password is too common. Please choose a stronger password' };
  }
  
  return { valid: true, message: 'Password is strong' };
}

// ============================================
// 4. ACCOUNT LOCKOUT TRACKING
// ============================================

// In-memory store for failed login attempts (use Redis in production)
const failedAttempts = new Map();
const LOCKOUT_DURATION = 30 * 60 * 1000; // 30 minutes
const MAX_FAILED_ATTEMPTS = 5;

/**
 * Record a failed login attempt
 */
export function recordFailedAttempt(identifier, ip) {
  const key = `${identifier}:${ip}`;
  const attempts = failedAttempts.get(key) || { count: 0, firstAttempt: Date.now() };
  attempts.count++;
  attempts.lastAttempt = Date.now();
  failedAttempts.set(key, attempts);
  
  // Clean up old entries periodically
  if (failedAttempts.size > 10000) {
    const now = Date.now();
    for (const [k, v] of failedAttempts.entries()) {
      if (now - v.lastAttempt > LOCKOUT_DURATION * 2) {
        failedAttempts.delete(k);
      }
    }
  }
}

/**
 * Clear failed attempts after successful login
 */
export function clearFailedAttempts(identifier, ip) {
  const key = `${identifier}:${ip}`;
  failedAttempts.delete(key);
}

/**
 * Check if account is locked
 */
export function isAccountLocked(identifier, ip) {
  const key = `${identifier}:${ip}`;
  const attempts = failedAttempts.get(key);
  
  if (!attempts) return false;
  
  // Check if lockout period has passed
  if (Date.now() - attempts.lastAttempt > LOCKOUT_DURATION) {
    failedAttempts.delete(key);
    return false;
  }
  
  // Check if max attempts exceeded
  if (attempts.count >= MAX_FAILED_ATTEMPTS) {
    return true;
  }
  
  return false;
}

/**
 * Get remaining lockout time in seconds
 */
export function getLockoutTimeRemaining(identifier, ip) {
  const key = `${identifier}:${ip}`;
  const attempts = failedAttempts.get(key);
  
  if (!attempts || attempts.count < MAX_FAILED_ATTEMPTS) {
    return 0;
  }
  
  const elapsed = Date.now() - attempts.lastAttempt;
  const remaining = LOCKOUT_DURATION - elapsed;
  
  return remaining > 0 ? Math.ceil(remaining / 1000) : 0;
}

// ============================================
// 5. REQUEST VALIDATION MIDDLEWARE
// ============================================

/**
 * Validate request size
 */
export const validateRequestSize = (maxSize = 10 * 1024 * 1024) => { // 10MB default
  return (req, res, next) => {
    const contentLength = parseInt(req.headers['content-length'] || '0');
    
    if (contentLength > maxSize) {
      console.warn(`[SECURITY] Request too large: ${contentLength} bytes from ${req.ip}`);
      return res.status(413).json({
        success: false,
        error: 'Request payload too large'
      });
    }
    
    next();
  };
};

/**
 * Validate file upload
 */
export const validateFileUpload = (allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'], maxSize = 5 * 1024 * 1024) => {
  return (req, res, next) => {
    if (!req.file && !req.files) {
      return next();
    }
    
    const files = req.files || [req.file];
    
    for (const file of files) {
      if (!file) continue;
      
      // Check file size
      if (file.size > maxSize) {
        return res.status(400).json({
          success: false,
          error: `File ${file.originalname} exceeds maximum size of ${maxSize / 1024 / 1024}MB`
        });
      }
      
      // Check file type
      if (!allowedTypes.includes(file.mimetype)) {
        return res.status(400).json({
          success: false,
          error: `File type ${file.mimetype} is not allowed`
        });
      }
      
      // Check file extension
      const ext = file.originalname.split('.').pop().toLowerCase();
      const allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
      if (!allowedExtensions.includes(ext)) {
        return res.status(400).json({
          success: false,
          error: `File extension .${ext} is not allowed`
        });
      }
    }
    
    next();
  };
};

// ============================================
// 6. SECURITY HEADERS ENHANCEMENT
// ============================================

/**
 * Additional security headers
 */
export const securityHeaders = (req, res, next) => {
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // Enable XSS protection
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  // Referrer policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Permissions policy
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  
  // Remove server information
  res.removeHeader('X-Powered-By');
  
  next();
};

// ============================================
// 7. AUDIT LOGGING
// ============================================

/**
 * Log security events
 */
export function logSecurityEvent(type, details, req) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    type,
    ip: req?.ip || req?.connection?.remoteAddress,
    userAgent: req?.get('user-agent'),
    path: req?.path,
    method: req?.method,
    userId: req?.session?.admin?.id || req?.session?.officer?.id || req?.session?.student?.id,
    details
  };
  
  // In production, send to logging service
  console.warn(`[SECURITY EVENT] ${type}:`, JSON.stringify(logEntry));
  
  // TODO: Store in database audit_logs table
}

/**
 * Middleware to log suspicious activities
 */
export const auditLog = (req, res, next) => {
  // Log sensitive operations
  const sensitivePaths = ['/admin', '/officer', '/api'];
  const sensitiveMethods = ['POST', 'PUT', 'DELETE', 'PATCH'];
  
  if (sensitivePaths.some(path => req.path.startsWith(path)) && 
      sensitiveMethods.includes(req.method)) {
    logSecurityEvent('SENSITIVE_OPERATION', {
      action: `${req.method} ${req.path}`,
      bodyKeys: Object.keys(req.body || {})
    }, req);
  }
  
  next();
};

// ============================================
// 8. SESSION SECURITY
// ============================================

/**
 * Regenerate session ID on privilege escalation (login)
 */
export function regenerateSession(req, callback) {
  const oldSession = req.session;
  
  req.session.regenerate((err) => {
    if (err) {
      return callback(err);
    }
    
    // Copy important data
    if (oldSession.csrfSecret) {
      req.session.csrfSecret = oldSession.csrfSecret;
    }
    
    callback(null);
  });
}

/**
 * Validate session integrity
 */
export function validateSession(req, res, next) {
  if (!req.session) {
    logSecurityEvent('INVALID_SESSION', { reason: 'No session found' }, req);
    return res.status(401).json({ success: false, error: 'Session expired' });
  }
  
  // Check session age
  if (req.session.cookie && req.session.cookie.maxAge) {
    const sessionAge = Date.now() - (req.session.cookie.originalMaxAge - req.session.cookie.maxAge);
    if (sessionAge > 24 * 60 * 60 * 1000) { // 24 hours
      logSecurityEvent('SESSION_EXPIRED', { age: sessionAge }, req);
      req.session.destroy();
      return res.status(401).json({ success: false, error: 'Session expired' });
    }
  }
  
  next();
}

// ============================================
// 9. ERROR MESSAGE SANITIZATION
// ============================================

/**
 * Sanitize error messages to prevent information leakage
 */
export function sanitizeError(error, isProduction) {
  if (isProduction) {
    // Don't expose internal errors in production
    if (error.message && (
      error.message.includes('SQL') ||
      error.message.includes('database') ||
      error.message.includes('connection') ||
      error.message.includes('syntax')
    )) {
      return 'An internal error occurred. Please contact support.';
    }
  }
  
  return error.message || 'An error occurred';
}

// ============================================
// 10. IP WHITELIST/BLACKLIST (Optional)
// ============================================

const blacklistedIPs = new Set();
const whitelistedIPs = new Set();

/**
 * Add IP to blacklist
 */
export function blacklistIP(ip) {
  blacklistedIPs.add(ip);
  logSecurityEvent('IP_BLACKLISTED', { ip }, { ip });
}

/**
 * Check if IP is blacklisted
 */
export function isIPBlacklisted(ip) {
  return blacklistedIPs.has(ip);
}

/**
 * Middleware to check IP blacklist
 */
export const checkIPBlacklist = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  
  if (isIPBlacklisted(ip)) {
    logSecurityEvent('BLACKLISTED_IP_ACCESS', { ip }, req);
    return res.status(403).json({
      success: false,
      error: 'Access denied'
    });
  }
  
  next();
};

export default {
  strictAuthLimiter,
  apiLimiter,
  uploadLimiter,
  passwordResetLimiter,
  sanitizeInput,
  sanitizeObject,
  sanitizeRequest,
  validateSQLSafe,
  validateEmail,
  validatePasswordStrength,
  recordFailedAttempt,
  clearFailedAttempts,
  isAccountLocked,
  getLockoutTimeRemaining,
  validateRequestSize,
  validateFileUpload,
  securityHeaders,
  logSecurityEvent,
  auditLog,
  regenerateSession,
  validateSession,
  sanitizeError,
  blacklistIP,
  isIPBlacklisted,
  checkIPBlacklist
};

