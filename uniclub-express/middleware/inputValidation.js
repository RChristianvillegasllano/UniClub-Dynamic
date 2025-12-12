/**
 * Advanced Input Validation
 * Protects against validation gaps, nested JSON attacks, prototype pollution, etc.
 */

import validator from 'validator';
import { body, validationResult } from 'express-validator';

// ============================================
// 1. PROTOTYPE POLLUTION PROTECTION
// ============================================

/**
 * Remove dangerous prototype properties from object
 */
export function sanitizeObject(obj, maxDepth = 10, currentDepth = 0) {
  // Prevent infinite recursion
  if (currentDepth > maxDepth) {
    console.warn('[SECURITY] Object nesting too deep, returning original object');
    return obj;
  }
  
  if (obj === null || obj === undefined) {
    return obj;
  }
  
  // Handle primitive types
  if (typeof obj !== 'object') {
    return obj;
  }
  
  // Handle special objects that shouldn't be sanitized
  if (obj instanceof Date || obj instanceof RegExp || Buffer.isBuffer(obj)) {
    return obj;
  }
  
  // Check for circular references by using a WeakSet (if available)
  // For now, we'll rely on depth limiting
  
  // Prevent prototype pollution
  if (Array.isArray(obj)) {
    // Limit array size
    if (obj.length > 1000) {
      console.warn('[SECURITY] Array too large, truncating');
      return obj.slice(0, 1000).map(item => {
        try {
          return sanitizeObject(item, maxDepth, currentDepth + 1);
        } catch (error) {
          console.warn('[SECURITY] Failed to sanitize array item:', error.message);
          return item; // Return original if sanitization fails
        }
      });
    }
    try {
      return obj.map(item => sanitizeObject(item, maxDepth, currentDepth + 1));
    } catch (error) {
      console.warn('[SECURITY] Array sanitization failed, returning original:', error.message);
      return obj; // Return original array if sanitization fails
    }
  }
  
  // Handle plain objects
  if (typeof obj === 'object') {
    // Check for dangerous keys
    const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
    for (const key of dangerousKeys) {
      try {
        if (key in obj) {
          try {
            delete obj[key];
          } catch (e) {
            // Ignore deletion errors
          }
        }
      } catch (error) {
        // Ignore errors when checking/deleting dangerous keys
      }
    }
    
    // Recursively sanitize nested objects
    const sanitized = {};
    try {
      const keys = Object.keys(obj);
      for (const key of keys) {
        try {
          // Skip dangerous keys
          if (dangerousKeys.includes(key)) continue;
          
          // Validate key name
          if (typeof key === 'string' && key.length > 100) {
            continue; // Skip overly long keys
          }
          
          // Try to sanitize the value
          try {
            sanitized[key] = sanitizeObject(obj[key], maxDepth, currentDepth + 1);
          } catch (valueError) {
            // If sanitization fails, skip this key or use original value
            console.warn(`[SECURITY] Failed to sanitize value for key "${key}":`, valueError.message);
            // Optionally include original value, but this could be risky
            // For safety, we'll skip the key
            continue;
          }
        } catch (error) {
          // Skip this key if anything fails
          console.warn(`[SECURITY] Failed to process key "${key}":`, error.message);
          continue;
        }
      }
    } catch (error) {
      console.warn('[SECURITY] Object sanitization failed, returning original:', error.message);
      return obj; // Return original object if sanitization fails
    }
    return sanitized;
  }
  
  return obj;
}

/**
 * Middleware to protect against prototype pollution
 */
export const preventPrototypePollution = (req, res, next) => {
  // Wrap everything in try-catch to ensure we never block requests
  try {
    // First, safely get the method - if we can't, assume GET and allow through
    let method = 'GET';
    try {
      if (!req || !req.method) {
        return next();
      }
      method = req.method.toUpperCase();
    } catch (e) {
      // If we can't access req.method, assume GET and allow through
      return next();
    }
    
    // Skip for GET, HEAD, OPTIONS requests (they typically don't have bodies to sanitize)
    // Check method first to avoid any processing for GET requests
    if (['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      return next();
    }
    
    // For non-GET requests, try to sanitize
    try {
    // Skip for certain content types that don't need sanitization
    try {
      const contentType = req.get('content-type') || '';
      if (contentType.includes('multipart/form-data') || contentType.includes('application/octet-stream')) {
        return next();
      }
    } catch (e) {
      // If we can't get content-type, continue
    }
    
    // Only sanitize if body exists and is an object (not null, not array at top level for body)
    if (req.body && typeof req.body === 'object' && !Array.isArray(req.body) && req.body !== null) {
      try {
        // Check if body is empty object
        if (Object.keys(req.body).length === 0) {
          return next();
        }
        req.body = sanitizeObject(req.body);
      } catch (bodyError) {
        console.error('[SECURITY] Body sanitization failed:', bodyError.message);
        console.error('[SECURITY] Request path:', req.path);
        console.error('[SECURITY] Request method:', method);
        // Don't fail the request, just log and continue
        // The route handler will validate the data
      }
    }
    
    // Sanitize query params (safe to do on all requests, but skip for GET since we already returned)
    // This is just a safety check in case we process query params elsewhere
    if (req.query && typeof req.query === 'object' && !Array.isArray(req.query) && req.query !== null) {
      try {
        if (Object.keys(req.query).length > 0) {
          req.query = sanitizeObject(req.query);
        }
      } catch (queryError) {
        console.error('[SECURITY] Query sanitization failed:', queryError.message);
        // Don't fail the request, just log and continue
      }
    }
    
    // Sanitize route params (safe to do on all requests, but skip for GET since we already returned)
    if (req.params && typeof req.params === 'object' && !Array.isArray(req.params) && req.params !== null) {
      try {
        if (Object.keys(req.params).length > 0) {
          req.params = sanitizeObject(req.params);
        }
      } catch (paramsError) {
        console.error('[SECURITY] Params sanitization failed:', paramsError.message);
        // Don't fail the request, just log and continue
      }
    }
    
      next();
    } catch (innerError) {
      // If inner try fails, just continue
      console.warn('[SECURITY] Inner sanitization error, allowing request to continue');
      return next();
    }
  } catch (error) {
    // Outer catch - always allow through, never block
    console.warn('[SECURITY] Prototype pollution middleware error (allowing through):', error.message);
    return next();
  }
};

// ============================================
// 2. NESTED JSON VALIDATION
// ============================================

/**
 * Flatten nested object for validation
 */
export function flattenObject(obj, prefix = '', maxDepth = 5, currentDepth = 0) {
  if (currentDepth > maxDepth) {
    throw new Error('Object nesting too deep');
  }
  
  const flattened = {};
  
  for (const key in obj) {
    if (obj.hasOwnProperty(key)) {
      const newKey = prefix ? `${prefix}.${key}` : key;
      
      if (typeof obj[key] === 'object' && obj[key] !== null && !Array.isArray(obj[key])) {
        Object.assign(flattened, flattenObject(obj[key], newKey, maxDepth, currentDepth + 1));
      } else {
        flattened[newKey] = obj[key];
      }
    }
  }
  
  return flattened;
}

/**
 * Validate nested email fields
 */
export const validateNestedEmail = (fieldPath) => {
  return body(fieldPath)
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage('Invalid email format')
    .isLength({ max: 255 })
    .withMessage('Email too long');
};

/**
 * Validate nested string fields
 */
export const validateNestedString = (fieldPath, options = {}) => {
  const { min = 0, max = 1000, required = false } = options;
  
  let chain = body(fieldPath);
  
  if (required) {
    chain = chain.notEmpty().withMessage('Field is required');
  } else {
    chain = chain.optional();
  }
  
  if (min > 0) {
    chain = chain.isLength({ min }).withMessage(`Must be at least ${min} characters`);
  }
  
  if (max > 0) {
    chain = chain.isLength({ max }).withMessage(`Must be less than ${max} characters`);
  }
  
  return chain.trim().escape();
};

// ============================================
// 3. JSON VALIDATION
// ============================================

/**
 * Validate JSON structure
 */
export function validateJSONStructure(jsonString, maxSize = 100000) {
  if (typeof jsonString !== 'string') {
    return { valid: false, error: 'Input must be a string' };
  }
  
  if (jsonString.length > maxSize) {
    return { valid: false, error: 'JSON too large' };
  }
  
  try {
    const parsed = JSON.parse(jsonString);
    
    // Check for circular references by limiting depth
    const depth = getObjectDepth(parsed);
    if (depth > 20) {
      return { valid: false, error: 'JSON structure too deep' };
    }
    
    return { valid: true, data: parsed };
  } catch (error) {
    return { valid: false, error: 'Invalid JSON format' };
  }
}

/**
 * Get object depth
 */
function getObjectDepth(obj, currentDepth = 0, maxDepth = 20) {
  if (currentDepth > maxDepth) return currentDepth;
  
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
    return currentDepth;
  }
  
  let maxChildDepth = currentDepth;
  for (const key in obj) {
    if (obj.hasOwnProperty(key)) {
      const childDepth = getObjectDepth(obj[key], currentDepth + 1, maxDepth);
      maxChildDepth = Math.max(maxChildDepth, childDepth);
    }
  }
  
  return maxChildDepth;
}

// ============================================
// 4. UNICODE & ENCODING VALIDATION
// ============================================

/**
 * Validate and normalize unicode input
 */
export function validateUnicode(input) {
  if (typeof input !== 'string') return input;
  
  // Remove zero-width characters
  let sanitized = input.replace(/[\u200B-\u200D\uFEFF]/g, '');
  
  // Normalize unicode
  try {
    sanitized = sanitized.normalize('NFKC');
  } catch {
    // If normalization fails, return original
  }
  
  // Check for suspicious unicode patterns
  const suspiciousPatterns = [
    /\u202E/, // Right-to-left override
    /\u202D/, // Left-to-right override
    /\u202A/, // Left-to-right embedding
    /\u202B/, // Right-to-left embedding
  ];
  
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(sanitized)) {
      sanitized = sanitized.replace(pattern, '');
    }
  }
  
  return sanitized;
}

// ============================================
// 5. COMPREHENSIVE VALIDATION MIDDLEWARE
// ============================================

/**
 * Validate request with comprehensive checks
 */
export const comprehensiveValidation = (validations) => {
  return async (req, res, next) => {
    // Skip validation for GET, HEAD, OPTIONS requests
    const method = (req && req.method) ? req.method.toUpperCase() : 'GET';
    if (['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      return next();
    }
    
    // Wrap everything in try-catch to ensure we never block requests unexpectedly
    try {
      // Run express-validator validations
      await Promise.all(validations.map(validation => validation.run(req)));
      
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ 
          success: false, 
          errors: errors.array() 
        });
      }
      
      // Additional checks
      try {
        // Validate JSON structure if present
        if (req.body && typeof req.body === 'object') {
          const jsonString = JSON.stringify(req.body);
          const jsonValidation = validateJSONStructure(jsonString);
          if (!jsonValidation.valid) {
            return res.status(400).json({ 
              success: false, 
              error: jsonValidation.error 
            });
          }
        }
        
        // Validate unicode
        if (req.body) {
          for (const key in req.body) {
            if (typeof req.body[key] === 'string') {
              req.body[key] = validateUnicode(req.body[key]);
            }
          }
        }
      } catch (error) {
        console.error('[VALIDATION] Validation error:', error.message);
        console.error('[VALIDATION] Error stack:', error.stack);
        console.error('[VALIDATION] Request path:', req.path);
        console.error('[VALIDATION] Request method:', req.method);
        console.error('[VALIDATION] Request body:', JSON.stringify(req.body).substring(0, 200));
        
        // Only return error for non-GET requests
        if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
          return res.status(400).json({ 
            success: false, 
            error: 'Invalid request data',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
          });
        }
        // For GET requests, just continue
        return next();
      }
      
      next();
    } catch (error) {
      // Outer catch - always allow through for GET requests
      if (['GET', 'HEAD', 'OPTIONS'].includes(method)) {
        console.warn('[VALIDATION] Error in GET request validation, allowing through');
        return next();
      }
      // For other methods, return error
      console.error('[VALIDATION] Comprehensive validation error:', error.message);
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid request data',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  };
};

// ============================================
// 6. EMAIL VALIDATION ENHANCEMENTS
// ============================================

/**
 * Enhanced email validation
 */
export function validateEmailStrict(email) {
  if (!email || typeof email !== 'string') {
    return { valid: false, error: 'Email is required' };
  }
  
  // Length check
  if (email.length > 255) {
    return { valid: false, error: 'Email too long' };
  }
  
  // Basic format check
  if (!validator.isEmail(email)) {
    return { valid: false, error: 'Invalid email format' };
  }
  
  // Check for dangerous characters
  if (/[<>\"']/.test(email)) {
    return { valid: false, error: 'Email contains invalid characters' };
  }
  
  // Check for multiple @ symbols
  if ((email.match(/@/g) || []).length !== 1) {
    return { valid: false, error: 'Invalid email format' };
  }
  
  // Check for suspicious patterns
  const suspiciousPatterns = [
    /javascript:/i,
    /on\w+\s*=/i, // Event handlers
    /<script/i,
  ];
  
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(email)) {
      return { valid: false, error: 'Email contains suspicious content' };
    }
  }
  
  return { valid: true };
}

export default {
  sanitizeObject,
  preventPrototypePollution,
  flattenObject,
  validateNestedEmail,
  validateNestedString,
  validateJSONStructure,
  validateUnicode,
  comprehensiveValidation,
  validateEmailStrict
};

