// middleware/security.js
import rateLimit from 'express-rate-limit';
import csrf from 'csurf';

// Rate limiting for login endpoints
export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: 'Too many login attempts from this IP, please try again after 15 minutes.',
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Don't count successful requests
});

// Rate limiting for API endpoints
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiting for password reset/OTP requests
export const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 attempts per hour
  message: 'Too many password reset attempts, please try again after 1 hour.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiting for write operations (POST/PUT/DELETE)
export const writeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // 50 write operations per 15 minutes
  message: 'Too many write operations, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// CSRF protection middleware
// Note: csurf requires express-session (which we have)
// Create CSRF protection instance
// ignoreMethods tells csurf to skip validation on these methods
// but it will still generate tokens on GET requests
const csrfMiddleware = csrf({ 
  cookie: false, // We're using sessions, not cookies for CSRF
  ignoreMethods: ['GET', 'HEAD', 'OPTIONS'] // Don't validate on these methods
});

// CSRF token rotation - invalidate old tokens after sensitive operations
let csrfTokenRotationTime = new Map(); // Track when tokens were last rotated

// Cleanup function to remove expired session entries from the Map
// Sessions expire after 24 hours (86400000ms), so we clean up entries older than session max age
const cleanupExpiredRotationTimes = () => {
  const now = Date.now();
  const sessionMaxAge = 86400000; // 24 hours in milliseconds (matches session cookie maxAge)
  // Clean up entries older than session max age (sessions are already expired)
  
  let cleanedCount = 0;
  for (const [sessionId, rotationTime] of csrfTokenRotationTime.entries()) {
    if (now - rotationTime > sessionMaxAge) {
      csrfTokenRotationTime.delete(sessionId);
      cleanedCount++;
    }
  }
  
  if (cleanedCount > 0) {
    console.log(`[CSRF Cleanup] Removed ${cleanedCount} expired rotation time entries`);
  }
  
  // Also limit Map size to prevent unbounded growth (keep only last 10,000 entries)
  // This protects against memory exhaustion attacks
  if (csrfTokenRotationTime.size > 10000) {
    // Remove oldest entries (entries with smallest timestamps)
    const entries = Array.from(csrfTokenRotationTime.entries())
      .sort((a, b) => a[1] - b[1]); // Sort by timestamp
    const toRemove = entries.slice(0, csrfTokenRotationTime.size - 10000);
    toRemove.forEach(([sessionId]) => csrfTokenRotationTime.delete(sessionId));
    console.log(`[CSRF Cleanup] Removed ${toRemove.length} oldest entries to limit Map size`);
  }
};

// Run cleanup every 15 minutes to prevent memory leak and match session expiration
setInterval(cleanupExpiredRotationTimes, 900000); // 15 minutes

// Helper to get CSRF token for views - makes token available in all views
// Must be called AFTER csrfMiddleware has run
export const getCsrfToken = (req, res, next) => {
  // Skip for API endpoints
  if (req.path.startsWith('/api/')) {
    res.locals.csrfToken = null;
    return next();
  }
  
  // Rotate CSRF token after sensitive operations (login, password change, etc.)
  const sessionId = req.sessionID;
  const lastRotation = csrfTokenRotationTime.get(sessionId);
  // Only calculate time since rotation if the session has been rotated before
  // New sessions (lastRotation === undefined) should not trigger rotation
  const timeSinceRotation = lastRotation !== undefined ? Date.now() - lastRotation : 0;
  
  // Extract token if available (will be set by csrfMiddleware for GET requests)
  // Do this BEFORE any rotation logic to ensure we can generate tokens
  let csrfTokenValue = null;
  if (req.csrfToken && typeof req.csrfToken === 'function') {
    try {
      csrfTokenValue = req.csrfToken();
    } catch (err) {
      console.warn('Failed to get CSRF token:', err.message);
      csrfTokenValue = null;
    }
  }
  
  // Rotate token if it's been more than 1 hour AND the session has been rotated before
  // Note: We don't rotate on /login or /password paths here because that would
  // break token generation on GET requests. Rotation should happen AFTER successful
  // login/password change (handled by rotateCsrfToken() function called from route handlers)
  // Only rotate based on time, not on path patterns
  // Only rotate if lastRotation is defined (session has been rotated before)
  if (lastRotation !== undefined && timeSinceRotation > 3600000) {
    if (req.session && req.session.csrfSecret) {
      // Regenerate CSRF secret to invalidate old tokens
      delete req.session.csrfSecret;
      csrfTokenRotationTime.set(sessionId, Date.now());
      
      // Immediately regenerate the secret so we can generate a new token for this request
      // This prevents null tokens from being passed to views
      if (req.csrfToken && typeof req.csrfToken === 'function') {
        try {
          // csrfMiddleware will automatically create a new secret when csrfToken() is called
          csrfTokenValue = req.csrfToken();
        } catch (err) {
          console.warn('Failed to regenerate CSRF token after rotation:', err.message);
          csrfTokenValue = null;
        }
      }
    }
  }
  
  // Run cleanup on every request to prevent unbounded growth
  // This is lightweight (O(n) where n is number of entries) and prevents memory exhaustion attacks
  cleanupExpiredRotationTimes();
  
  res.locals.csrfToken = csrfTokenValue;
  
  next();
};

// Function to force CSRF token rotation (call after sensitive operations)
export const rotateCsrfToken = (req) => {
  if (req.session && req.session.csrfSecret) {
    delete req.session.csrfSecret;
    csrfTokenRotationTime.set(req.sessionID, Date.now());
  }
};

// CSRF protection wrapper - this is now a no-op since csrfMiddleware is applied globally
// Kept for backwards compatibility with existing route code
// The actual validation is handled by the global csrfMiddleware
export const csrfProtection = (req, res, next) => {
  // CSRF validation is already handled globally by csrfMiddleware
  // This middleware is kept for backwards compatibility but doesn't do anything
  next();
};

// Export the main CSRF middleware for global application
// This should be applied globally AFTER session middleware
// It will generate tokens on GET requests and validate on POST/PUT/DELETE/PATCH
export { csrfMiddleware };

