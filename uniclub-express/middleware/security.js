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

// Helper to get CSRF token for views - makes token available in all views
// Must be called AFTER csrfMiddleware has run
export const getCsrfToken = (req, res, next) => {
  // Skip for API endpoints
  if (req.path.startsWith('/api/')) {
    res.locals.csrfToken = null;
    return next();
  }
  
  // Extract token if available (will be set by csrfMiddleware for GET requests)
  if (req.csrfToken && typeof req.csrfToken === 'function') {
    try {
      res.locals.csrfToken = req.csrfToken();
    } catch (err) {
      console.warn('Failed to get CSRF token:', err.message);
      res.locals.csrfToken = null;
    }
  } else {
    res.locals.csrfToken = null;
  }
  
  next();
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

