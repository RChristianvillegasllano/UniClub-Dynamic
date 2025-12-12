# CSRF Protection Migration Guide

## Current Status
Currently using `csurf` package which has dependency vulnerabilities related to the `cookie` package.

## Migration Options

### Option A: Switch to `csrf` Package (Recommended)
**Pros:**
- Actively maintained
- No dependency vulnerabilities
- Similar API to csurf
- Better TypeScript support

**Cons:**
- Requires code changes
- Need to test thoroughly

### Option B: Wait for csurf Patch
**Pros:**
- Minimal code changes
- Keep existing implementation

**Cons:**
- Unknown timeline for patch
- May have other vulnerabilities

### Option C: Double-Submit Cookie Pattern
**Pros:**
- No external dependencies
- Full control over implementation

**Cons:**
- More code to maintain
- Need to implement correctly

## Recommended: Option A - Switch to `csrf`

### Step 1: Install New Package
```bash
npm uninstall csurf
npm install csrf
```

### Step 2: Update `middleware/security.js`

**Current Code:**
```javascript
import csrf from 'csurf';

const csrfMiddleware = csrf({ 
  cookie: false,
  ignoreMethods: ['GET', 'HEAD', 'OPTIONS']
});
```

**New Code:**
```javascript
import Tokens from 'csrf';

const tokens = new Tokens();

const csrfMiddleware = (req, res, next) => {
  // Skip for API endpoints
  if (req.path.startsWith('/api/')) {
    return next();
  }
  
  // Skip for GET, HEAD, OPTIONS
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    // Generate token for GET requests
    if (!req.session.csrfSecret) {
      req.session.csrfSecret = tokens.secretSync();
    }
    req.csrfToken = () => tokens.create(req.session.csrfSecret);
    return next();
  }
  
  // Validate token for POST, PUT, DELETE, PATCH
  const secret = req.session.csrfSecret;
  const token = req.body._csrf || req.headers['x-csrf-token'];
  
  if (!secret || !token) {
    return res.status(403).json({ error: 'CSRF token missing' });
  }
  
  if (!tokens.verify(secret, token)) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  
  next();
};
```

### Step 3: Update `getCsrfToken` Helper

**Current Code:**
```javascript
export const getCsrfToken = (req, res, next) => {
  if (req.path.startsWith('/api/')) {
    res.locals.csrfToken = null;
    return next();
  }
  
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
```

**New Code:**
```javascript
export const getCsrfToken = (req, res, next) => {
  if (req.path.startsWith('/api/')) {
    res.locals.csrfToken = null;
    return next();
  }
  
  // Ensure secret exists
  if (!req.session.csrfSecret) {
    req.session.csrfSecret = tokens.secretSync();
  }
  
  // Generate token
  try {
    res.locals.csrfToken = tokens.create(req.session.csrfSecret);
  } catch (err) {
    console.warn('Failed to get CSRF token:', err.message);
    res.locals.csrfToken = null;
  }
  
  next();
};
```

### Step 4: Test
1. Test all forms submit correctly
2. Test CSRF token validation
3. Test token rotation
4. Test error handling

### Step 5: Update Documentation
- Update SECURITY.md
- Update deployment checklist
- Document migration in changelog

## Alternative: Option C - Double-Submit Cookie

If you prefer not to use external packages:

```javascript
import crypto from 'crypto';

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function setCsrfCookie(req, res, next) {
  if (!req.cookies.csrfToken) {
    const token = generateToken();
    res.cookie('csrfToken', token, {
      httpOnly: false, // Must be readable by JavaScript
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    req.csrfToken = token;
  } else {
    req.csrfToken = req.cookies.csrfToken;
  }
  next();
}

function validateCsrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  
  const cookieToken = req.cookies.csrfToken;
  const bodyToken = req.body._csrf;
  
  if (!cookieToken || !bodyToken) {
    return res.status(403).json({ error: 'CSRF token missing' });
  }
  
  if (cookieToken !== bodyToken) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  
  next();
}
```

## Migration Checklist

- [ ] Choose migration option
- [ ] Install new package (if Option A)
- [ ] Update middleware code
- [ ] Test all forms
- [ ] Test API endpoints
- [ ] Test error handling
- [ ] Update documentation
- [ ] Deploy to staging
- [ ] Test in staging
- [ ] Deploy to production
- [ ] Monitor for issues

## Rollback Plan

If issues occur:
1. Revert to previous version
2. Reinstall csurf
3. Restore original middleware
4. Investigate issues
5. Plan new migration attempt

