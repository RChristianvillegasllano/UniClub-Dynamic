import express from "express";
import dotenv from "dotenv";
import session from "express-session";
import helmet from "helmet";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import pool from "./config/db.js";
import { csrfProtection, getCsrfToken, csrfMiddleware } from "./middleware/security.js";
import { 
  sanitizeRequest, 
  securityHeaders, 
  auditLog, 
  checkIPBlacklist,
  validateRequestSize 
} from "./middleware/advancedSecurity.js";
import { preventPrototypePollution } from "./middleware/inputValidation.js";
import { requestLogger } from "./config/logging.js";
import requirementsRoutes from "./routes/requirementsRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";
import apiRoutes from "./routes/apiRoutes.js";
import officerAuthRoutes from "./routes/officerAuthRoutes.js";
import officerDashboardRoutes from "./routes/officerDashboardRoutes.js";
import officerApiRoutes from "./routes/officerApiRoutes.js";
import studentRoutes from "./routes/studentRoutes.js";

dotenv.config();

// Validate required environment variables
const requiredEnvVars = ['SESSION_SECRET'];
const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingVars.join(', '));
  console.error('⚠️  Please set these in your .env file before running the application');
  if (process.env.NODE_ENV === 'production') {
    process.exit(1);
  }
}

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';

// ESM-friendly __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Security Headers (Helmet)
// In development, use less strict settings to avoid issues
app.use(helmet({
  contentSecurityPolicy: isProduction ? {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline styles for EJS templates
      scriptSrc: ["'self'", "'unsafe-inline'"], // Allow inline scripts for EJS templates
      imgSrc: ["'self'", "data:", "https:"],
      fontSrc: ["'self'", "data:", "https:"],
    },
  } : false, // Disable CSP in development to avoid issues
  crossOriginEmbedderPolicy: false, // Disable if causing issues with external resources
  hsts: isProduction ? {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  } : false, // Disable HSTS in development (forces HTTPS)
}));

// CORS Configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : (isProduction ? [] : ['http://localhost:3000']);

app.use('/api', cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, Postman, etc.) in development
    if (!origin && !isProduction) {
      return callback(null, true);
    }
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Enforce HTTPS in production only
// Disabled in development to allow HTTP access
if (isProduction) {
  app.use((req, res, next) => {
    // Only redirect if we're behind a proxy that indicates HTTP
    const forwardedProto = req.header('x-forwarded-proto');
    if (forwardedProto && forwardedProto !== 'https') {
      return res.redirect(`https://${req.header('host')}${req.url}`);
    }
    next();
  });
}

// Views + static
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));

// Advanced Security Headers
app.use(securityHeaders);

// IP Blacklist Check
app.use(checkIPBlacklist);

// Request Size Validation
app.use(validateRequestSize(10 * 1024 * 1024)); // 10MB max

// Body parsers with size limits
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.json({ limit: '10mb' }));

// Prototype Pollution Protection - Must come before sanitization
// Temporarily disabled to debug issue - will re-enable after fixing
// app.use(preventPrototypePollution);

// Input Sanitization - Must come after body parsers
// Temporarily disabled to debug issue - will re-enable after fixing
// app.use(sanitizeRequest);

// Request Logging
app.use(requestLogger);

// Audit Logging
app.use(auditLog);

// Session Configuration
const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret && isProduction) {
  throw new Error('SESSION_SECRET environment variable is required in production');
}

app.use(
  session({
    secret: sessionSecret || "change-me-development-only",
    resave: false, // Changed to false - only save if session was modified
    saveUninitialized: true, // Keep true so session is created for CSRF token generation
    name: 'sessionId', // Don't use default 'connect.sid'
    cookie: { 
      httpOnly: true, 
      sameSite: isProduction ? "strict" : "lax",
      secure: isProduction, // true in production (requires HTTPS)
      maxAge: 86400000 // 24 hours
    },
    // Don't regenerate session ID on login - this breaks CSRF tokens
    rolling: false, // Don't reset expiration on every request
  })
);

// CSRF Protection - Apply globally (but skip API endpoints)
// This must come AFTER session middleware
// The middleware will generate tokens on GET requests and validate on POST/PUT/DELETE/PATCH
app.use((req, res, next) => {
  // Skip CSRF for API endpoints
  if (req.path.startsWith('/api/')) {
    return next();
  }
  
  // Skip CSRF for JSON PUT requests to status update endpoint (handled manually in route)
  if (req.method === 'PUT' && req.path.includes('/events/') && req.path.includes('/status') && req.headers['content-type'] && req.headers['content-type'].includes('application/json')) {
    return next();
  }
  
  // Skip CSRF for multipart/form-data routes (multer will handle parsing, then we validate manually)
  if (req.headers['content-type'] && req.headers['content-type'].includes('multipart/form-data')) {
    // Skip validation here - will be validated after multer parses the form
    return next();
  }
  
  // Temporarily disable CSRF in development if CSRF_DISABLED env var is set
  if (process.env.NODE_ENV !== 'production' && process.env.CSRF_DISABLED === 'true') {
    return next();
  }
  
  // Apply CSRF middleware - it will generate tokens on GET and validate on POST/PUT/DELETE/PATCH
  // ignoreMethods ensures it won't validate on GET/HEAD/OPTIONS
  return csrfMiddleware(req, res, (err) => {
    if (err) {
      // CSRF validation failed (only happens on POST/PUT/DELETE/PATCH)
      console.error('CSRF validation error:', err.message);
      console.error('Request path:', req.path);
      console.error('Request method:', req.method);
      console.error('CSRF token received:', (req.body && req.body._csrf) ? 'present' : 'missing');
      if (req.body && req.body._csrf) {
        console.error('CSRF token value (first 20 chars):', req.body._csrf.substring(0, 20) + '...');
      }
      console.error('Session ID:', req.sessionID);
      console.error('Session secret exists:', !!req.session?.csrfSecret);
      if (req.session?.csrfSecret) {
        console.error('Session secret value (first 20 chars):', req.session.csrfSecret.substring(0, 20) + '...');
      }
      
      // For login routes, redirect back to login with error instead of showing error page
      if (req.path === '/admin/login' && req.method === 'POST') {
        return res.redirect('/admin/login?error=csrf_invalid');
      }
      
      if (req.path === '/student/login' && req.method === 'POST') {
        return res.redirect('/student/login?error=csrf_invalid');
      }
      
      if (req.method === 'POST') {
        // For POST requests, render error page with helpful message
        return res.status(403).render('errors/500', {
          title: 'Forbidden',
          error: 'Invalid security token. This usually happens if the page was open for too long. Please refresh the page and try again.',
          stack: process.env.NODE_ENV === 'development' ? err.stack : null
        });
      }
      return next(err);
    }
    next();
  });
});

// Extract CSRF token for views (must come after csrfMiddleware)
app.use(getCsrfToken); // Make CSRF token available to all views

// Routes
app.use("/requirements", requirementsRoutes);
app.use("/admin", adminRoutes);
app.use("/api", apiRoutes);
app.use("/officer", officerAuthRoutes);
app.use("/officer", officerDashboardRoutes);
app.use("/api/officer", officerApiRoutes);
app.use("/student", studentRoutes);

// Root - Landing page with statistics
app.get("/", async (req, res) => {
  try {
    // Fetch statistics
    const [
      studentsCount,
      clubsCount,
      eventsCount,
    ] = await Promise.all([
      pool.query("SELECT COUNT(*) AS count FROM students").catch(() => ({ rows: [{ count: 0 }] })),
      pool.query("SELECT COUNT(*) AS count FROM clubs").catch(() => ({ rows: [{ count: 0 }] })),
      pool.query("SELECT COUNT(*) AS count FROM events").catch(() => ({ rows: [{ count: 0 }] })),
    ]);

    res.render("index", {
      title: "UniClub • University of Mindanao",
      stats: {
        students: Number(studentsCount.rows[0]?.count || 0),
        clubs: Number(clubsCount.rows[0]?.count || 0),
        events: Number(eventsCount.rows[0]?.count || 0),
      },
    });
  } catch (error) {
    console.error("Error loading landing page stats:", error);
    // Render with default values on error
    res.render("index", {
      title: "UniClub • University of Mindanao",
      stats: { students: 0, clubs: 0, events: 0 },
    });
  }
});

// 404
app.use((req, res) => res.status(404).render("errors/404", { title: "Not Found" }));

// Error handler
app.use((err, req, res, _next) => {
  console.error('Error:', err);
  
  // Don't expose error details in production
  const errorMessage = isProduction 
    ? 'An internal server error occurred. Please try again later.' 
    : err.message;
  
  const errorDetails = isProduction ? null : err.stack;
  
  res.status(err.status || 500).render("errors/500", { 
    title: "Server Error", 
    error: errorMessage,
    stack: errorDetails
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`⚠️  Make sure you access: http://localhost:${PORT} (NOT https://)`);
  if (isProduction) {
    console.log(`🔒 Production mode: HTTPS required`);
  } else {
    console.log(`🔓 Development mode: HTTP is allowed`);
  }
});
