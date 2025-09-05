const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');

// Rate limiting configurations
const createRateLimit = (windowMs, max, message) => {
  return rateLimit({
    windowMs,
    max,
    message: {
      success: false,
      error: message || 'Too many requests, please try again later'
    },
    standardHeaders: true,
    legacyHeaders: false,
  });
};

// General API rate limiting
const generalLimiter = createRateLimit(
  15 * 60 * 1000, // 15 minutes
  100, // 100 requests per window
  'Too many requests from this IP, please try again later'
);

// Scan API rate limiting (more restrictive)
const scanLimiter = createRateLimit(
  15 * 60 * 1000, // 15 minutes
  20, // 20 scan requests per window
  'Too many scan requests, please try again later'
);

// Report API rate limiting
const reportLimiter = createRateLimit(
  60 * 60 * 1000, // 1 hour
  10, // 10 reports per hour
  'Too many reports submitted, please try again later'
);

// Admin API rate limiting
const adminLimiter = createRateLimit(
  15 * 60 * 1000, // 15 minutes
  200, // 200 admin requests per window
  'Too many admin requests, please try again later'
);

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      process.env.FRONTEND_URL,
      process.env.EXTENSION_URL,
      'https://cybersafe-india.vercel.app', // Production frontend
      'http://localhost:5173', // Vite dev server
      'http://localhost:3000', // Alternative dev server
      'chrome-extension://*' // Browser extensions
    ];

    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);

    // Check if origin is allowed
    const isAllowed = allowedOrigins.some(allowedOrigin => {
      if (allowedOrigin.includes('*')) {
        return origin.startsWith(allowedOrigin.replace('*', ''));
      }
      return origin === allowedOrigin;
    });

    if (isAllowed) {
      callback(null, true);
    } else {
      console.warn(`CORS blocked request from origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  optionsSuccessStatus: 200
};

// Helmet security configuration
const helmetOptions = {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://www.virustotal.com", "https://api.abuseipdb.com", "https://accounts.google.com", "https://securetoken.googleapis.com"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'self'", "https://accounts.google.com"],
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: "unsafe-none" }, // Allow popup communication
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
};

// Request logging middleware
const requestLogger = (req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logData = {
      method: req.method,
      url: req.url,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString()
    };

    // Log errors and slow requests
    if (res.statusCode >= 400 || duration > 5000) {
      console.warn('Request warning:', logData);
    } else {
      console.log('Request:', logData);
    }
  });

  next();
};

// Error handling middleware
const errorHandler = (err, req, res, next) => {
  console.error('Error:', err);

  // CORS error
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({
      success: false,
      error: true,
      message: 'CORS policy violation'
    });
  }

  // Rate limit error
  if (err.status === 429) {
    return res.status(429).json({
      success: false,
      error: true,
      message: 'Too many requests, please try again later'
    });
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      error: true,
      message: 'Invalid token'
    });
  }

  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      success: false,
      error: true,
      message: 'Token expired'
    });
  }

  // Validation errors
  if (err.isJoi) {
    return res.status(400).json({
      success: false,
      error: true,
      message: err.details[0].message
    });
  }

  // Database errors
  if (err.code && err.code.startsWith('23')) {
    return res.status(400).json({
      success: false,
      error: true,
      message: 'Database constraint violation'
    });
  }

  // Default error
  res.status(500).json({
    success: false,
    error: true,
    message: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message
  });
};

// 404 handler
const notFoundHandler = (req, res) => {
  res.status(404).json({
    success: false,
    error: true,
    message: 'API endpoint not found',
    path: req.originalUrl
  });
};

// Health check middleware
const healthCheck = (req, res) => {
  res.json({
    success: true,
    message: 'CyberSafe India API is running',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
};

module.exports = {
  generalLimiter,
  scanLimiter,
  reportLimiter,
  adminLimiter,
  corsOptions,
  helmetOptions,
  requestLogger,
  errorHandler,
  notFoundHandler,
  healthCheck
};
