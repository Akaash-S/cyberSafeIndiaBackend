// Production configuration for Render deployment
require('dotenv').config();

const productionConfig = {
  // Server configuration
  port: process.env.PORT || 5000,
  nodeEnv: process.env.NODE_ENV || 'production',
  
  // Database configuration
  database: {
    url: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 20, // Maximum number of clients in the pool
    idleTimeoutMillis: 30000, // Close idle clients after 30 seconds
    connectionTimeoutMillis: 2000, // Return an error after 2 seconds if connection could not be established
  },
  
  // API Keys
  apiKeys: {
    virusTotal: process.env.VIRUSTOTAL_API_KEY,
    abuseIpDb: process.env.ABUSEIPDB_API_KEY,
  },
  
  // CORS configuration
  cors: {
    origin: [
      process.env.FRONTEND_URL,
      process.env.EXTENSION_URL,
      'https://cybersafe-india.vercel.app', // Your production frontend
      'http://localhost:5173', // Development
      'http://localhost:3000', // Alternative development
    ].filter(Boolean), // Remove undefined values
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  },
  
  // Rate limiting configuration
  rateLimiting: {
    general: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // 100 requests per window
    },
    scan: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 20, // 20 scan requests per window
    },
    report: {
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 10, // 10 reports per hour
    },
    admin: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 200, // 200 admin requests per window
    },
  },
  
  // Security configuration
  security: {
    helmet: {
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: [
            "'self'",
            "https://www.virustotal.com",
            "https://api.abuseipdb.com",
            "https://accounts.google.com",
            "https://securetoken.googleapis.com"
          ],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'self'", "https://accounts.google.com"],
        },
      },
      crossOriginEmbedderPolicy: false,
      crossOriginOpenerPolicy: { policy: "unsafe-none" },
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
      },
    },
  },
  
  // Logging configuration
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    format: process.env.NODE_ENV === 'production' ? 'combined' : 'dev',
  },
  
  // Health check configuration
  healthCheck: {
    timeout: 5000, // 5 seconds
    interval: 30000, // 30 seconds
  },
};

// Validation
const requiredEnvVars = [
  'DATABASE_URL',
  'VIRUSTOTAL_API_KEY',
  'ABUSEIPDB_API_KEY',
];

const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingEnvVars);
  console.error('Please set these environment variables in your Render dashboard');
  process.exit(1);
}

module.exports = productionConfig;
