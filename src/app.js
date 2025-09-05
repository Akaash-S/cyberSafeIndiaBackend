const express = require('express');
const morgan = require('morgan');
const helmet = require('helmet');
const cors = require('cors');
require('dotenv').config();

// Import middleware
const {
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
} = require('./middleware/securityMiddleware');

// Import routes
const userRoutes = require('./routes/userRoutes');
const scanRoutes = require('./routes/scanRoutes');
const historyRoutes = require('./routes/historyRoutes');
const reportRoutes = require('./routes/reportRoutes');
const analyticsRoutes = require('./routes/analyticsRoutes');
const adminRoutes = require('./routes/adminRoutes');
const reputationRoutes = require('./routes/reputationRoutes');
const notificationRoutes = require('./routes/notificationRoutes');

// Create Express app
const app = express();

// Trust proxy for accurate IP addresses
app.set('trust proxy', 1);

// Security middleware
app.use(helmet(helmetOptions));
app.use(cors(corsOptions));

// Request logging
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('combined'));
}
app.use(requestLogger);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health check endpoint (no rate limiting)
app.get('/health', healthCheck);

// API documentation endpoint
app.get('/api', (req, res) => {
  res.json({
    success: true,
    message: 'CyberSafe India API',
    version: '1.0.0',
    endpoints: {
      user: {
        'POST /api/user/register': 'Register user after Firebase auth',
        'GET /api/user/profile': 'Get user profile (authenticated)',
        'PUT /api/user/profile': 'Update user profile (authenticated)'
      },
      scan: {
        'POST /api/scan': 'Scan a single URL',
        'POST /api/scan/batch': 'Scan multiple URLs (authenticated)'
      },
      history: {
        'GET /api/history': 'Get scan history (authenticated)',
        'GET /api/history/stats': 'Get scan statistics (authenticated)',
        'DELETE /api/history/:id': 'Delete specific scan (authenticated)',
        'DELETE /api/history': 'Delete all scans (authenticated)',
        'GET /api/history/export': 'Export scan history as CSV (authenticated)'
      },
      reports: {
        'POST /api/report': 'Submit suspicious URL report (authenticated)',
        'GET /api/reports': 'Get all reports (admin only)',
        'PUT /api/reports/:id/status': 'Update report status (admin only)',
        'DELETE /api/reports/:id': 'Delete report (admin only)',
        'GET /api/reports/stats': 'Get report statistics (admin only)',
        'GET /api/reports/my': 'Get user\'s reports (authenticated)'
      },
      reputation: {
        'POST /api/reputation/check': 'Check URL reputation in community database',
        'POST /api/reputation/report-threat': 'Report URL as threat (authenticated)',
        'POST /api/reputation/report-safe': 'Report URL as safe (authenticated)',
        'GET /api/reputation/stats': 'Get reputation statistics'
      },
      analytics: {
        'GET /api/analytics/overview': 'Get analytics overview (authenticated)',
        'GET /api/analytics/trends': 'Get scan trends (authenticated)',
        'GET /api/analytics/threats': 'Get threat analysis (authenticated)',
        'GET /api/analytics/admin': 'Get admin analytics (admin only)',
        'GET /api/analytics/export': 'Export analytics data (authenticated)'
      },
      admin: {
        'GET /api/admin/users': 'Get all users (admin only)',
        'GET /api/admin/user/:id': 'Get user details (admin only)',
        'DELETE /api/admin/user/:id': 'Delete user (admin only)',
        'GET /api/admin/system': 'Get system information (admin only)',
        'GET /api/admin/flagged': 'Get flagged content (admin only)',
        'POST /api/admin/maintenance': 'Perform maintenance (admin only)'
      }
    },
    authentication: {
      type: 'Bearer Token (Base64 encoded user data)',
      header: 'Authorization: Bearer <base64_encoded_user_data>',
      note: 'Frontend handles Firebase auth and sends user data to backend. Most endpoints require authentication. Admin endpoints require admin role.'
    }
  });
});

// Apply rate limiting to all routes
app.use(generalLimiter);

// API routes with specific rate limiting
app.use('/api/user', userRoutes);
app.use('/api/scan', scanLimiter, scanRoutes);
app.use('/api/history', historyRoutes);
app.use('/api/report', reportLimiter, reportRoutes);
app.use('/api/reports', reportLimiter, reportRoutes);
app.use('/api/reputation', reportLimiter, reputationRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/admin', adminLimiter, adminRoutes);
app.use('/api/notifications', notificationRoutes);

// 404 handler for undefined routes
app.use(notFoundHandler);

// Global error handler
app.use(errorHandler);

module.exports = app;
