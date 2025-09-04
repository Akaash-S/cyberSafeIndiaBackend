const express = require('express');
const Joi = require('joi');
const { requireAdmin } = require('../middleware/authMiddleware');
const { pool } = require('../config/db');

const router = express.Router();

// Validation schemas
const paginationSchema = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20),
  sortBy: Joi.string().valid('created_at', 'last_login', 'email', 'display_name').default('created_at'),
  sortOrder: Joi.string().valid('asc', 'desc').default('desc')
});

const userActionSchema = Joi.object({
  action: Joi.string().valid('suspend', 'activate', 'delete').required(),
  reason: Joi.string().max(500).optional()
});

// GET /api/admin/users - Get all users (admin only)
router.get('/admin/users', requireAdmin, async (req, res) => {
  try {
    // Validate query parameters
    const { error, value } = paginationSchema.validate(req.query);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message
      });
    }

    const { page, limit, sortBy, sortOrder } = value;
    const offset = (page - 1) * limit;

    // Build query
    const query = `
      SELECT 
        u.id,
        u.email,
        u.display_name,
        u.created_at,
        u.last_login,
        COUNT(s.id) as scan_count,
        COUNT(r.id) as report_count,
        COUNT(CASE WHEN s.status = 'malicious' THEN 1 END) as malicious_scans
      FROM users u
      LEFT JOIN scans s ON u.id = s.user_id
      LEFT JOIN reports r ON u.id = r.user_id
      GROUP BY u.id, u.email, u.display_name, u.created_at, u.last_login
      ORDER BY u.${sortBy} ${sortOrder.toUpperCase()}
      LIMIT $1 OFFSET $2
    `;

    const result = await pool.query(query, [limit, offset]);

    // Get total count
    const countResult = await pool.query('SELECT COUNT(*) FROM users');
    const totalCount = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(totalCount / limit);

    // Format response
    const users = result.rows.map(row => ({
      id: row.id,
      email: row.email,
      displayName: row.display_name,
      createdAt: row.created_at,
      lastLogin: row.last_login,
      stats: {
        scanCount: parseInt(row.scan_count),
        reportCount: parseInt(row.report_count),
        maliciousScans: parseInt(row.malicious_scans)
      }
    }));

    res.json({
      success: true,
      data: {
        users: users,
        pagination: {
          currentPage: page,
          totalPages: totalPages,
          totalCount: totalCount,
          limit: limit,
          hasNext: page < totalPages,
          hasPrev: page > 1
        }
      }
    });

  } catch (error) {
    console.error('Admin users fetch error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch users'
    });
  }
});

// GET /api/admin/user/:id - Get specific user details (admin only)
router.get('/admin/user/:id', requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;

    // Get user details
    const userQuery = `
      SELECT 
        u.id,
        u.email,
        u.display_name,
        u.created_at,
        u.last_login
      FROM users u
      WHERE u.id = $1
    `;

    const userResult = await pool.query(userQuery, [userId]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    const user = userResult.rows[0];

    // Get user's recent scans
    const scansQuery = `
      SELECT 
        id,
        url,
        status,
        scan_date
      FROM scans 
      WHERE user_id = $1 
      ORDER BY scan_date DESC 
      LIMIT 10
    `;

    const scansResult = await pool.query(scansQuery, [userId]);

    // Get user's reports
    const reportsQuery = `
      SELECT 
        id,
        url,
        reason,
        status,
        report_date
      FROM reports 
      WHERE user_id = $1 
      ORDER BY report_date DESC 
      LIMIT 10
    `;

    const reportsResult = await pool.query(reportsQuery, [userId]);

    // Get user statistics
    const statsQuery = `
      SELECT 
        COUNT(s.id) as total_scans,
        COUNT(CASE WHEN s.status = 'malicious' THEN 1 END) as malicious_scans,
        COUNT(CASE WHEN s.status = 'suspicious' THEN 1 END) as suspicious_scans,
        COUNT(CASE WHEN s.status = 'safe' THEN 1 END) as safe_scans,
        COUNT(r.id) as total_reports,
        COUNT(CASE WHEN r.status = 'approved' THEN 1 END) as approved_reports
      FROM users u
      LEFT JOIN scans s ON u.id = s.user_id
      LEFT JOIN reports r ON u.id = r.user_id
      WHERE u.id = $1
      GROUP BY u.id
    `;

    const statsResult = await pool.query(statsQuery, [userId]);
    const stats = statsResult.rows[0];

    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          displayName: user.display_name,
          createdAt: user.created_at,
          lastLogin: user.last_login
        },
        stats: {
          totalScans: parseInt(stats.total_scans),
          maliciousScans: parseInt(stats.malicious_scans),
          suspiciousScans: parseInt(stats.suspicious_scans),
          safeScans: parseInt(stats.safe_scans),
          totalReports: parseInt(stats.total_reports),
          approvedReports: parseInt(stats.approved_reports)
        },
        recentScans: scansResult.rows.map(row => ({
          id: row.id,
          url: row.url,
          status: row.status,
          scanDate: row.scan_date
        })),
        recentReports: reportsResult.rows.map(row => ({
          id: row.id,
          url: row.url,
          reason: row.reason,
          status: row.status,
          reportDate: row.report_date
        }))
      }
    });

  } catch (error) {
    console.error('Admin user details error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch user details'
    });
  }
});

// DELETE /api/admin/user/:id - Delete user (admin only)
router.delete('/admin/user/:id', requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;

    // Check if user exists
    const userCheck = await pool.query('SELECT id FROM users WHERE id = $1', [userId]);
    
    if (userCheck.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Delete user's data (cascade should handle this, but being explicit)
    await pool.query('DELETE FROM scans WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM reports WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM users WHERE id = $1', [userId]);

    res.json({
      success: true,
      message: 'User and all associated data deleted successfully'
    });

  } catch (error) {
    console.error('Admin user deletion error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete user'
    });
  }
});

// GET /api/admin/system - Get system information (admin only)
router.get('/admin/system', requireAdmin, async (req, res) => {
  try {
    // Get system statistics
    const systemStatsQuery = `
      SELECT 
        (SELECT COUNT(*) FROM users) as total_users,
        (SELECT COUNT(*) FROM scans) as total_scans,
        (SELECT COUNT(*) FROM reports) as total_reports,
        (SELECT COUNT(*) FROM scans WHERE scan_date >= NOW() - INTERVAL '24 hours') as scans_today,
        (SELECT COUNT(*) FROM reports WHERE report_date >= NOW() - INTERVAL '24 hours') as reports_today,
        (SELECT COUNT(*) FROM users WHERE last_login >= NOW() - INTERVAL '7 days') as active_users_week,
        (SELECT COUNT(*) FROM users WHERE last_login >= NOW() - INTERVAL '30 days') as active_users_month
    `;

    const systemStatsResult = await pool.query(systemStatsQuery);
    const systemStats = systemStatsResult.rows[0];

    // Get database size information
    const dbSizeQuery = `
      SELECT 
        pg_size_pretty(pg_database_size(current_database())) as database_size,
        pg_size_pretty(pg_total_relation_size('scans')) as scans_table_size,
        pg_size_pretty(pg_total_relation_size('reports')) as reports_table_size,
        pg_size_pretty(pg_total_relation_size('users')) as users_table_size
    `;

    const dbSizeResult = await pool.query(dbSizeQuery);
    const dbSize = dbSizeResult.rows[0];

    // Get recent activity
    const recentActivityQuery = `
      SELECT 
        'scan' as type,
        url as content,
        scan_date as timestamp,
        user_id
      FROM scans 
      WHERE scan_date >= NOW() - INTERVAL '24 hours'
      UNION ALL
      SELECT 
        'report' as type,
        url as content,
        report_date as timestamp,
        user_id
      FROM reports 
      WHERE report_date >= NOW() - INTERVAL '24 hours'
      ORDER BY timestamp DESC
      LIMIT 20
    `;

    const recentActivityResult = await pool.query(recentActivityQuery);

    res.json({
      success: true,
      data: {
        systemStats: {
          totalUsers: parseInt(systemStats.total_users),
          totalScans: parseInt(systemStats.total_scans),
          totalReports: parseInt(systemStats.total_reports),
          scansToday: parseInt(systemStats.scans_today),
          reportsToday: parseInt(systemStats.reports_today),
          activeUsersWeek: parseInt(systemStats.active_users_week),
          activeUsersMonth: parseInt(systemStats.active_users_month)
        },
        databaseSize: {
          totalSize: dbSize.database_size,
          scansTableSize: dbSize.scans_table_size,
          reportsTableSize: dbSize.reports_table_size,
          usersTableSize: dbSize.users_table_size
        },
        recentActivity: recentActivityResult.rows.map(row => ({
          type: row.type,
          content: row.content,
          timestamp: row.timestamp,
          userId: row.user_id
        }))
      }
    });

  } catch (error) {
    console.error('Admin system info error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch system information'
    });
  }
});

// GET /api/admin/flagged - Get flagged URLs and domains (admin only)
router.get('/admin/flagged', requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    // Get most frequently scanned malicious URLs
    const flaggedUrlsQuery = `
      SELECT 
        url,
        COUNT(*) as scan_count,
        COUNT(CASE WHEN status = 'malicious' THEN 1 END) as malicious_count,
        MAX(scan_date) as last_scan,
        ROUND(
          (COUNT(CASE WHEN status = 'malicious' THEN 1 END)::numeric / COUNT(*)) * 100, 
          2
        ) as threat_percentage
      FROM scans 
      WHERE status IN ('malicious', 'suspicious')
      GROUP BY url
      HAVING COUNT(*) >= 2
      ORDER BY malicious_count DESC, scan_count DESC
      LIMIT $1 OFFSET $2
    `;

    const flaggedUrlsResult = await pool.query(flaggedUrlsQuery, [limit, offset]);

    // Get most reported domains
    const flaggedDomainsQuery = `
      SELECT 
        CASE 
          WHEN url LIKE 'http://%' THEN SUBSTRING(url FROM 'http://([^/]+)')
          WHEN url LIKE 'https://%' THEN SUBSTRING(url FROM 'https://([^/]+)')
          ELSE url
        END as domain,
        COUNT(DISTINCT url) as unique_urls,
        COUNT(*) as total_reports,
        COUNT(CASE WHEN status = 'approved' THEN 1 END) as approved_reports
      FROM reports 
      GROUP BY domain
      HAVING COUNT(*) >= 2
      ORDER BY total_reports DESC
      LIMIT 10
    `;

    const flaggedDomainsResult = await pool.query(flaggedDomainsQuery);

    res.json({
      success: true,
      data: {
        flaggedUrls: flaggedUrlsResult.rows.map(row => ({
          url: row.url,
          scanCount: parseInt(row.scan_count),
          maliciousCount: parseInt(row.malicious_count),
          lastScan: row.last_scan,
          threatPercentage: parseFloat(row.threat_percentage)
        })),
        flaggedDomains: flaggedDomainsResult.rows.map(row => ({
          domain: row.domain,
          uniqueUrls: parseInt(row.unique_urls),
          totalReports: parseInt(row.total_reports),
          approvedReports: parseInt(row.approved_reports)
        }))
      }
    });

  } catch (error) {
    console.error('Admin flagged content error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch flagged content'
    });
  }
});

// POST /api/admin/maintenance - Perform maintenance tasks (admin only)
router.post('/admin/maintenance', requireAdmin, async (req, res) => {
  try {
    const { action } = req.body;

    switch (action) {
      case 'cleanup_old_scans':
        // Delete scans older than 1 year
        const result = await pool.query(
          'DELETE FROM scans WHERE scan_date < NOW() - INTERVAL \'1 year\''
        );
        
        res.json({
          success: true,
          message: `Cleaned up ${result.rowCount} old scans`
        });
        break;

      case 'cleanup_old_reports':
        // Delete resolved reports older than 6 months
        const reportsResult = await pool.query(
          'DELETE FROM reports WHERE status IN (\'approved\', \'rejected\') AND report_date < NOW() - INTERVAL \'6 months\''
        );
        
        res.json({
          success: true,
          message: `Cleaned up ${reportsResult.rowCount} old reports`
        });
        break;

      case 'vacuum_database':
        // Vacuum database tables
        await pool.query('VACUUM ANALYZE scans');
        await pool.query('VACUUM ANALYZE reports');
        await pool.query('VACUUM ANALYZE users');
        
        res.json({
          success: true,
          message: 'Database vacuum completed'
        });
        break;

      default:
        res.status(400).json({
          success: false,
          error: 'Invalid maintenance action'
        });
    }

  } catch (error) {
    console.error('Admin maintenance error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to perform maintenance task'
    });
  }
});

module.exports = router;
