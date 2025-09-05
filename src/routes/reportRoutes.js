const express = require('express');
const Joi = require('joi');
const { authenticateUser, requireAdmin } = require('../middleware/authMiddleware');
const { pool } = require('../config/db');

const router = express.Router();

// Validation schemas
const reportSchema = Joi.object({
  url: Joi.string().uri().required().messages({
    'string.uri': 'Please provide a valid URL',
    'any.required': 'URL is required'
  }),
  reason: Joi.string().max(500).optional().messages({
    'string.max': 'Reason must be less than 500 characters'
  }),
  threatType: Joi.string().valid('malware', 'phishing', 'suspicious', 'spam', 'other').required().messages({
    'any.only': 'Threat type must be one of: malware, phishing, suspicious, spam, other',
    'any.required': 'Threat type is required'
  }),
  severity: Joi.string().valid('low', 'medium', 'high', 'critical').default('medium').messages({
    'any.only': 'Severity must be one of: low, medium, high, critical'
  })
});

const reportStatusSchema = Joi.object({
  status: Joi.string().valid('pending', 'approved', 'rejected').required()
});

const paginationSchema = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20),
  status: Joi.string().valid('pending', 'approved', 'rejected').optional(),
  sortBy: Joi.string().valid('report_date', 'url', 'status').default('report_date'),
  sortOrder: Joi.string().valid('asc', 'desc').default('desc')
});

// POST /api/report - Submit a suspicious URL report
router.post('/report', authenticateUser, async (req, res) => {
  try {
    // Validate request body
    const { error, value } = reportSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message
      });
    }

    const { url, reason, threatType, severity } = value;
    const userId = req.user.uid;

    // Extract domain from URL
    let domain = '';
    try {
      const urlObj = new URL(url);
      domain = urlObj.hostname;
    } catch (error) {
      console.error('Error extracting domain from URL:', error);
    }

    // Check if user has already reported this URL recently (within last 24 hours)
    const recentReport = await pool.query(
      'SELECT id FROM reports WHERE url = $1 AND user_id = $2 AND report_date > NOW() - INTERVAL \'24 hours\'',
      [url, userId]
    );

    if (recentReport.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: 'You have already reported this URL recently. Please wait 24 hours before reporting again.'
      });
    }

    // Insert new report with enhanced data
    const result = await pool.query(
      'INSERT INTO reports (user_id, url, reason, threat_type, severity, domain, status) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, report_date',
      [userId, url, reason || null, threatType, severity, domain, 'pending']
    );

    const reportId = result.rows[0].id;
    const reportDate = result.rows[0].report_date;

    // Update community reputation system
    try {
      const reputationService = require('../services/reputationService');
      await reputationService.reportThreatUrl(url, threatType, severity, userId);
      console.log(`Community reputation updated for reported URL: ${url}`);
    } catch (reputationError) {
      console.error('Error updating community reputation:', reputationError);
      // Don't fail the report submission if reputation update fails
    }

    res.status(201).json({
      success: true,
      data: {
        id: reportId,
        url: url,
        reason: reason,
        threatType: threatType,
        severity: severity,
        domain: domain,
        status: 'pending',
        reportDate: reportDate,
        message: 'Threat report submitted successfully. Our team will review it shortly.'
      }
    });

  } catch (error) {
    console.error('Report submission error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to submit report'
    });
  }
});

// GET /api/reports - Get reports (admin only)
router.get('/reports', requireAdmin, async (req, res) => {
  try {
    // Validate query parameters
    const { error, value } = paginationSchema.validate(req.query);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message
      });
    }

    const { page, limit, status, sortBy, sortOrder } = value;
    const offset = (page - 1) * limit;

    // Build query
    let query = `
      SELECT 
        r.id, 
        r.url, 
        r.reason, 
        r.threat_type,
        r.severity,
        r.domain,
        r.status, 
        r.report_date,
        r.admin_notes,
        r.reviewed_by,
        r.reviewed_at,
        u.email as reporter_email,
        u.display_name as reporter_name
      FROM reports r
      LEFT JOIN users u ON r.user_id = u.id
    `;
    const queryParams = [];
    let paramCount = 0;

    // Add status filter if provided
    if (status) {
      paramCount++;
      query += ` WHERE r.status = $${paramCount}`;
      queryParams.push(status);
    }

    // Add sorting
    query += ` ORDER BY r.${sortBy} ${sortOrder.toUpperCase()}`;

    // Add pagination
    paramCount++;
    query += ` LIMIT $${paramCount}`;
    queryParams.push(limit);

    paramCount++;
    query += ` OFFSET $${paramCount}`;
    queryParams.push(offset);

    // Execute query
    const result = await pool.query(query, queryParams);

    // Get total count for pagination
    let countQuery = 'SELECT COUNT(*) FROM reports r';
    const countParams = [];
    let countParamCount = 0;

    if (status) {
      countParamCount++;
      countQuery += ` WHERE r.status = $${countParamCount}`;
      countParams.push(status);
    }

    const countResult = await pool.query(countQuery, countParams);
    const totalCount = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(totalCount / limit);

    // Format response
    const reports = result.rows.map(row => ({
      id: row.id,
      url: row.url,
      reason: row.reason,
      threatType: row.threat_type,
      severity: row.severity,
      domain: row.domain,
      status: row.status,
      reportDate: row.report_date,
      adminNotes: row.admin_notes,
      reviewedBy: row.reviewed_by,
      reviewedAt: row.reviewed_at,
      reporter: {
        email: row.reporter_email,
        name: row.reporter_name
      }
    }));

    res.json({
      success: true,
      data: {
        reports: reports,
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
    console.error('Reports fetch error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch reports'
    });
  }
});

// PUT /api/reports/:id/status - Update report status (admin only)
router.put('/reports/:id/status', requireAdmin, async (req, res) => {
  try {
    const reportId = req.params.id;
    const { error, value } = reportStatusSchema.validate(req.body);
    
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message
      });
    }

    const { status } = value;

    // Check if report exists
    const checkResult = await pool.query('SELECT id, status FROM reports WHERE id = $1', [reportId]);
    
    if (checkResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Report not found'
      });
    }

    // Update report status
    await pool.query(
      'UPDATE reports SET status = $1 WHERE id = $2',
      [status, reportId]
    );

    res.json({
      success: true,
      message: `Report status updated to ${status}`,
      data: {
        id: reportId,
        status: status
      }
    });

  } catch (error) {
    console.error('Report status update error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update report status'
    });
  }
});

// DELETE /api/reports/:id - Delete report (admin only)
router.delete('/reports/:id', requireAdmin, async (req, res) => {
  try {
    const reportId = req.params.id;

    // Check if report exists
    const checkResult = await pool.query('SELECT id FROM reports WHERE id = $1', [reportId]);
    
    if (checkResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Report not found'
      });
    }

    // Delete report
    await pool.query('DELETE FROM reports WHERE id = $1', [reportId]);

    res.json({
      success: true,
      message: 'Report deleted successfully'
    });

  } catch (error) {
    console.error('Report deletion error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete report'
    });
  }
});

// GET /api/reports/stats - Get report statistics (admin only)
router.get('/reports/stats', requireAdmin, async (req, res) => {
  try {
    // Get overall statistics
    const statsQuery = `
      SELECT 
        status,
        COUNT(*) as count
      FROM reports 
      GROUP BY status
    `;

    const statsResult = await pool.query(statsQuery);

    // Get recent activity (last 30 days)
    const recentQuery = `
      SELECT 
        DATE(report_date) as report_date,
        COUNT(*) as count
      FROM reports 
      WHERE report_date >= NOW() - INTERVAL '30 days'
      GROUP BY DATE(report_date)
      ORDER BY report_date DESC
    `;

    const recentResult = await pool.query(recentQuery);

    // Get most reported domains
    const domainsQuery = `
      SELECT 
        CASE 
          WHEN url LIKE 'http://%' THEN SUBSTRING(url FROM 'http://([^/]+)')
          WHEN url LIKE 'https://%' THEN SUBSTRING(url FROM 'https://([^/]+)')
          ELSE url
        END as domain,
        COUNT(*) as count
      FROM reports 
      GROUP BY domain
      ORDER BY count DESC
      LIMIT 10
    `;

    const domainsResult = await pool.query(domainsQuery);

    // Get top reporters
    const reportersQuery = `
      SELECT 
        u.display_name as reporter_name,
        u.email as reporter_email,
        COUNT(*) as count
      FROM reports r
      LEFT JOIN users u ON r.user_id = u.id
      GROUP BY u.id, u.display_name, u.email
      ORDER BY count DESC
      LIMIT 10
    `;

    const reportersResult = await pool.query(reportersQuery);

    // Format statistics
    const statusStats = {
      pending: 0,
      approved: 0,
      rejected: 0
    };

    statsResult.rows.forEach(row => {
      statusStats[row.status] = parseInt(row.count);
    });

    const totalReports = Object.values(statusStats).reduce((sum, count) => sum + count, 0);

    res.json({
      success: true,
      data: {
        totalReports: totalReports,
        statusBreakdown: statusStats,
        recentActivity: recentResult.rows.map(row => ({
          date: row.report_date,
          count: parseInt(row.count)
        })),
        topReportedDomains: domainsResult.rows.map(row => ({
          domain: row.domain,
          count: parseInt(row.count)
        })),
        topReporters: reportersResult.rows.map(row => ({
          name: row.reporter_name || 'Anonymous',
          email: row.reporter_email,
          count: parseInt(row.count)
        }))
      }
    });

  } catch (error) {
    console.error('Report stats error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch report statistics'
    });
  }
});

// GET /api/reports/my - Get current user's reports
router.get('/reports/my', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.uid;

    // Get user's reports
    const result = await pool.query(
      'SELECT id, url, reason, threat_type, severity, domain, status, report_date FROM reports WHERE user_id = $1 ORDER BY report_date DESC',
      [userId]
    );

    const reports = result.rows.map(row => ({
      id: row.id,
      url: row.url,
      reason: row.reason,
      threatType: row.threat_type,
      severity: row.severity,
      domain: row.domain,
      status: row.status,
      reportDate: row.report_date
    }));

    res.json({
      success: true,
      data: reports
    });

  } catch (error) {
    console.error('User reports fetch error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch your reports'
    });
  }
});

// GET /api/reports/analytics - Get threat reports analytics for analytics page
router.get('/reports/analytics', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.uid;

    // Get user's threat reports statistics
    const userStatsQuery = `
      SELECT 
        COUNT(*) as total_reports,
        COUNT(CASE WHEN status = 'approved' THEN 1 END) as approved_reports,
        COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_reports,
        COUNT(CASE WHEN status = 'rejected' THEN 1 END) as rejected_reports
      FROM reports 
      WHERE user_id = $1
    `;

    const userStatsResult = await pool.query(userStatsQuery, [userId]);
    const userStats = userStatsResult.rows[0];

    // Get threat type breakdown for user
    const threatTypeQuery = `
      SELECT 
        threat_type,
        COUNT(*) as count,
        COUNT(CASE WHEN status = 'approved' THEN 1 END) as approved_count
      FROM reports 
      WHERE user_id = $1
      GROUP BY threat_type
      ORDER BY count DESC
    `;

    const threatTypeResult = await pool.query(threatTypeQuery, [userId]);

    // Get severity breakdown for user
    const severityQuery = `
      SELECT 
        severity,
        COUNT(*) as count
      FROM reports 
      WHERE user_id = $1
      GROUP BY severity
      ORDER BY count DESC
    `;

    const severityResult = await pool.query(severityQuery, [userId]);

    // Get recent reports (last 30 days)
    const recentReportsQuery = `
      SELECT 
        DATE(report_date) as report_date,
        COUNT(*) as count,
        COUNT(CASE WHEN status = 'approved' THEN 1 END) as approved_count
      FROM reports 
      WHERE user_id = $1 
        AND report_date >= NOW() - INTERVAL '30 days'
      GROUP BY DATE(report_date)
      ORDER BY report_date DESC
    `;

    const recentReportsResult = await pool.query(recentReportsQuery, [userId]);

    // Get most reported domains by user
    const userDomainsQuery = `
      SELECT 
        domain,
        COUNT(*) as count,
        COUNT(CASE WHEN status = 'approved' THEN 1 END) as approved_count
      FROM reports 
      WHERE user_id = $1 
        AND domain IS NOT NULL
      GROUP BY domain
      ORDER BY count DESC
      LIMIT 10
    `;

    const userDomainsResult = await pool.query(userDomainsQuery, [userId]);

    res.json({
      success: true,
      data: {
        userStats: {
          totalReports: parseInt(userStats.total_reports),
          approvedReports: parseInt(userStats.approved_reports),
          pendingReports: parseInt(userStats.pending_reports),
          rejectedReports: parseInt(userStats.rejected_reports)
        },
        threatTypeBreakdown: threatTypeResult.rows.map(row => ({
          type: row.threat_type,
          count: parseInt(row.count),
          approvedCount: parseInt(row.approved_count)
        })),
        severityBreakdown: severityResult.rows.map(row => ({
          severity: row.severity,
          count: parseInt(row.count)
        })),
        recentReports: recentReportsResult.rows.map(row => ({
          date: row.report_date,
          count: parseInt(row.count),
          approvedCount: parseInt(row.approved_count)
        })),
        topReportedDomains: userDomainsResult.rows.map(row => ({
          domain: row.domain,
          count: parseInt(row.count),
          approvedCount: parseInt(row.approved_count)
        }))
      }
    });

  } catch (error) {
    console.error('Threat reports analytics error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch threat reports analytics'
    });
  }
});

module.exports = router;
