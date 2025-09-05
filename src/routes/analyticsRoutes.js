const express = require('express');
const Joi = require('joi');
const { authenticateUser, requireAdmin } = require('../middleware/authMiddleware');
const { pool } = require('../config/db');

const router = express.Router();

// Validation schemas
const timeRangeSchema = Joi.object({
  period: Joi.string().valid('day', 'week', 'month', 'year').default('month'),
  startDate: Joi.date().optional(),
  endDate: Joi.date().optional()
});

const paginationSchema = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20)
});

// GET /api/analytics/overview - Get overall analytics overview
router.get('/overview', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.uid;

    // Get user's scan statistics
    const userStatsQuery = `
      SELECT 
        COUNT(*) as total_scans,
        COUNT(CASE WHEN status = 'safe' THEN 1 END) as safe_scans,
        COUNT(CASE WHEN status = 'suspicious' THEN 1 END) as suspicious_scans,
        COUNT(CASE WHEN status = 'malicious' THEN 1 END) as malicious_scans,
        COUNT(CASE WHEN status = 'unknown' THEN 1 END) as unknown_scans
      FROM scans 
      WHERE user_id = $1
    `;

    const userStatsResult = await pool.query(userStatsQuery, [userId]);
    const userStats = userStatsResult.rows[0];

    // Get recent activity (last 7 days)
    const recentActivityQuery = `
      SELECT 
        DATE(scan_date) as scan_date,
        COUNT(*) as count,
        COUNT(CASE WHEN status = 'malicious' THEN 1 END) as malicious_count
      FROM scans 
      WHERE user_id = $1 
        AND scan_date >= NOW() - INTERVAL '7 days'
      GROUP BY DATE(scan_date)
      ORDER BY scan_date DESC
    `;

    const recentActivityResult = await pool.query(recentActivityQuery, [userId]);

    // Get most scanned domains
    const topDomainsQuery = `
      SELECT 
        CASE 
          WHEN url LIKE 'http://%' THEN SUBSTRING(url FROM 'http://([^/]+)')
          WHEN url LIKE 'https://%' THEN SUBSTRING(url FROM 'https://([^/]+)')
          ELSE url
        END as domain,
        COUNT(*) as count,
        COUNT(CASE WHEN status = 'malicious' THEN 1 END) as malicious_count
      FROM scans 
      WHERE user_id = $1 
      GROUP BY domain
      ORDER BY count DESC
      LIMIT 5
    `;

    const topDomainsResult = await pool.query(topDomainsQuery, [userId]);

    res.json({
      success: true,
      data: {
        totalScans: parseInt(userStats.total_scans),
        statusBreakdown: {
          safe: parseInt(userStats.safe_scans),
          suspicious: parseInt(userStats.suspicious_scans),
          malicious: parseInt(userStats.malicious_scans),
          unknown: parseInt(userStats.unknown_scans)
        },
        recentActivity: recentActivityResult.rows.map(row => ({
          date: row.scan_date,
          totalScans: parseInt(row.count),
          maliciousScans: parseInt(row.malicious_count)
        })),
        topDomains: topDomainsResult.rows.map(row => ({
          domain: row.domain,
          totalScans: parseInt(row.count),
          maliciousScans: parseInt(row.malicious_count)
        }))
      }
    });

  } catch (error) {
    console.error('Analytics overview error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch analytics overview'
    });
  }
});

// GET /api/analytics/trends - Get scan trends over time
router.get('/trends', authenticateUser, async (req, res) => {
  try {
    const { error, value } = timeRangeSchema.validate(req.query);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message
      });
    }

    const { period, startDate, endDate } = value;
    const userId = req.user.uid;

    // Determine date range
    let dateRange = '';
    let groupBy = '';
    
    if (startDate && endDate) {
      dateRange = `AND scan_date BETWEEN '${startDate}' AND '${endDate}'`;
      groupBy = 'DATE(scan_date)';
    } else {
      switch (period) {
        case 'day':
          dateRange = 'AND scan_date >= NOW() - INTERVAL \'1 day\'';
          groupBy = 'DATE_TRUNC(\'hour\', scan_date)';
          break;
        case 'week':
          dateRange = 'AND scan_date >= NOW() - INTERVAL \'7 days\'';
          groupBy = 'DATE(scan_date)';
          break;
        case 'month':
          dateRange = 'AND scan_date >= NOW() - INTERVAL \'30 days\'';
          groupBy = 'DATE(scan_date)';
          break;
        case 'year':
          dateRange = 'AND scan_date >= NOW() - INTERVAL \'365 days\'';
          groupBy = 'DATE_TRUNC(\'month\', scan_date)';
          break;
      }
    }

    const trendsQuery = `
      SELECT 
        ${groupBy} as period,
        COUNT(*) as total_scans,
        COUNT(CASE WHEN status = 'safe' THEN 1 END) as safe_scans,
        COUNT(CASE WHEN status = 'suspicious' THEN 1 END) as suspicious_scans,
        COUNT(CASE WHEN status = 'malicious' THEN 1 END) as malicious_scans,
        COUNT(CASE WHEN status = 'unknown' THEN 1 END) as unknown_scans
      FROM scans 
      WHERE user_id = $1 ${dateRange}
      GROUP BY ${groupBy}
      ORDER BY period ASC
    `;

    const trendsResult = await pool.query(trendsQuery, [userId]);

    res.json({
      success: true,
      data: {
        period: period,
        trends: trendsResult.rows.map(row => ({
          period: row.period,
          totalScans: parseInt(row.total_scans),
          safeScans: parseInt(row.safe_scans),
          suspiciousScans: parseInt(row.suspicious_scans),
          maliciousScans: parseInt(row.malicious_scans),
          unknownScans: parseInt(row.unknown_scans)
        }))
      }
    });

  } catch (error) {
    console.error('Analytics trends error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch analytics trends'
    });
  }
});

// GET /api/analytics/threats - Get threat analysis
router.get('/threats', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.uid;

    // Get threat statistics
    const threatStatsQuery = `
      SELECT 
        status,
        COUNT(*) as count,
        AVG(CASE 
          WHEN virustotal_data->>'data' IS NOT NULL 
          THEN (virustotal_data->'data'->'attributes'->>'last_analysis_stats')::json->>'malicious'::text
          ELSE '0'
        END)::numeric as avg_malicious_detections
      FROM scans 
      WHERE user_id = $1 
        AND status IN ('malicious', 'suspicious')
      GROUP BY status
    `;

    const threatStatsResult = await pool.query(threatStatsQuery, [userId]);

    // Get most dangerous domains
    const dangerousDomainsQuery = `
      SELECT 
        CASE 
          WHEN url LIKE 'http://%' THEN SUBSTRING(url FROM 'http://([^/]+)')
          WHEN url LIKE 'https://%' THEN SUBSTRING(url FROM 'https://([^/]+)')
          ELSE url
        END as domain,
        COUNT(*) as total_scans,
        COUNT(CASE WHEN status = 'malicious' THEN 1 END) as malicious_count,
        ROUND(
          (COUNT(CASE WHEN status = 'malicious' THEN 1 END)::numeric / COUNT(*)) * 100, 
          2
        ) as threat_percentage
      FROM scans 
      WHERE user_id = $1 
        AND status IN ('malicious', 'suspicious')
      GROUP BY domain
      HAVING COUNT(*) >= 2
      ORDER BY threat_percentage DESC, malicious_count DESC
      LIMIT 10
    `;

    const dangerousDomainsResult = await pool.query(dangerousDomainsQuery, [userId]);

    // Get threat timeline
    const threatTimelineQuery = `
      SELECT 
        DATE(scan_date) as scan_date,
        COUNT(*) as total_threats,
        COUNT(CASE WHEN status = 'malicious' THEN 1 END) as malicious_count
      FROM scans 
      WHERE user_id = $1 
        AND status IN ('malicious', 'suspicious')
        AND scan_date >= NOW() - INTERVAL '30 days'
      GROUP BY DATE(scan_date)
      ORDER BY scan_date DESC
    `;

    const threatTimelineResult = await pool.query(threatTimelineQuery, [userId]);

    res.json({
      success: true,
      data: {
        threatStatistics: threatStatsResult.rows.map(row => ({
          status: row.status,
          count: parseInt(row.count),
          avgMaliciousDetections: parseFloat(row.avg_malicious_detections) || 0
        })),
        dangerousDomains: dangerousDomainsResult.rows.map(row => ({
          domain: row.domain,
          totalScans: parseInt(row.total_scans),
          maliciousScans: parseInt(row.malicious_count),
          threatPercentage: parseFloat(row.threat_percentage)
        })),
        threatTimeline: threatTimelineResult.rows.map(row => ({
          date: row.scan_date,
          totalThreats: parseInt(row.total_threats),
          maliciousThreats: parseInt(row.malicious_count)
        }))
      }
    });

  } catch (error) {
    console.error('Analytics threats error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch threat analytics'
    });
  }
});

// GET /api/analytics/admin - Get admin analytics (admin only)
router.get('/admin', requireAdmin, async (req, res) => {
  try {
    // Get system-wide statistics
    const systemStatsQuery = `
      SELECT 
        (SELECT COUNT(*) FROM users) as total_users,
        (SELECT COUNT(*) FROM scans) as total_scans,
        (SELECT COUNT(*) FROM reports) as total_reports,
        (SELECT COUNT(*) FROM scans WHERE scan_date >= NOW() - INTERVAL '24 hours') as scans_today,
        (SELECT COUNT(*) FROM reports WHERE report_date >= NOW() - INTERVAL '24 hours') as reports_today
    `;

    const systemStatsResult = await pool.query(systemStatsQuery);
    const systemStats = systemStatsResult.rows[0];

    // Get scan status distribution
    const scanDistributionQuery = `
      SELECT 
        status,
        COUNT(*) as count,
        ROUND((COUNT(*)::numeric / (SELECT COUNT(*) FROM scans)) * 100, 2) as percentage
      FROM scans 
      GROUP BY status
      ORDER BY count DESC
    `;

    const scanDistributionResult = await pool.query(scanDistributionQuery);

    // Get report status distribution
    const reportDistributionQuery = `
      SELECT 
        status,
        COUNT(*) as count,
        ROUND((COUNT(*)::numeric / (SELECT COUNT(*) FROM reports)) * 100, 2) as percentage
      FROM reports 
      GROUP BY status
      ORDER BY count DESC
    `;

    const reportDistributionResult = await pool.query(reportDistributionQuery);

    // Get daily activity for last 30 days
    const dailyActivityQuery = `
      SELECT 
        DATE(scan_date) as activity_date,
        COUNT(DISTINCT user_id) as active_users,
        COUNT(*) as total_scans,
        COUNT(CASE WHEN status = 'malicious' THEN 1 END) as malicious_scans
      FROM scans 
      WHERE scan_date >= NOW() - INTERVAL '30 days'
      GROUP BY DATE(scan_date)
      ORDER BY activity_date DESC
    `;

    const dailyActivityResult = await pool.query(dailyActivityQuery);

    // Get top users by scan count
    const topUsersQuery = `
      SELECT 
        u.display_name,
        u.email,
        COUNT(s.id) as scan_count,
        COUNT(CASE WHEN s.status = 'malicious' THEN 1 END) as malicious_count
      FROM users u
      LEFT JOIN scans s ON u.id = s.user_id
      GROUP BY u.id, u.display_name, u.email
      ORDER BY scan_count DESC
      LIMIT 10
    `;

    const topUsersResult = await pool.query(topUsersQuery);

    res.json({
      success: true,
      data: {
        systemStats: {
          totalUsers: parseInt(systemStats.total_users),
          totalScans: parseInt(systemStats.total_scans),
          totalReports: parseInt(systemStats.total_reports),
          scansToday: parseInt(systemStats.scans_today),
          reportsToday: parseInt(systemStats.reports_today)
        },
        scanDistribution: scanDistributionResult.rows.map(row => ({
          status: row.status,
          count: parseInt(row.count),
          percentage: parseFloat(row.percentage)
        })),
        reportDistribution: reportDistributionResult.rows.map(row => ({
          status: row.status,
          count: parseInt(row.count),
          percentage: parseFloat(row.percentage)
        })),
        dailyActivity: dailyActivityResult.rows.map(row => ({
          date: row.activity_date,
          activeUsers: parseInt(row.active_users),
          totalScans: parseInt(row.total_scans),
          maliciousScans: parseInt(row.malicious_scans)
        })),
        topUsers: topUsersResult.rows.map(row => ({
          name: row.display_name || 'Anonymous',
          email: row.email,
          scanCount: parseInt(row.scan_count),
          maliciousCount: parseInt(row.malicious_count)
        }))
      }
    });

  } catch (error) {
    console.error('Admin analytics error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch admin analytics'
    });
  }
});

// GET /api/analytics/reputation - Get reputation analytics
router.get('/reputation', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.uid;

    // Get user's reputation contribution stats
    const userReputationQuery = `
      SELECT 
        (SELECT COUNT(*) FROM threat_urls WHERE reported_by = $1) as threat_reports,
        (SELECT COUNT(*) FROM safe_urls WHERE verified_by = $1) as safe_reports,
        (SELECT COUNT(*) FROM reports WHERE user_id = $1) as total_reports
    `;

    const userReputationResult = await pool.query(userReputationQuery, [userId]);
    const userReputation = userReputationResult.rows[0];

    // Get community reputation statistics
    const communityStatsQuery = `
      SELECT 
        (SELECT COUNT(*) FROM safe_urls) as total_safe_urls,
        (SELECT COUNT(*) FROM threat_urls) as total_threat_urls,
        (SELECT COUNT(*) FROM url_reputation) as total_reputation_records,
        (SELECT SUM(report_count) FROM safe_urls) as total_safe_reports,
        (SELECT SUM(report_count) FROM threat_urls) as total_threat_reports
    `;

    const communityStatsResult = await pool.query(communityStatsQuery);
    const communityStats = communityStatsResult.rows[0];

    // Get threat type breakdown
    const threatTypeQuery = `
      SELECT 
        threat_type,
        COUNT(*) as count,
        SUM(report_count) as total_reports,
        AVG(confidence_score) as avg_confidence
      FROM threat_urls 
      GROUP BY threat_type
      ORDER BY count DESC
    `;

    const threatTypeResult = await pool.query(threatTypeQuery);

    // Get reputation trends over time
    const reputationTrendsQuery = `
      SELECT 
        DATE(created_at) as date,
        COUNT(CASE WHEN 'safe_urls' = 'safe_urls' THEN 1 END) as safe_additions,
        COUNT(CASE WHEN 'threat_urls' = 'threat_urls' THEN 1 END) as threat_additions
      FROM (
        SELECT created_at, 'safe_urls' as table_name FROM safe_urls
        UNION ALL
        SELECT created_at, 'threat_urls' as table_name FROM threat_urls
      ) combined
      WHERE created_at >= NOW() - INTERVAL '30 days'
      GROUP BY DATE(created_at)
      ORDER BY date DESC
    `;

    const reputationTrendsResult = await pool.query(reputationTrendsQuery);

    // Get most reported domains
    const topReportedDomainsQuery = `
      SELECT 
        domain,
        COUNT(*) as total_reports,
        COUNT(CASE WHEN 'safe_urls' = 'safe_urls' THEN 1 END) as safe_reports,
        COUNT(CASE WHEN 'threat_urls' = 'threat_urls' THEN 1 END) as threat_reports
      FROM (
        SELECT domain, 'safe_urls' as table_name FROM safe_urls
        UNION ALL
        SELECT domain, 'threat_urls' as table_name FROM threat_urls
      ) combined
      GROUP BY domain
      ORDER BY total_reports DESC
      LIMIT 10
    `;

    const topReportedDomainsResult = await pool.query(topReportedDomainsQuery);

    res.json({
      success: true,
      data: {
        userContribution: {
          threatReports: parseInt(userReputation.threat_reports),
          safeReports: parseInt(userReputation.safe_reports),
          totalReports: parseInt(userReputation.total_reports)
        },
        communityStats: {
          totalSafeUrls: parseInt(communityStats.total_safe_urls),
          totalThreatUrls: parseInt(communityStats.total_threat_urls),
          totalReputationRecords: parseInt(communityStats.total_reputation_records),
          totalSafeReports: parseInt(communityStats.total_safe_reports),
          totalThreatReports: parseInt(communityStats.total_threat_reports)
        },
        threatTypeBreakdown: threatTypeResult.rows.map(row => ({
          type: row.threat_type,
          count: parseInt(row.count),
          totalReports: parseInt(row.total_reports),
          avgConfidence: parseFloat(row.avg_confidence)
        })),
        reputationTrends: reputationTrendsResult.rows.map(row => ({
          date: row.date,
          safeAdditions: parseInt(row.safe_additions),
          threatAdditions: parseInt(row.threat_additions)
        })),
        topReportedDomains: topReportedDomainsResult.rows.map(row => ({
          domain: row.domain,
          totalReports: parseInt(row.total_reports),
          safeReports: parseInt(row.safe_reports),
          threatReports: parseInt(row.threat_reports)
        }))
      }
    });

  } catch (error) {
    console.error('Reputation analytics error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch reputation analytics'
    });
  }
});

// GET /api/analytics/export - Export analytics data
router.get('/export', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.uid;
    const { format = 'csv' } = req.query;

    if (format !== 'csv' && format !== 'json') {
      return res.status(400).json({
        success: false,
        error: 'Invalid format. Supported formats: csv, json'
      });
    }

    // Get user's scan data
    const result = await pool.query(
      'SELECT url, status, scan_date FROM scans WHERE user_id = $1 ORDER BY scan_date DESC',
      [userId]
    );

    if (format === 'csv') {
      // Generate CSV content
      const csvHeader = 'URL,Status,Scan Date\n';
      const csvRows = result.rows.map(row => 
        `"${row.url}","${row.status}","${row.scan_date.toISOString()}"`
      ).join('\n');

      const csvContent = csvHeader + csvRows;

      // Set response headers for file download
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="analytics-export-${new Date().toISOString().split('T')[0]}.csv"`);
      
      res.send(csvContent);
    } else {
      // Return JSON data
      res.json({
        success: true,
        data: result.rows.map(row => ({
          url: row.url,
          status: row.status,
          scanDate: row.scan_date
        }))
      });
    }

  } catch (error) {
    console.error('Analytics export error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to export analytics data'
    });
  }
});

module.exports = router;
