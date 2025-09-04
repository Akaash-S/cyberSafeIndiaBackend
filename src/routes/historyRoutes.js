const express = require('express');
const Joi = require('joi');
const { authenticateUser } = require('../middleware/authMiddleware');
const { pool } = require('../config/db');

const router = express.Router();

// Validation schemas
const paginationSchema = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20),
  status: Joi.string().valid('safe', 'suspicious', 'malicious', 'unknown').optional(),
  sortBy: Joi.string().valid('scan_date', 'url', 'status').default('scan_date'),
  sortOrder: Joi.string().valid('asc', 'desc').default('desc')
});

const deleteSchema = Joi.object({
  id: Joi.number().integer().positive().required()
});

// GET /api/history - Get user's scan history
router.get('/history', authenticateUser, async (req, res) => {
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
    const userId = req.user.uid;
    const offset = (page - 1) * limit;

    // Build query
    let query = `
      SELECT id, url, status, scan_date, virustotal_data, abuseipdb_data
      FROM scans 
      WHERE user_id = $1
    `;
    const queryParams = [userId];
    let paramCount = 1;

    // Add status filter if provided
    if (status) {
      paramCount++;
      query += ` AND status = $${paramCount}`;
      queryParams.push(status);
    }

    // Add sorting
    query += ` ORDER BY ${sortBy} ${sortOrder.toUpperCase()}`;

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
    let countQuery = 'SELECT COUNT(*) FROM scans WHERE user_id = $1';
    const countParams = [userId];
    let countParamCount = 1;

    if (status) {
      countParamCount++;
      countQuery += ` AND status = $${countParamCount}`;
      countParams.push(status);
    }

    const countResult = await pool.query(countQuery, countParams);
    const totalCount = parseInt(countResult.rows[0].count);
    const totalPages = Math.ceil(totalCount / limit);

    // Format response
    const scans = result.rows.map(row => ({
      id: row.id,
      url: row.url,
      status: row.status,
      scanDate: row.scan_date,
      details: {
        virustotal: row.virustotal_data,
        abuseipdb: row.abuseipdb_data
      }
    }));

    res.json({
      success: true,
      data: {
        scans: scans,
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
    console.error('History fetch error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch scan history'
    });
  }
});

// GET /api/history/stats - Get scan statistics for user
router.get('/history/stats', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.uid;

    // Get overall statistics
    const statsQuery = `
      SELECT 
        status,
        COUNT(*) as count
      FROM scans 
      WHERE user_id = $1 
      GROUP BY status
    `;

    const statsResult = await pool.query(statsQuery, [userId]);

    // Get recent activity (last 30 days)
    const recentQuery = `
      SELECT 
        DATE(scan_date) as scan_date,
        COUNT(*) as count
      FROM scans 
      WHERE user_id = $1 
        AND scan_date >= NOW() - INTERVAL '30 days'
      GROUP BY DATE(scan_date)
      ORDER BY scan_date DESC
    `;

    const recentResult = await pool.query(recentQuery, [userId]);

    // Get most scanned domains
    const domainsQuery = `
      SELECT 
        CASE 
          WHEN url LIKE 'http://%' THEN SUBSTRING(url FROM 'http://([^/]+)')
          WHEN url LIKE 'https://%' THEN SUBSTRING(url FROM 'https://([^/]+)')
          ELSE url
        END as domain,
        COUNT(*) as count
      FROM scans 
      WHERE user_id = $1 
      GROUP BY domain
      ORDER BY count DESC
      LIMIT 10
    `;

    const domainsResult = await pool.query(domainsQuery, [userId]);

    // Format statistics
    const statusStats = {
      safe: 0,
      suspicious: 0,
      malicious: 0,
      unknown: 0
    };

    statsResult.rows.forEach(row => {
      statusStats[row.status] = parseInt(row.count);
    });

    const totalScans = Object.values(statusStats).reduce((sum, count) => sum + count, 0);

    res.json({
      success: true,
      data: {
        totalScans: totalScans,
        statusBreakdown: statusStats,
        recentActivity: recentResult.rows.map(row => ({
          date: row.scan_date,
          count: parseInt(row.count)
        })),
        topDomains: domainsResult.rows.map(row => ({
          domain: row.domain,
          count: parseInt(row.count)
        }))
      }
    });

  } catch (error) {
    console.error('Stats fetch error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch scan statistics'
    });
  }
});

// DELETE /api/history/:id - Delete specific scan entry
router.delete('/history/:id', authenticateUser, async (req, res) => {
  try {
    // Validate ID parameter
    const { error, value } = deleteSchema.validate({ id: req.params.id });
    if (error) {
      return res.status(400).json({
        success: false,
        error: 'Invalid scan ID'
      });
    }

    const { id } = value;
    const userId = req.user.uid;

    // Check if scan exists and belongs to user
    const checkQuery = 'SELECT id FROM scans WHERE id = $1 AND user_id = $2';
    const checkResult = await pool.query(checkQuery, [id, userId]);

    if (checkResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Scan not found or access denied'
      });
    }

    // Delete the scan
    await pool.query('DELETE FROM scans WHERE id = $1 AND user_id = $2', [id, userId]);

    res.json({
      success: true,
      message: 'Scan deleted successfully'
    });

  } catch (error) {
    console.error('Delete scan error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete scan'
    });
  }
});

// DELETE /api/history - Delete all scans for user
router.delete('/history', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.uid;

    // Get count before deletion
    const countResult = await pool.query('SELECT COUNT(*) FROM scans WHERE user_id = $1', [userId]);
    const deletedCount = parseInt(countResult.rows[0].count);

    // Delete all scans
    await pool.query('DELETE FROM scans WHERE user_id = $1', [userId]);

    res.json({
      success: true,
      message: `Deleted ${deletedCount} scans successfully`
    });

  } catch (error) {
    console.error('Delete all scans error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete scans'
    });
  }
});

// GET /api/history/export - Export scan history as CSV
router.get('/history/export', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.uid;

    // Get all scans for user
    const result = await pool.query(
      'SELECT url, status, scan_date FROM scans WHERE user_id = $1 ORDER BY scan_date DESC',
      [userId]
    );

    // Generate CSV content
    const csvHeader = 'URL,Status,Scan Date\n';
    const csvRows = result.rows.map(row => 
      `"${row.url}","${row.status}","${row.scan_date.toISOString()}"`
    ).join('\n');

    const csvContent = csvHeader + csvRows;

    // Set response headers for file download
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="scan-history-${new Date().toISOString().split('T')[0]}.csv"`);
    
    res.send(csvContent);

  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to export scan history'
    });
  }
});

module.exports = router;
