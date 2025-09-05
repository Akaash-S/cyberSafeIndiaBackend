const express = require('express');
const Joi = require('joi');
const { authenticateUser, optionalAuth } = require('../middleware/authMiddleware');
const { pool } = require('../config/db');
const virusTotalService = require('../services/virusTotalService');
const abuseIpService = require('../services/abuseIpService');

const router = express.Router();

// Validation schema for URL scanning
const scanUrlSchema = Joi.object({
  url: Joi.string().uri().required().messages({
    'string.uri': 'Please provide a valid URL',
    'any.required': 'URL is required'
  })
});

// POST /api/scan - Scan a URL
router.post('/', optionalAuth, async (req, res) => {
  try {
    // Validate request body
    const { error, value } = scanUrlSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message
      });
    }

    const { url } = value;
    const userId = req.user?.uid || null;

    // Check if URL was recently scanned (within last 5 minutes)
    if (userId) {
      const recentScan = await pool.query(
        'SELECT * FROM scans WHERE url = $1 AND user_id = $2 AND scan_date > NOW() - INTERVAL \'5 minutes\' ORDER BY scan_date DESC LIMIT 1',
        [url, userId]
      );

      if (recentScan.rows.length > 0) {
        return res.json({
          success: true,
          data: {
            url: url,
            status: recentScan.rows[0].status,
            details: {
              virustotal: recentScan.rows[0].virustotal_data,
              abuseipdb: recentScan.rows[0].abuseipdb_data
            },
            scanDate: recentScan.rows[0].scan_date,
            cached: true
          }
        });
      }
    }

    // Perform parallel scans
    const [virusTotalResult, abuseIpResult] = await Promise.allSettled([
      virusTotalService.scanUrl(url),
      abuseIpService.checkUrl(url)
    ]);

    // Process VirusTotal results
    const virusTotalData = virusTotalResult.status === 'fulfilled' ? virusTotalResult.value : null;
    const abuseIpData = abuseIpResult.status === 'fulfilled' ? abuseIpResult.value : null;

    // Determine overall threat status
    const overallStatus = determineOverallStatus(virusTotalData, abuseIpData);

    // Prepare response data
    const scanResult = {
      url: url,
      status: overallStatus.status,
      confidence: overallStatus.confidence,
      details: {
        virustotal: virusTotalData?.success ? virusTotalData.data : null,
        abuseipdb: abuseIpData?.success ? abuseIpData.data : null
      },
      scanDate: new Date().toISOString(),
      cached: false
    };

    // Save scan result to database if user is authenticated
    if (userId) {
      try {
        await pool.query(
          'INSERT INTO scans (user_id, url, status, virustotal_data, abuseipdb_data) VALUES ($1, $2, $3, $4, $5)',
          [
            userId,
            url,
            overallStatus.status,
            JSON.stringify(virusTotalData?.data || null),
            JSON.stringify(abuseIpData?.data || null)
          ]
        );
      } catch (dbError) {
        console.error('Error saving scan to database:', dbError);
        // Don't fail the request if database save fails
      }
    }

    res.json({
      success: true,
      data: scanResult
    });

  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error during scan'
    });
  }
});

// POST /api/scan/batch - Scan multiple URLs
router.post('/batch', authenticateUser, async (req, res) => {
  try {
    const { urls } = req.body;

    if (!Array.isArray(urls) || urls.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'URLs array is required and must not be empty'
      });
    }

    if (urls.length > 10) {
      return res.status(400).json({
        success: false,
        error: 'Maximum 10 URLs allowed per batch scan'
      });
    }

    // Validate all URLs
    const validationResults = urls.map(url => {
      const { error } = Joi.string().uri().validate(url);
      return { url, valid: !error, error: error?.details[0]?.message };
    });

    const invalidUrls = validationResults.filter(result => !result.valid);
    if (invalidUrls.length > 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid URLs found',
        invalidUrls: invalidUrls
      });
    }

    // Process URLs in parallel (with concurrency limit)
    const results = await Promise.allSettled(
      urls.map(url => scanSingleUrl(url, req.user.uid))
    );

    const scanResults = results.map((result, index) => ({
      url: urls[index],
      success: result.status === 'fulfilled',
      data: result.status === 'fulfilled' ? result.value : null,
      error: result.status === 'rejected' ? result.reason.message : null
    }));

    res.json({
      success: true,
      data: scanResults
    });

  } catch (error) {
    console.error('Batch scan error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error during batch scan'
    });
  }
});

// Helper function to scan a single URL
async function scanSingleUrl(url, userId) {
  try {
    // Check for recent scan
    const recentScan = await pool.query(
      'SELECT * FROM scans WHERE url = $1 AND user_id = $2 AND scan_date > NOW() - INTERVAL \'5 minutes\' ORDER BY scan_date DESC LIMIT 1',
      [url, userId]
    );

    if (recentScan.rows.length > 0) {
      return {
        url: url,
        status: recentScan.rows[0].status,
        details: {
          virustotal: recentScan.rows[0].virustotal_data,
          abuseipdb: recentScan.rows[0].abuseipdb_data
        },
        scanDate: recentScan.rows[0].scan_date,
        cached: true
      };
    }

    // Perform scans
    const [virusTotalResult, abuseIpResult] = await Promise.allSettled([
      virusTotalService.scanUrl(url),
      abuseIpService.checkUrl(url)
    ]);

    const virusTotalData = virusTotalResult.status === 'fulfilled' ? virusTotalResult.value : null;
    const abuseIpData = abuseIpResult.status === 'fulfilled' ? abuseIpResult.value : null;

    const overallStatus = determineOverallStatus(virusTotalData, abuseIpData);

    const scanResult = {
      url: url,
      status: overallStatus.status,
      confidence: overallStatus.confidence,
      details: {
        virustotal: virusTotalData?.success ? virusTotalData.data : null,
        abuseipdb: abuseIpData?.success ? abuseIpData.data : null
      },
      scanDate: new Date().toISOString(),
      cached: false
    };

    // Save to database
    await pool.query(
      'INSERT INTO scans (user_id, url, status, virustotal_data, abuseipdb_data) VALUES ($1, $2, $3, $4, $5)',
      [
        userId,
        url,
        overallStatus.status,
        JSON.stringify(virusTotalData?.data || null),
        JSON.stringify(abuseIpData?.data || null)
      ]
    );

    return scanResult;
  } catch (error) {
    throw new Error(`Failed to scan ${url}: ${error.message}`);
  }
}

// Helper function to determine overall threat status
function determineOverallStatus(virusTotalData, abuseIpData) {
  const virusTotalStatus = virusTotalData?.success ? 
    virusTotalService.analyzeThreatLevel(virusTotalData.data) : 
    { status: 'unknown', confidence: 0 };

  const abuseIpStatus = abuseIpData?.success ? 
    abuseIpService.analyzeThreatLevel(abuseIpData.data) : 
    { status: 'unknown', confidence: 0 };

  // Priority: malicious > suspicious > safe > unknown
  if (virusTotalStatus.status === 'malicious' || abuseIpStatus.status === 'malicious') {
    return {
      status: 'malicious',
      confidence: Math.max(virusTotalStatus.confidence, abuseIpStatus.confidence)
    };
  }

  if (virusTotalStatus.status === 'suspicious' || abuseIpStatus.status === 'suspicious') {
    return {
      status: 'suspicious',
      confidence: Math.max(virusTotalStatus.confidence, abuseIpStatus.confidence)
    };
  }

  if (virusTotalStatus.status === 'safe' && abuseIpStatus.status === 'safe') {
    return {
      status: 'safe',
      confidence: Math.min(virusTotalStatus.confidence, abuseIpStatus.confidence)
    };
  }

  if (virusTotalStatus.status === 'safe' || abuseIpStatus.status === 'safe') {
    return {
      status: 'safe',
      confidence: Math.max(virusTotalStatus.confidence, abuseIpStatus.confidence)
    };
  }

  return {
    status: 'unknown',
    confidence: 0
  };
}

module.exports = router;
