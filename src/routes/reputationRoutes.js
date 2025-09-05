const express = require('express');
const Joi = require('joi');
const { authenticateUser, optionalAuth } = require('../middleware/authMiddleware');
const reputationService = require('../services/reputationService');

const router = express.Router();

// Validation schemas
const checkReputationSchema = Joi.object({
  url: Joi.string().uri().required().messages({
    'string.uri': 'Please provide a valid URL',
    'any.required': 'URL is required'
  })
});

const reportThreatSchema = Joi.object({
  url: Joi.string().uri().required().messages({
    'string.uri': 'Please provide a valid URL',
    'any.required': 'URL is required'
  }),
  threatType: Joi.string().valid('malware', 'phishing', 'suspicious', 'spam', 'other').required().messages({
    'any.only': 'Threat type must be one of: malware, phishing, suspicious, spam, other',
    'any.required': 'Threat type is required'
  }),
  severity: Joi.string().valid('low', 'medium', 'high', 'critical').default('medium').messages({
    'any.only': 'Severity must be one of: low, medium, high, critical'
  })
});

const reportSafeSchema = Joi.object({
  url: Joi.string().uri().required().messages({
    'string.uri': 'Please provide a valid URL',
    'any.required': 'URL is required'
  })
});

// POST /api/reputation/check - Check URL reputation
router.post('/check', optionalAuth, async (req, res) => {
  try {
    // Validate request body
    const { error, value } = checkReputationSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message
      });
    }

    const { url } = value;
    const result = await reputationService.checkUrlReputation(url);

    if (result.success) {
      res.json({
        success: true,
        data: result.data
      });
    } else {
      res.status(500).json({
        success: false,
        error: result.error
      });
    }

  } catch (error) {
    console.error('Check reputation error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error during reputation check'
    });
  }
});

// POST /api/reputation/report-threat - Report URL as threat
router.post('/report-threat', authenticateUser, async (req, res) => {
  try {
    // Validate request body
    const { error, value } = reportThreatSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message
      });
    }

    const { url, threatType, severity } = value;
    const reportedBy = req.user.uid;

    const result = await reputationService.reportThreatUrl(url, threatType, severity, reportedBy);

    if (result.success) {
      res.json({
        success: true,
        message: result.message
      });
    } else {
      res.status(500).json({
        success: false,
        error: result.error
      });
    }

  } catch (error) {
    console.error('Report threat error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error during threat reporting'
    });
  }
});

// POST /api/reputation/report-safe - Report URL as safe
router.post('/report-safe', authenticateUser, async (req, res) => {
  try {
    // Validate request body
    const { error, value } = reportSafeSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message
      });
    }

    const { url } = value;
    const verifiedBy = req.user.uid;

    const result = await reputationService.reportSafeUrl(url, verifiedBy);

    if (result.success) {
      res.json({
        success: true,
        message: result.message
      });
    } else {
      res.status(500).json({
        success: false,
        error: result.error
      });
    }

  } catch (error) {
    console.error('Report safe error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error during safe reporting'
    });
  }
});

// GET /api/reputation/stats - Get reputation statistics
router.get('/stats', optionalAuth, async (req, res) => {
  try {
    const result = await reputationService.getReputationStats();

    if (result.success) {
      res.json({
        success: true,
        data: result.data
      });
    } else {
      res.status(500).json({
        success: false,
        error: result.error
      });
    }

  } catch (error) {
    console.error('Get reputation stats error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error during stats retrieval'
    });
  }
});

module.exports = router;
