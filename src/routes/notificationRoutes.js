const express = require('express');
const Joi = require('joi');
const { authenticateUser } = require('../middleware/authMiddleware');
const { pool } = require('../config/db');

const router = express.Router();

// Validation schema for notification preferences
const notificationSchema = Joi.object({
  email: Joi.boolean().default(true),
  push: Joi.boolean().default(true),
  security: Joi.boolean().default(true),
  weekly: Joi.boolean().default(false),
  threatAlerts: Joi.boolean().default(true),
  scanComplete: Joi.boolean().default(true),
  reportUpdates: Joi.boolean().default(true)
});

// GET /api/notifications/preferences - Get user notification preferences
router.get('/preferences', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.uid;

    // Get user notification preferences
    const result = await pool.query(
      'SELECT notification_preferences FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    const preferences = result.rows[0].notification_preferences || {
      email: true,
      push: true,
      security: true,
      weekly: false,
      threatAlerts: true,
      scanComplete: true,
      reportUpdates: true
    };

    res.json({
      success: true,
      data: preferences
    });

  } catch (error) {
    console.error('Get notification preferences error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch notification preferences'
    });
  }
});

// PUT /api/notifications/preferences - Update user notification preferences
router.put('/preferences', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.uid;

    // Validate request body
    const { error, value } = notificationSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message
      });
    }

    const preferences = value;

    // Update user notification preferences
    await pool.query(
      'UPDATE users SET notification_preferences = $1, updated_at = NOW() WHERE id = $2',
      [JSON.stringify(preferences), userId]
    );

    res.json({
      success: true,
      message: 'Notification preferences updated successfully',
      data: preferences
    });

  } catch (error) {
    console.error('Update notification preferences error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update notification preferences'
    });
  }
});

// POST /api/notifications/test - Test notification (for development)
router.post('/test', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.uid;
    const { type, message } = req.body;

    // Get user preferences
    const result = await pool.query(
      'SELECT notification_preferences FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    const preferences = result.rows[0].notification_preferences || {};

    // Check if notification type is enabled
    if (!preferences[type]) {
      return res.json({
        success: true,
        message: `Notification type '${type}' is disabled`,
        sent: false
      });
    }

    // In a real app, this would send actual notifications
    console.log(`📧 Notification sent to user ${userId}:`, {
      type,
      message,
      preferences
    });

    res.json({
      success: true,
      message: 'Test notification sent successfully',
      sent: true
    });

  } catch (error) {
    console.error('Test notification error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to send test notification'
    });
  }
});

module.exports = router;
