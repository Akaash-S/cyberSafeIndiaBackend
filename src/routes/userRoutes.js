const express = require('express');
const Joi = require('joi');
const { pool } = require('../config/db');

const router = express.Router();

// Validation schema for user registration
const userRegistrationSchema = Joi.object({
  uid: Joi.string().required(),
  email: Joi.string().email().required(),
  displayName: Joi.string().allow('').optional(),
  photoURL: Joi.string().allow('').optional(),
  admin: Joi.boolean().default(false)
});

// POST /api/user/register - Register a new user (called from frontend after Firebase auth)
router.post('/register', async (req, res) => {
  try {
    // Validate request body
    const { error, value } = userRegistrationSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message
      });
    }

    const { uid, email, displayName, photoURL, admin } = value;

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE id = $1',
      [uid]
    );

    if (existingUser.rows.length > 0) {
      // Update existing user
      await pool.query(
        'UPDATE users SET email = $1, display_name = $2, photo_url = $3, updated_at = NOW() WHERE id = $4',
        [email, displayName, photoURL, uid]
      );

      return res.json({
        success: true,
        message: 'User updated successfully',
        data: {
          uid,
          email,
          displayName,
          photoURL,
          admin: false // Default to false since admin column doesn't exist
        }
      });
    }

    // Create new user
    const result = await pool.query(
      'INSERT INTO users (id, email, display_name, photo_url, firebase_uid, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) RETURNING id, email, display_name, photo_url, firebase_uid, created_at',
      [uid, email, displayName, photoURL, uid]
    );

    const newUser = result.rows[0];

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        uid: newUser.id,
        email: newUser.email,
        displayName: newUser.display_name,
        photoURL: newUser.photo_url,
        admin: false, // Default to false since admin column doesn't exist
        createdAt: newUser.created_at
      }
    });

  } catch (error) {
    console.error('User registration error:', error);
    console.error('Error details:', {
      message: error.message,
      code: error.code,
      detail: error.detail,
      constraint: error.constraint
    });
    res.status(500).json({
      success: false,
      error: 'Failed to register user',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// GET /api/user/profile - Get user profile
router.get('/profile', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const userData = authHeader && authHeader.split(' ')[1];

    if (!userData) {
      return res.status(401).json({
        success: false,
        error: 'User authentication required'
      });
    }

    const user = JSON.parse(Buffer.from(userData, 'base64').toString());
    
    if (!user.uid) {
      return res.status(401).json({
        success: false,
        error: 'Invalid user data'
      });
    }

    // Get user profile from database
    const result = await pool.query(
      'SELECT id, email, display_name, photo_url, firebase_uid, created_at, updated_at FROM users WHERE id = $1',
      [user.uid]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    const userProfile = result.rows[0];

    res.json({
      success: true,
      data: {
        uid: userProfile.id,
        email: userProfile.email,
        displayName: userProfile.display_name,
        photoURL: userProfile.photo_url,
        admin: false, // Default to false since admin column doesn't exist
        createdAt: userProfile.created_at,
        lastLogin: userProfile.updated_at // Use updated_at as lastLogin
      }
    });

  } catch (error) {
    console.error('User profile fetch error:', error);
    console.error('Error details:', {
      message: error.message,
      code: error.code,
      detail: error.detail,
      constraint: error.constraint
    });
    res.status(500).json({
      success: false,
      error: 'Failed to fetch user profile',
      details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// PUT /api/user/profile - Update user profile
router.put('/profile', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const userData = authHeader && authHeader.split(' ')[1];

    if (!userData) {
      return res.status(401).json({
        success: false,
        error: 'User authentication required'
      });
    }

    const user = JSON.parse(Buffer.from(userData, 'base64').toString());
    
    if (!user.uid) {
      return res.status(401).json({
        success: false,
        error: 'Invalid user data'
      });
    }

    const { displayName } = req.body;

    // Update user profile
    await pool.query(
      'UPDATE users SET display_name = $1 WHERE id = $2',
      [displayName, user.uid]
    );

    res.json({
      success: true,
      message: 'Profile updated successfully'
    });

  } catch (error) {
    console.error('User profile update error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update user profile'
    });
  }
});

module.exports = router;
