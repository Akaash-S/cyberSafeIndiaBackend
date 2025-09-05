const express = require('express');
const Joi = require('joi');
const { pool } = require('../config/db');
const admin = require('../config/firebaseAdmin');

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
    console.log('User registration request received:', {
      body: req.body,
      headers: req.headers
    });

    // Validate request body
    const { error, value } = userRegistrationSchema.validate(req.body);
    if (error) {
      console.log('Validation error:', error.details[0].message);
      return res.status(400).json({
        success: false,
        error: error.details[0].message
      });
    }

    const { uid, email, displayName, photoURL, admin } = value;
    console.log('Validated registration data:', { uid, email, displayName, photoURL, admin });

    // Check if user already exists
    console.log('Checking if user exists with UID:', uid);
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE id = $1',
      [uid]
    );

    if (existingUser.rows.length > 0) {
      console.log('User exists, updating...');
      // Update existing user
      await pool.query(
        'UPDATE users SET email = $1, display_name = $2, photo_url = $3, updated_at = NOW() WHERE id = $4',
        [email, displayName, photoURL, uid]
      );

      console.log('User updated successfully');
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

    console.log('User does not exist, creating new user...');
    // Create new user
    const result = await pool.query(
      'INSERT INTO users (id, email, display_name, photo_url, firebase_uid, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) RETURNING id, email, display_name, photo_url, firebase_uid, created_at',
      [uid, email, displayName, photoURL, uid]
    );
    console.log('User created successfully:', result.rows[0]);

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
      constraint: error.constraint,
      stack: error.stack
    });
    
    // Return more specific error messages based on error type
    let errorMessage = 'Failed to register user';
    let statusCode = 500;
    
    if (error.code === '23505') { // Unique constraint violation
      errorMessage = 'User already exists';
      statusCode = 409;
    } else if (error.code === '23502') { // Not null constraint violation
      errorMessage = 'Missing required fields';
      statusCode = 400;
    } else if (error.code === '23503') { // Foreign key constraint violation
      errorMessage = 'Invalid reference data';
      statusCode = 400;
    }
    
    res.status(statusCode).json({
      success: false,
      error: errorMessage,
      details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// GET /api/user/profile - Get user profile
router.get('/profile', async (req, res) => {
  try {
    console.log('Profile request received:', {
      headers: req.headers,
      query: req.query
    });

    const authHeader = req.headers.authorization;
    const userData = authHeader && authHeader.split(' ')[1];

    if (!userData) {
      console.log('No authorization header found');
      return res.status(401).json({
        success: false,
        error: 'User authentication required'
      });
    }

    let user;
    try {
      user = JSON.parse(Buffer.from(userData, 'base64').toString());
      console.log('Decoded user data:', user);
    } catch (parseError) {
      console.error('Failed to parse user data:', parseError);
      return res.status(401).json({
        success: false,
        error: 'Invalid authentication data'
      });
    }
    
    if (!user.uid) {
      console.log('No UID found in user data');
      return res.status(401).json({
        success: false,
        error: 'Invalid user data'
      });
    }

    // Get user profile from database
    console.log('Querying database for user:', user.uid);
    const result = await pool.query(
      'SELECT id, email, display_name, photo_url, firebase_uid, created_at, updated_at FROM users WHERE id = $1',
      [user.uid]
    );

    console.log('Database query result:', result.rows);

    if (result.rows.length === 0) {
      console.log('User not found in database');
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    const userProfile = result.rows[0];
    console.log('User profile found:', userProfile);

    const responseData = {
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
    };

    console.log('Sending profile response:', responseData);
    res.json(responseData);

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

// DELETE /api/user/profile - Delete user account (from Firebase)
router.delete('/profile', async (req, res) => {
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

    const uid = user.uid;

    // Delete the user from Firebase Authentication
    await admin.auth().deleteUser(uid);

    res.json({
      success: true,
      message: 'User account deleted successfully from Firebase.'
    });

  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete user account'
    });
  }
});

module.exports = router;
