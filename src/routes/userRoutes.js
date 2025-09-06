const express = require('express');
const Joi = require('joi');
const { pool } = require('../config/db');
const admin = require('../config/firebaseAdmin');
const authService = require('../services/authService');
const { authenticateUser } = require('../middleware/authMiddleware');

const router = express.Router();

// POST /api/user/login - Login or register a user with Firebase ID token
router.post('/login', async (req, res) => {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      return res.status(400).json({ success: false, error: 'Firebase ID token is required' });
    }

    const { user, emailVerified, verificationLink } = await authService.loginOrRegister(idToken);

    res.status(200).json({
      success: true,
      message: emailVerified ? 'User logged in successfully' : 'Verification email sent',
      data: {
        uid: user.id,
        email: user.email,
        displayName: user.display_name,
        photoURL: user.photo_url,
        emailVerified: user.email_verified,
      },
      verificationLink: verificationLink || null,
    });

  } catch (error) {
    console.error('User login/registration error:', error);
    res.status(500).json({ success: false, error: 'Failed to process login/registration', details: error.message });
  }
});

// GET /api/user/verify-email - Handle email verification link
router.get('/verify-email', async (req, res) => {
  try {
    const { oobCode } = req.query;

    if (!oobCode) {
      return res.status(400).json({ success: false, error: 'Verification code is missing' });
    }

    await authService.verifyEmail(oobCode);

    // Redirect to a frontend page indicating success
    res.redirect(`${process.env.FRONTEND_URL}/email-verified?status=success`);

  } catch (error) {
    console.error('Email verification error:', error);
    // Redirect to a frontend page indicating failure
    res.redirect(`${process.env.FRONTEND_URL}/email-verified?status=error&message=${encodeURIComponent(error.message)}`);
  }
});

// GET /api/user/profile - Get user profile (protected)
router.get('/profile', authenticateUser, async (req, res) => {
  try {
    const uid = req.user.uid;

    const result = await pool.query(
      'SELECT id, email, display_name, photo_url, firebase_uid, created_at, updated_at, email_verified FROM users WHERE id = $1',
      [uid]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const userProfile = result.rows[0];

    res.json({
      success: true,
      data: {
        uid: userProfile.id,
        email: userProfile.email,
        displayName: userProfile.display_name,
        photoURL: userProfile.photo_url,
        emailVerified: userProfile.email_verified,
        createdAt: userProfile.created_at,
        lastLogin: userProfile.updated_at
      }
    });

  } catch (error) {
    console.error('User profile fetch error:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch user profile', details: error.message });
  }
});

// PUT /api/user/profile - Update user profile (protected)
router.put('/profile', authenticateUser, async (req, res) => {
  try {
    const uid = req.user.uid;
    const { displayName } = req.body;

    await pool.query(
      'UPDATE users SET display_name = $1, updated_at = NOW() WHERE id = $2',
      [displayName, uid]
    );

    res.json({ success: true, message: 'Profile updated successfully' });

  } catch (error) {
    console.error('User profile update error:', error);
    res.status(500).json({ success: false, error: 'Failed to update user profile', details: error.message });
  }
});

// DELETE /api/user/profile - Delete user account (protected)
router.delete('/profile', authenticateUser, async (req, res) => {
  try {
    const uid = req.user.uid;

    // Delete the user from Firebase Authentication
    await admin.auth().deleteUser(uid);

    // Delete the user from our database
    await pool.query('DELETE FROM users WHERE id = $1', [uid]);

    res.json({ success: true, message: 'User account deleted successfully.' });

  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete user account', details: error.message });
  }
});

module.exports = router;
