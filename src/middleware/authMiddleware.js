const admin = require('../config/firebaseAdmin');
const authService = require('../services/authService');

const authenticateUser = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const idToken = authHeader && authHeader.split(' ')[1];

    if (!idToken) {
      return res.status(401).json({
        error: 'Authentication token required',
        code: 'MISSING_AUTH_TOKEN'
      });
    }

    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Firebase authentication error:', error);
    return res.status(401).json({
      error: 'Authentication failed', 
      code: 'INVALID_AUTH_TOKEN',
      details: error.message
    });
  }
};

const requireAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const idToken = authHeader && authHeader.split(' ')[1];

    if (!idToken) {
      return res.status(401).json({
        error: 'Authentication token required',
        code: 'MISSING_AUTH_TOKEN'
      });
    }

    const decodedToken = await admin.auth().verifyIdToken(idToken);
    
    // Check if user is admin in Firebase (e.g., via custom claims)
    if (!decodedToken.admin) {
      // Optionally, check in your database if Firebase custom claims are not used
      const userRecord = await admin.auth().getUser(decodedToken.uid);
      if (!userRecord.customClaims || !userRecord.customClaims.admin) {
        return res.status(403).json({
          error: 'Admin access required',
          code: 'INSUFFICIENT_PERMISSIONS'
        });
      }
    }

    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Admin authentication error:', error);
    return res.status(401).json({
      error: 'Authentication failed',
      code: 'AUTH_FAILED',
      details: error.message
    });
  }
};

const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const idToken = authHeader && authHeader.split(' ')[1];

    if (idToken) {
      const decodedToken = await admin.auth().verifyIdToken(idToken);
      req.user = decodedToken;
    }
    next();
  } catch (error) {
    // Continue without authentication for optional auth if token is invalid
    console.warn('Optional authentication failed:', error.message);
    next();
  }
};

module.exports = {
  authenticateUser,
  requireAdmin,
  optionalAuth
};
