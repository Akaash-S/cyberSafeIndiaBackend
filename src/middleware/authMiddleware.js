const { pool } = require('../config/db');

// Simple authentication middleware - expects user data from frontend
const authenticateUser = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const userData = authHeader && authHeader.split(' ')[1]; // Bearer <user_data_json>

    if (!userData) {
      return res.status(401).json({ 
        error: 'User authentication required',
        code: 'MISSING_AUTH'
      });
    }

    // Parse user data sent from frontend
    const user = JSON.parse(Buffer.from(userData, 'base64').toString());
    
    // Validate required fields
    if (!user.uid || !user.email) {
      return res.status(401).json({ 
        error: 'Invalid user data',
        code: 'INVALID_USER_DATA'
      });
    }

    // Attach user info to request object
    req.user = {
      uid: user.uid,
      email: user.email,
      name: user.name || user.displayName,
      picture: user.picture || user.photoURL,
      admin: user.admin || false
    };

    // Update or create user in database
    await updateUserInDatabase(req.user);

    next();
  } catch (error) {
    console.error('Authentication error:', error);
    return res.status(401).json({ 
      error: 'Authentication failed',
      code: 'AUTH_FAILED'
    });
  }
};

// Middleware to check if user is admin
const requireAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const userData = authHeader && authHeader.split(' ')[1];

    if (!userData) {
      return res.status(401).json({ 
        error: 'User authentication required',
        code: 'MISSING_AUTH'
      });
    }

    const user = JSON.parse(Buffer.from(userData, 'base64').toString());
    
    if (!user.uid || !user.email) {
      return res.status(401).json({ 
        error: 'Invalid user data',
        code: 'INVALID_USER_DATA'
      });
    }

    // Check if user is admin in database
    const adminCheck = await pool.query(
      'SELECT admin FROM users WHERE id = $1',
      [user.uid]
    );

    if (adminCheck.rows.length === 0 || !adminCheck.rows[0].admin) {
      return res.status(403).json({ 
        error: 'Admin access required',
        code: 'INSUFFICIENT_PERMISSIONS'
      });
    }

    req.user = {
      uid: user.uid,
      email: user.email,
      name: user.name || user.displayName,
      picture: user.picture || user.photoURL,
      admin: true
    };

    next();
  } catch (error) {
    console.error('Admin authentication error:', error);
    return res.status(401).json({ 
      error: 'Authentication failed',
      code: 'AUTH_FAILED'
    });
  }
};

// Helper function to update or create user in database
const updateUserInDatabase = async (user) => {
  try {
    const query = `
      INSERT INTO users (id, email, display_name, last_login, admin)
      VALUES ($1, $2, $3, NOW(), $4)
      ON CONFLICT (id) 
      DO UPDATE SET 
        email = EXCLUDED.email,
        display_name = EXCLUDED.display_name,
        last_login = NOW()
    `;
    
    await pool.query(query, [user.uid, user.email, user.name, user.admin || false]);
  } catch (error) {
    console.error('Error updating user in database:', error);
    // Don't throw error here as it's not critical for authentication
  }
};

// Optional authentication middleware (doesn't fail if no auth)
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const userData = authHeader && authHeader.split(' ')[1];

    if (userData) {
      const user = JSON.parse(Buffer.from(userData, 'base64').toString());
      
      if (user.uid && user.email) {
        req.user = {
          uid: user.uid,
          email: user.email,
          name: user.name || user.displayName,
          picture: user.picture || user.photoURL,
          admin: user.admin || false
        };
        await updateUserInDatabase(req.user);
      }
    }

    next();
  } catch (error) {
    // Continue without authentication for optional auth
    next();
  }
};

module.exports = {
  authenticateUser,
  requireAdmin,
  optionalAuth
};
