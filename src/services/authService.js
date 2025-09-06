const admin = require('../config/firebaseAdmin');
const { pool } = require('../config/db');

class AuthService {
  async loginOrRegister(idToken) {
    try {
      const decodedToken = await admin.auth().verifyIdToken(idToken);
      const { uid, email, name, picture } = decodedToken;

      // Check if user exists in our database
      let userResult = await pool.query('SELECT * FROM users WHERE id = $1', [uid]);
      let user = userResult.rows[0];

      if (!user) {
        // User does not exist, create new user
        const insertQuery = `
          INSERT INTO users (id, email, display_name, photo_url, firebase_uid, last_login, email_verified)
          VALUES ($1, $2, $3, $4, $5, NOW(), $6)
          RETURNING *;
        `;
        const insertValues = [uid, email, name || null, picture || null, uid, decodedToken.email_verified || false];
        userResult = await pool.query(insertQuery, insertValues);
        user = userResult.rows[0];
      } else {
        // User exists, update last login time and email_verified status
        const updateQuery = `
          UPDATE users
          SET last_login = NOW(), email_verified = $1
          WHERE id = $2
          RETURNING *;
        `;
        const updateValues = [decodedToken.email_verified || false, uid];
        userResult = await pool.query(updateQuery, updateValues);
        user = userResult.rows[0];
      }

      // If email is not verified, send verification email
      if (!user.email_verified) {
        const actionCodeSettings = {
          url: `${process.env.FRONTEND_URL}/verify-email`, // Frontend URL for email verification
          handleCodeInApp: true,
        };
        const link = await admin.auth().generateEmailVerificationLink(email, actionCodeSettings);
        return { user, emailVerified: false, verificationLink: link };
      }

      return { user, emailVerified: true };

    } catch (error) {
      console.error('Error in loginOrRegister:', error);
      throw error;
    }
  }

  async verifyEmail(oobCode) {
    try {
      const result = await admin.auth().applyActionCode(oobCode);
      const user = await admin.auth().getUser(result.operationType === 'VERIFY_EMAIL' ? result.email : null);

      if (!user || !user.emailVerified) {
        throw new Error('Email verification failed or user not found.');
      }

      // Update email_verified status in our database
      await pool.query('UPDATE users SET email_verified = TRUE WHERE id = $1', [user.uid]);

      return { success: true, message: 'Email verified successfully.' };
    } catch (error) {
      console.error('Error verifying email:', error);
      throw error;
    }
  }
}

module.exports = new AuthService();
