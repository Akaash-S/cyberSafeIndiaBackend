const admin = require('firebase-admin');
const path = require('path');
require('dotenv').config();


// Check if FIREBASE_SERVICE_ACCOUNT_PATH is provided
if (!process.env.FIREBASE_SERVICE_ACCOUNT_PATH) {
  console.error('❌ FIREBASE_SERVICE_ACCOUNT_PATH environment variable is required');
  console.error('Please set it to the path of your Firebase service account key file.');
  process.exit(1);
}

const serviceAccountPath = path.resolve(process.env.FIREBASE_SERVICE_ACCOUNT_PATH);

try {
  const serviceAccount = require(serviceAccountPath);

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log('✅ Firebase Admin SDK initialized successfully');
} catch (error) {
  console.error('❌ Error initializing Firebase Admin SDK:', error);
  console.error('Please ensure FIREBASE_SERVICE_ACCOUNT_PATH points to a valid service account key file.');
  process.exit(1);
}

module.exports = admin;
