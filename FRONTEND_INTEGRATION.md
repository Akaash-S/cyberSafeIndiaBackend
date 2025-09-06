# 🔗 Frontend Integration Guide

This guide explains how to integrate the CyberSafe India backend with your React frontend that uses Firebase authentication.

## 🔄 **Authentication Flow**

### 1. **Frontend (React + Firebase)**
- User logs in with Firebase
- Firebase returns user data and JWT token
- Frontend sends user data to backend for storage

### 2. **Backend (Node.js + PostgreSQL)**
- Receives user data from frontend
- Stores user in PostgreSQL database
- No Firebase Admin SDK needed

## 🚀 **Frontend Implementation**

### 1. **User Registration After Firebase Auth**

```javascript
// After successful Firebase login
import { auth } from './firebase';

const registerUserWithBackend = async (user) => {
  try {
    const userData = {
      uid: user.uid,
      email: user.email,
      displayName: user.displayName,
      photoURL: user.photoURL,
      admin: false // Set to true for admin users
    };

    const response = await fetch('http://localhost:5000/api/user/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(userData)
    });

    const result = await response.json();
    
    if (result.success) {
      console.log('User registered with backend:', result.data);
    } else {
      console.error('Registration failed:', result.error);
    }
  } catch (error) {
    console.error('Error registering user:', error);
  }
};

// Call this after Firebase login
auth.onAuthStateChanged((user) => {
  if (user) {
    registerUserWithBackend(user);
  }
});
```

### 2. **Sending Authenticated Requests**

```javascript
// Helper function to create auth header
const createAuthHeader = (user) => {
  const userData = {
    uid: user.uid,
    email: user.email,
    displayName: user.displayName,
    photoURL: user.photoURL,
    admin: false // Get this from your user state
  };
  
  const encodedData = Buffer.from(JSON.stringify(userData)).toString('base64');
  return `Bearer ${encodedData}`;
};

// Example: Scan a URL
const scanUrl = async (url, user) => {
  try {
    const response = await fetch('http://localhost:5000/api/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': createAuthHeader(user)
      },
      body: JSON.stringify({ url })
    });

    const result = await response.json();
    return result;
  } catch (error) {
    console.error('Scan error:', error);
    throw error;
  }
};

// Example: Get scan history
const getScanHistory = async (user) => {
  try {
    const response = await fetch('http://localhost:5000/api/history', {
      headers: {
        'Authorization': createAuthHeader(user)
      }
    });

    const result = await response.json();
    return result;
  } catch (error) {
    console.error('History fetch error:', error);
    throw error;
  }
};
```

### 3. **Complete Auth Context Example**

```javascript
// AuthContext.js
import React, { createContext, useContext, useState, useEffect } from 'react';
import { auth } from './firebase';

const AuthContext = createContext();

export const useAuth = () => {
  return useContext(AuthContext);
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Register user with backend after Firebase auth
  const registerUserWithBackend = async (firebaseUser) => {
    try {
      const userData = {
        uid: firebaseUser.uid,
        email: firebaseUser.email,
        displayName: firebaseUser.displayName,
        photoURL: firebaseUser.photoURL,
        admin: false
      };

      const response = await fetch('http://localhost:5000/api/user/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(userData)
      });

      const result = await response.json();
      
      if (result.success) {
        setUser({
          ...firebaseUser,
          backendData: result.data
        });
      }
    } catch (error) {
      console.error('Error registering user with backend:', error);
    }
  };

  useEffect(() => {
    const unsubscribe = auth.onAuthStateChanged(async (firebaseUser) => {
      if (firebaseUser) {
        await registerUserWithBackend(firebaseUser);
      } else {
        setUser(null);
      }
      setLoading(false);
    });

    return unsubscribe;
  }, []);

  const value = {
    user,
    loading,
    createAuthHeader: (user) => {
      const userData = {
        uid: user.uid,
        email: user.email,
        displayName: user.displayName,
        photoURL: user.photoURL,
        admin: user.backendData?.admin || false
      };
      
      const encodedData = Buffer.from(JSON.stringify(userData)).toString('base64');
      return `Bearer ${encodedData}`;
    }
  };

  return (
    <AuthContext.Provider value={value}>
      {!loading && children}
    </AuthContext.Provider>
  );
};
```

### 4. **API Service Example**

```javascript
// apiService.js
class ApiService {
  constructor(baseURL = 'http://localhost:5000/api') {
    this.baseURL = baseURL;
  }

  // Helper method to create auth header
  createAuthHeader(user) {
    const userData = {
      uid: user.uid,
      email: user.email,
      displayName: user.displayName,
      photoURL: user.photoURL,
      admin: user.backendData?.admin || false
    };
    
    const encodedData = Buffer.from(JSON.stringify(userData)).toString('base64');
    return `Bearer ${encodedData}`;
  }

  // Scan URL
  async scanUrl(url, user) {
    const response = await fetch(`${this.baseURL}/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': this.createAuthHeader(user)
      },
      body: JSON.stringify({ url })
    });

    return response.json();
  }

  // Get scan history
  async getScanHistory(user, params = {}) {
    const queryString = new URLSearchParams(params).toString();
    const response = await fetch(`${this.baseURL}/history?${queryString}`, {
      headers: {
        'Authorization': this.createAuthHeader(user)
      }
    });

    return response.json();
  }

  // Submit report
  async submitReport(url, reason, user) {
    const response = await fetch(`${this.baseURL}/report`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': this.createAuthHeader(user)
      },
      body: JSON.stringify({ url, reason })
    });

    return response.json();
  }

  // Get analytics
  async getAnalytics(user, type = 'overview') {
    const response = await fetch(`${this.baseURL}/analytics/${type}`, {
      headers: {
        'Authorization': this.createAuthHeader(user)
      }
    });

    return response.json();
  }
}

export default new ApiService();
```

## 🔧 **Environment Variables**

### Frontend (.env)
```env
VITE_API_BASE_URL=https://cybersafeindiabackend-1.onrender.com/api
REACT_APP_FIREBASE_API_KEY=your_firebase_api_key
REACT_APP_FIREBASE_AUTH_DOMAIN=your_project.firebaseapp.com
REACT_APP_FIREBASE_PROJECT_ID=your_project_id
```

### Backend (.env)
```env
DATABASE_URL=your_neon_postgresql_connection_string
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
PORT=5000
NODE_ENV=development
FRONTEND_URL=https://cybersafe-india.vercel.app
```

## 🚨 **Important Notes**

1. **No Firebase Admin SDK**: Backend doesn't need Firebase Admin SDK
2. **User Data Storage**: Backend stores user data in PostgreSQL
3. **Authentication**: Frontend handles Firebase auth, backend stores user info
4. **Admin Users**: Set `admin: true` in user data for admin access
5. **Security**: User data is base64 encoded in Authorization header

## 🔄 **Complete Flow Example**

```javascript
// 1. User logs in with Firebase
const signInWithGoogle = async () => {
  const provider = new GoogleAuthProvider();
  const result = await signInWithPopup(auth, provider);
  // User is automatically registered with backend via onAuthStateChanged
};

// 2. Use authenticated API calls
const handleScanUrl = async () => {
  if (user) {
    const result = await apiService.scanUrl(url, user);
    console.log('Scan result:', result);
  }
};

// 3. Get user profile
const getUserProfile = async () => {
  if (user) {
    const response = await fetch('https://cybersafeindiabackend-1.onrender.com/api/user/profile', {
      headers: {
        'Authorization': createAuthHeader(user)
      }
    });
    const profile = await response.json();
    console.log('User profile:', profile);
  }
};
```

## 🆘 **Troubleshooting**

### Common Issues:

1. **CORS Errors**: Make sure `FRONTEND_URL` is set in backend `.env`
2. **Authentication Errors**: Check if user data is properly encoded
3. **Database Errors**: Ensure user is registered with backend first
4. **Admin Access**: Set `admin: true` in user data for admin endpoints

### Debug Tips:

```javascript
// Check if user data is properly formatted
console.log('User data:', {
  uid: user.uid,
  email: user.email,
  displayName: user.displayName,
  admin: user.backendData?.admin
});

// Check auth header
const authHeader = createAuthHeader(user);
console.log('Auth header:', authHeader);
```

---

**Ready to integrate! 🚀**

Your frontend can now handle Firebase authentication and communicate with the backend API without needing Firebase Admin SDK.
