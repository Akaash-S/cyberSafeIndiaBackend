# 🔐 CyberSafe India - Backend API

A comprehensive backend API for URL scanning and threat detection, built with Node.js, Express.js, and PostgreSQL.

## 🚀 Features

- **URL Scanning**: Integration with VirusTotal and AbuseIPDB APIs
- **User Authentication**: Firebase Admin SDK integration
- **Scan History**: Personalized scan tracking and management
- **Community Reporting**: User-driven threat reporting system
- **Analytics**: Comprehensive threat analysis and insights
- **Admin Panel**: Complete administrative controls
- **Security**: Rate limiting, CORS, Helmet, and input validation

## 🛠️ Tech Stack

- **Runtime**: Node.js 18+
- **Framework**: Express.js
- **Database**: Neon PostgreSQL
- **Authentication**: Firebase Admin SDK
- **Security**: Helmet, CORS, Rate Limiting
- **APIs**: VirusTotal, AbuseIPDB

## 📋 Prerequisites

- Node.js 18 or higher
- PostgreSQL database (Neon recommended)
- Firebase project with Admin SDK
- VirusTotal API key
- AbuseIPDB API key

## 🚀 Quick Start

### 1. Clone and Install

```bash
cd backend
npm install
```

### 2. Environment Setup

Copy the example environment file and configure:

```bash
cp env.example .env
```

Update `.env` with your configuration:

```env
# Database
DATABASE_URL=your_neon_postgresql_connection_string

# Firebase
FIREBASE_PROJECT_ID=your_project_id
FIREBASE_PRIVATE_KEY_ID=your_private_key_id
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nyour_key\n-----END PRIVATE KEY-----\n"
FIREBASE_CLIENT_EMAIL=your_client_email
FIREBASE_CLIENT_ID=your_client_id

# API Keys
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key

# Server
PORT=5000
NODE_ENV=development
FRONTEND_URL=http://localhost:5173
```

### 3. Start Development Server

```bash
npm run dev
```

The server will start on `http://localhost:5000`

## 📚 API Documentation

### Base URL
```
http://localhost:5000/api
```

### Authentication
Most endpoints require a Firebase JWT token in the Authorization header:
```
Authorization: Bearer <firebase_token>
```

### Core Endpoints

#### URL Scanning
- `POST /api/scan` - Scan a single URL
- `POST /api/scan/batch` - Scan multiple URLs (authenticated)

#### Scan History
- `GET /api/history` - Get scan history (authenticated)
- `GET /api/history/stats` - Get scan statistics (authenticated)
- `DELETE /api/history/:id` - Delete specific scan (authenticated)
- `GET /api/history/export` - Export as CSV (authenticated)

#### Community Reports
- `POST /api/report` - Submit suspicious URL report (authenticated)
- `GET /api/reports` - Get all reports (admin only)
- `PUT /api/reports/:id/status` - Update report status (admin only)

#### Analytics
- `GET /api/analytics/overview` - Get analytics overview (authenticated)
- `GET /api/analytics/trends` - Get scan trends (authenticated)
- `GET /api/analytics/threats` - Get threat analysis (authenticated)

#### Admin Panel
- `GET /api/admin/users` - Get all users (admin only)
- `GET /api/admin/system` - Get system information (admin only)
- `POST /api/admin/maintenance` - Perform maintenance (admin only)

## 🗄️ Database Schema

### Tables

#### users
- `id` (VARCHAR) - Firebase UID
- `email` (VARCHAR) - User email
- `display_name` (VARCHAR) - User display name
- `created_at` (TIMESTAMP) - Account creation date
- `last_login` (TIMESTAMP) - Last login date

#### scans
- `id` (SERIAL) - Primary key
- `user_id` (VARCHAR) - Foreign key to users
- `url` (TEXT) - Scanned URL
- `status` (VARCHAR) - Scan result (safe/suspicious/malicious/unknown)
- `virustotal_data` (JSONB) - VirusTotal response
- `abuseipdb_data` (JSONB) - AbuseIPDB response
- `scan_date` (TIMESTAMP) - Scan timestamp

#### reports
- `id` (SERIAL) - Primary key
- `user_id` (VARCHAR) - Foreign key to users
- `url` (TEXT) - Reported URL
- `reason` (TEXT) - Report reason
- `status` (VARCHAR) - Report status (pending/approved/rejected)
- `report_date` (TIMESTAMP) - Report timestamp

## 🔒 Security Features

- **Rate Limiting**: Prevents API abuse
- **CORS**: Configured for frontend and extension access
- **Helmet**: Security headers
- **Input Validation**: Joi schema validation
- **Authentication**: Firebase JWT verification
- **Authorization**: Role-based access control

## 🚀 Deployment

### Environment Variables for Production

```env
NODE_ENV=production
DATABASE_URL=your_production_database_url
PORT=5000
FRONTEND_URL=https://cybersafe-india.vercel.app
EXTENSION_URL=chrome-extension://your-extension-id
```

### Deploy to Render

1. Connect your GitHub repository
2. Set environment variables
3. Deploy automatically

## 🧪 Testing

```bash
# Run tests
npm test

# Run with coverage
npm run test:coverage
```

## 📊 Monitoring

- Health check: `GET /health`
- API documentation: `GET /api`
- Request logging with Morgan
- Error tracking and reporting

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Contact the development team

---

**CyberSafe India** - Protecting users from cyber threats, one scan at a time.
