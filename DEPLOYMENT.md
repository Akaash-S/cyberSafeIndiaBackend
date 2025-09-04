# 🚀 CyberSafe India Backend - Deployment Guide

This guide covers deploying the CyberSafe India backend API to production.

## 📋 Prerequisites

- Node.js 18+ installed
- PostgreSQL database (Neon recommended)
- Firebase project with Admin SDK
- VirusTotal API key
- AbuseIPDB API key
- Domain name (for production)

## 🗄️ Database Setup

### 1. Create Neon PostgreSQL Database

1. Go to [Neon Console](https://console.neon.tech/)
2. Create a new project
3. Copy the connection string
4. Update your `.env` file with the `DATABASE_URL`

### 2. Initialize Database Tables

```bash
npm run init-db
```

This will create all necessary tables and indexes.

## 🔑 API Keys Setup

### 1. VirusTotal API Key

1. Go to [VirusTotal](https://www.virustotal.com/)
2. Create an account
3. Get your API key from the profile section
4. Add to `.env`: `VIRUSTOTAL_API_KEY=your_key_here`

### 2. AbuseIPDB API Key

1. Go to [AbuseIPDB](https://www.abuseipdb.com/)
2. Create an account
3. Get your API key from the account section
4. Add to `.env`: `ABUSEIPDB_API_KEY=your_key_here`

## 🔥 Firebase Setup

### 1. Create Firebase Project

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Create a new project
3. Enable Authentication
4. Add your domain to authorized domains

### 2. Generate Service Account Key

1. Go to Project Settings > Service Accounts
2. Generate new private key
3. Download the JSON file
4. Extract the values and add to `.env`:

```env
FIREBASE_PROJECT_ID=your_project_id
FIREBASE_PRIVATE_KEY_ID=your_private_key_id
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nyour_key\n-----END PRIVATE KEY-----\n"
FIREBASE_CLIENT_EMAIL=your_client_email
FIREBASE_CLIENT_ID=your_client_id
FIREBASE_AUTH_URI=https://accounts.google.com/o/oauth2/auth
FIREBASE_TOKEN_URI=https://oauth2.googleapis.com/token
```

## 🌐 Deployment Options

### Option 1: Render (Recommended)

1. **Connect Repository**
   - Go to [Render](https://render.com/)
   - Connect your GitHub repository
   - Select the backend folder

2. **Configure Build Settings**
   ```
   Build Command: npm install
   Start Command: npm start
   Node Version: 18
   ```

3. **Set Environment Variables**
   - Add all variables from your `.env` file
   - Set `NODE_ENV=production`
   - Update `FRONTEND_URL` to your production domain

4. **Deploy**
   - Click "Deploy"
   - Wait for deployment to complete
   - Note the provided URL

### Option 2: Heroku

1. **Install Heroku CLI**
   ```bash
   npm install -g heroku
   ```

2. **Create Heroku App**
   ```bash
   heroku create cybersafe-india-backend
   ```

3. **Set Environment Variables**
   ```bash
   heroku config:set NODE_ENV=production
   heroku config:set DATABASE_URL=your_database_url
   # ... add all other variables
   ```

4. **Deploy**
   ```bash
   git push heroku main
   ```

### Option 3: DigitalOcean App Platform

1. **Create App**
   - Go to DigitalOcean App Platform
   - Connect your repository
   - Select Node.js

2. **Configure**
   - Set build command: `npm install`
   - Set run command: `npm start`
   - Add environment variables

3. **Deploy**
   - Click "Create Resources"
   - Wait for deployment

### Option 4: AWS EC2

1. **Launch EC2 Instance**
   - Choose Ubuntu 20.04 LTS
   - Configure security groups (port 5000)

2. **Install Dependencies**
   ```bash
   sudo apt update
   sudo apt install nodejs npm nginx
   ```

3. **Deploy Application**
   ```bash
   git clone your-repo
   cd backend
   npm install
   npm start
   ```

4. **Configure Nginx**
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;
       
       location / {
           proxy_pass http://localhost:5000;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection 'upgrade';
           proxy_set_header Host $host;
           proxy_cache_bypass $http_upgrade;
       }
   }
   ```

## 🔒 Production Security

### 1. Environment Variables

Ensure all sensitive data is in environment variables:
- Never commit `.env` files
- Use strong, unique API keys
- Rotate keys regularly

### 2. HTTPS Setup

- Use SSL certificates (Let's Encrypt recommended)
- Redirect HTTP to HTTPS
- Set secure headers

### 3. Database Security

- Use connection pooling
- Enable SSL for database connections
- Regular backups
- Monitor database performance

### 4. Monitoring

- Set up error tracking (Sentry)
- Monitor API performance
- Set up alerts for failures
- Log analysis

## 📊 Health Checks

### Basic Health Check
```bash
curl https://your-api-domain.com/health
```

### API Documentation
```bash
curl https://your-api-domain.com/api
```

## 🚨 Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check `DATABASE_URL` format
   - Verify database is accessible
   - Check firewall settings

2. **Firebase Authentication Failed**
   - Verify service account key
   - Check project ID
   - Ensure private key format is correct

3. **API Keys Not Working**
   - Verify key format
   - Check API quotas
   - Test keys independently

4. **CORS Issues**
   - Update `FRONTEND_URL` in environment
   - Check allowed origins
   - Verify domain configuration

### Logs

Check application logs for errors:
```bash
# Render
# Check dashboard logs

# Heroku
heroku logs --tail

# DigitalOcean
# Check app logs in dashboard

# EC2
pm2 logs
# or
journalctl -u your-app
```

## 🔄 Updates and Maintenance

### 1. Database Migrations

When updating the database schema:
```bash
npm run init-db
```

### 2. Application Updates

1. Update code
2. Test locally
3. Deploy to staging
4. Deploy to production

### 3. Monitoring

- Set up uptime monitoring
- Monitor API response times
- Track error rates
- Monitor database performance

## 📈 Scaling

### Horizontal Scaling

- Use load balancers
- Multiple app instances
- Database read replicas
- CDN for static assets

### Vertical Scaling

- Increase server resources
- Optimize database queries
- Use connection pooling
- Cache frequently accessed data

## 🆘 Support

If you encounter issues:

1. Check the logs
2. Verify environment variables
3. Test API endpoints
4. Check database connectivity
5. Create an issue in the repository

---

**Happy Deploying! 🚀**

For more help, refer to the main README.md or create an issue.
