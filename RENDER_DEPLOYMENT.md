# Render Deployment Guide for CyberSafe India Backend

## Prerequisites

1. **Render Account**: Sign up at [render.com](https://render.com)
2. **Database**: Set up a PostgreSQL database (Neon, Supabase, or Render's managed PostgreSQL)
3. **API Keys**: Get API keys from VirusTotal and AbuseIPDB

## Environment Variables

Set these environment variables in your Render dashboard:

### Required Variables
```
DATABASE_URL=postgresql://username:password@hostname:port/database
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```

### Optional Variables
```
NODE_ENV=production
PORT=5000
FRONTEND_URL=https://cybersafe-india.vercel.app
EXTENSION_URL=chrome-extension://your_extension_id
```

## Deployment Steps

### 1. Connect Repository
1. Go to your Render dashboard
2. Click "New +" → "Web Service"
3. Connect your GitHub repository
4. Select the `backend` folder as the root directory

### 2. Configure Build Settings
- **Build Command**: `npm ci`
- **Start Command**: `npm start`
- **Node Version**: 18

### 3. Configure Environment
- **Environment**: Node
- **Region**: Choose closest to your users
- **Instance Type**: Starter (free) or higher for production

### 4. Set Environment Variables
Add all required environment variables in the Render dashboard under "Environment"

### 5. Deploy
Click "Create Web Service" to deploy

## Database Setup

### Option 1: Neon (Recommended)
1. Sign up at [neon.tech](https://neon.tech)
2. Create a new project
3. Copy the connection string
4. Set as `DATABASE_URL` in Render

### Option 2: Render PostgreSQL
1. In Render dashboard, create a new PostgreSQL database
2. Copy the connection string
3. Set as `DATABASE_URL` in Render

### Option 3: Supabase
1. Sign up at [supabase.com](https://supabase.com)
2. Create a new project
3. Go to Settings → Database
4. Copy the connection string
5. Set as `DATABASE_URL` in Render

## API Keys Setup

### VirusTotal API Key
1. Sign up at [virustotal.com](https://virustotal.com)
2. Go to your profile → API Key
3. Copy the key
4. Set as `VIRUSTOTAL_API_KEY` in Render

### AbuseIPDB API Key
1. Sign up at [abuseipdb.com](https://abuseipdb.com)
2. Go to API → API Key
3. Copy the key
4. Set as `ABUSEIPDB_API_KEY` in Render

## Health Check

After deployment, test the health endpoint:
```
https://your-app-name.onrender.com/health
```

Expected response:
```json
{
  "success": true,
  "message": "CyberSafe India API is running",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "version": "1.0.0"
}
```

## API Documentation

Access the API documentation at:
```
https://your-app-name.onrender.com/api
```

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check `DATABASE_URL` format
   - Ensure database is accessible from Render
   - Check SSL settings

2. **API Keys Not Working**
   - Verify API keys are correct
   - Check API key permissions
   - Ensure no extra spaces in environment variables

3. **Build Failures**
   - Check Node.js version (should be 18+)
   - Verify all dependencies are in package.json
   - Check build logs in Render dashboard

4. **CORS Issues**
   - Update `FRONTEND_URL` with your frontend domain (https://cybersafe-india.vercel.app)
   - Check CORS configuration in securityMiddleware.js

### Logs
- View logs in Render dashboard under "Logs" tab
- Check for specific error messages
- Monitor database connection status

## Performance Optimization

### For Production
1. **Upgrade Instance**: Use at least "Starter" plan for production
2. **Database Indexes**: Already configured in the application
3. **Rate Limiting**: Configured to prevent abuse
4. **Caching**: Consider adding Redis for caching

### Monitoring
1. **Health Checks**: Monitor `/health` endpoint
2. **Database**: Monitor connection pool usage
3. **API Usage**: Monitor rate limiting and API calls

## Security Considerations

1. **Environment Variables**: Never commit API keys to repository
2. **HTTPS**: Render provides HTTPS by default
3. **Rate Limiting**: Configured to prevent abuse
4. **CORS**: Properly configured for your frontend domain
5. **Helmet**: Security headers configured

## Scaling

### Horizontal Scaling
- Render supports auto-scaling
- Configure based on your traffic needs
- Monitor performance metrics

### Database Scaling
- Use connection pooling (already configured)
- Consider read replicas for high traffic
- Monitor query performance

## Support

For issues:
1. Check Render logs
2. Verify environment variables
3. Test API endpoints
4. Check database connectivity

## Cost Optimization

1. **Free Tier**: Good for development and testing
2. **Starter Plan**: Recommended for production
3. **Database**: Use managed services for better performance
4. **Monitoring**: Use Render's built-in monitoring
