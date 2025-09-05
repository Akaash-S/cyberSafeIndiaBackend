const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.on('connect', () => {
  console.log('✅ Connected to Neon PostgreSQL database');
});

pool.on('error', (err) => {
  console.error('❌ Database connection error:', err);
  process.exit(-1);
});

// Initialize database tables
const initializeDatabase = async () => {
  try {
    // Create scans table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS scans (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL,
        url TEXT NOT NULL,
        status VARCHAR(50) NOT NULL,
        virustotal_data JSONB,
        abuseipdb_data JSONB,
        scan_date TIMESTAMP DEFAULT NOW()
      )
    `);

    // Create reports table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS reports (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL,
        url TEXT NOT NULL,
        reason TEXT,
        threat_type VARCHAR(50),
        severity VARCHAR(20) DEFAULT 'medium',
        domain VARCHAR(255),
        report_date TIMESTAMP DEFAULT NOW(),
        status VARCHAR(20) DEFAULT 'pending',
        admin_notes TEXT,
        reviewed_by VARCHAR(255),
        reviewed_at TIMESTAMP
      )
    `);

    // Create users table for additional user data
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(255) PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        display_name VARCHAR(255),
        admin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW(),
        last_login TIMESTAMP DEFAULT NOW()
      )
    `);

    // Create safe_urls table for community-verified safe URLs
    await pool.query(`
      CREATE TABLE IF NOT EXISTS safe_urls (
        id SERIAL PRIMARY KEY,
        url TEXT UNIQUE NOT NULL,
        domain VARCHAR(255) NOT NULL,
        report_count INTEGER DEFAULT 0,
        last_verified TIMESTAMP DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW(),
        verified_by VARCHAR(255),
        confidence_score INTEGER DEFAULT 100
      )
    `);

    // Create threat_urls table for community-reported threat URLs
    await pool.query(`
      CREATE TABLE IF NOT EXISTS threat_urls (
        id SERIAL PRIMARY KEY,
        url TEXT UNIQUE NOT NULL,
        domain VARCHAR(255) NOT NULL,
        threat_type VARCHAR(50) NOT NULL,
        report_count INTEGER DEFAULT 1,
        severity VARCHAR(20) DEFAULT 'medium',
        last_reported TIMESTAMP DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW(),
        reported_by VARCHAR(255),
        confidence_score INTEGER DEFAULT 100
      )
    `);

    // Create url_reputation table for tracking URL reputation over time
    await pool.query(`
      CREATE TABLE IF NOT EXISTS url_reputation (
        id SERIAL PRIMARY KEY,
        url TEXT NOT NULL,
        domain VARCHAR(255) NOT NULL,
        reputation_score INTEGER NOT NULL,
        safe_reports INTEGER DEFAULT 0,
        threat_reports INTEGER DEFAULT 0,
        last_updated TIMESTAMP DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Create indexes for better performance
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
      CREATE INDEX IF NOT EXISTS idx_scans_scan_date ON scans(scan_date);
      CREATE INDEX IF NOT EXISTS idx_reports_user_id ON reports(user_id);
      CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
      CREATE INDEX IF NOT EXISTS idx_safe_urls_domain ON safe_urls(domain);
      CREATE INDEX IF NOT EXISTS idx_safe_urls_url ON safe_urls(url);
      CREATE INDEX IF NOT EXISTS idx_threat_urls_domain ON threat_urls(domain);
      CREATE INDEX IF NOT EXISTS idx_threat_urls_url ON threat_urls(url);
      CREATE INDEX IF NOT EXISTS idx_threat_urls_type ON threat_urls(threat_type);
      CREATE INDEX IF NOT EXISTS idx_url_reputation_domain ON url_reputation(domain);
      CREATE INDEX IF NOT EXISTS idx_url_reputation_url ON url_reputation(url);
    `);

    console.log('✅ Database tables initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing database:', error);
    throw error;
  }
};

module.exports = { pool, initializeDatabase };
