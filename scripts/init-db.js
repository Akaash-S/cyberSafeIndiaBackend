const { pool, initializeDatabase } = require('../src/config/db');
require('dotenv').config();

async function initDatabase() {
  try {
    console.log('🔄 Initializing CyberSafe India database...');
    
    // Initialize database tables
    await initializeDatabase();
    
    console.log('✅ Database initialization completed successfully!');
    console.log('📊 Tables created:');
    console.log('   - users');
    console.log('   - scans');
    console.log('   - reports');
    console.log('   - safe_urls');
    console.log('   - threat_urls');
    console.log('   - url_reputation');
    console.log('   - Indexes created for optimal performance');
    
    process.exit(0);
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    process.exit(1);
  }
}

// Run initialization
initDatabase();
