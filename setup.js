#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

console.log('🔧 CyberSafe India Backend Setup');
console.log('================================\n');

// Check if .env file exists
const envPath = path.join(__dirname, '.env');
const envExamplePath = path.join(__dirname, 'env.example');

if (fs.existsSync(envPath)) {
  console.log('✅ .env file already exists');
  console.log('📝 Please update it with your actual database credentials\n');
} else {
  console.log('❌ .env file not found');
  console.log('📝 Creating .env file from template...\n');
  
  if (fs.existsSync(envExamplePath)) {
    // Copy env.example to .env
    const envExample = fs.readFileSync(envExamplePath, 'utf8');
    fs.writeFileSync(envPath, envExample);
    console.log('✅ Created .env file from template');
  } else {
    // Create basic .env file
    const basicEnv = `# Database Configuration
DATABASE_URL=postgresql://username:password@hostname:port/database

# API Keys
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

# Server Configuration
PORT=5000
NODE_ENV=development

# CORS Configuration
FRONTEND_URL=http://localhost:5173
EXTENSION_URL=chrome-extension://your_extension_id
`;
    fs.writeFileSync(envPath, basicEnv);
    console.log('✅ Created basic .env file');
  }
}

console.log('\n📋 Next Steps:');
console.log('1. Update the .env file with your actual database credentials');
console.log('2. Get API keys from:');
console.log('   - VirusTotal: https://www.virustotal.com/gui/my-apikey');
console.log('   - AbuseIPDB: https://www.abuseipdb.com/account/api');
console.log('3. Run: npm start');
console.log('\n💡 For Neon PostgreSQL:');
console.log('   - Sign up at https://neon.tech');
console.log('   - Create a new project');
console.log('   - Copy the connection string to DATABASE_URL');
console.log('\n🚀 Happy coding!');
