const axios = require('axios');
require('dotenv').config();

class AbuseIPService {
  constructor() {
    this.apiKey = process.env.ABUSEIPDB_API_KEY;
    this.baseURL = 'https://api.abuseipdb.com/api/v2';
    this.timeout = 10000; // 10 seconds timeout
  }

  // Check IP address using AbuseIPDB API
  async checkIp(ipAddress) {
    try {
      if (!this.apiKey) {
        throw new Error('AbuseIPDB API key not configured');
      }

      const response = await axios.get(
        `${this.baseURL}/check`,
        {
          params: {
            ipAddress: ipAddress,
            maxAgeInDays: 90,
            verbose: ''
          },
          headers: {
            'Key': this.apiKey,
            'Accept': 'application/json'
          },
          timeout: this.timeout
        }
      );

      return {
        success: true,
        data: response.data
      };
    } catch (error) {
      console.error('AbuseIPDB check error:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  // Check domain using AbuseIPDB API
  async checkDomain(domain) {
    try {
      if (!this.apiKey) {
        throw new Error('AbuseIPDB API key not configured');
      }

      // First, resolve domain to IP
      const ipAddress = await this.resolveDomain(domain);
      
      if (!ipAddress) {
        return {
          success: false,
          error: 'Could not resolve domain to IP address',
          data: null
        };
      }

      // Check the resolved IP
      return await this.checkIp(ipAddress);
    } catch (error) {
      console.error('AbuseIPDB domain check error:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  // Check URL by extracting domain and checking it
  async checkUrl(url) {
    try {
      const domain = this.extractDomain(url);
      
      if (!domain) {
        return {
          success: false,
          error: 'Could not extract domain from URL',
          data: null
        };
      }

      return await this.checkDomain(domain);
    } catch (error) {
      console.error('AbuseIPDB URL check error:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  // Report IP address to AbuseIPDB
  async reportIp(ipAddress, categories, comment) {
    try {
      if (!this.apiKey) {
        throw new Error('AbuseIPDB API key not configured');
      }

      const response = await axios.post(
        `${this.baseURL}/report`,
        {
          ip: ipAddress,
          categories: categories.join(','),
          comment: comment
        },
        {
          headers: {
            'Key': this.apiKey,
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          timeout: this.timeout
        }
      );

      return {
        success: true,
        data: response.data
      };
    } catch (error) {
      console.error('AbuseIPDB report error:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  // Analyze AbuseIPDB results and determine threat level
  analyzeThreatLevel(abuseData) {
    if (!abuseData || !abuseData.data) {
      return {
        status: 'unknown',
        confidence: 0,
        details: 'No AbuseIPDB data available'
      };
    }

    const data = abuseData.data;
    const abuseConfidence = data.abuseConfidencePercentage || 0;
    const totalReports = data.totalReports || 0;
    const isWhitelisted = data.isWhitelisted || false;
    const isPublic = data.isPublic || false;

    if (isWhitelisted) {
      return {
        status: 'safe',
        confidence: 100,
        details: 'IP is whitelisted in AbuseIPDB'
      };
    }

    // More conservative thresholds for better accuracy
    if (abuseConfidence >= 75) {
      return {
        status: 'malicious',
        confidence: abuseConfidence,
        details: `High abuse confidence (${abuseConfidence}%) with ${totalReports} reports`
      };
    } else if (abuseConfidence >= 50) {
      return {
        status: 'suspicious',
        confidence: abuseConfidence,
        details: `Moderate abuse confidence (${abuseConfidence}%) with ${totalReports} reports`
      };
    } else if (abuseConfidence >= 25) {
      return {
        status: 'suspicious',
        confidence: abuseConfidence,
        details: `Low abuse confidence (${abuseConfidence}%) with ${totalReports} reports`
      };
    } else if (totalReports > 5) {
      return {
        status: 'suspicious',
        confidence: abuseConfidence,
        details: `Multiple reports (${totalReports}) with low confidence (${abuseConfidence}%)`
      };
    } else {
      return {
        status: 'safe',
        confidence: 100 - abuseConfidence,
        details: 'No significant abuse reports found'
      };
    }
  }

  // Extract domain from URL
  extractDomain(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch (error) {
      console.error('Error extracting domain from URL:', error);
      return null;
    }
  }

  // Resolve domain to IP address
  async resolveDomain(domain) {
    try {
      const dns = require('dns').promises;
      const addresses = await dns.resolve4(domain);
      return addresses[0]; // Return first IPv4 address
    } catch (error) {
      console.error('Error resolving domain:', error);
      return null;
    }
  }

  // Get category names for reporting
  getCategoryNames() {
    return {
      1: 'DNS Compromise',
      2: 'DNS Poisoning',
      3: 'Fraud Orders',
      4: 'DDoS Attack',
      5: 'FTP Brute-Force',
      6: 'Ping of Death',
      7: 'Phishing',
      8: 'Fraud VoIP',
      9: 'Open Proxy',
      10: 'Web Spam',
      11: 'Email Spam',
      12: 'Blog Spam',
      13: 'VPN IP',
      14: 'Port Scan',
      15: 'Hacking',
      16: 'SQL Injection',
      17: 'Spoofing',
      18: 'Brute-Force',
      19: 'Bad Web Bot',
      20: 'Exploited Host',
      21: 'Web App Attack',
      22: 'SSH',
      23: 'IoT Targeted'
    };
  }
}

module.exports = new AbuseIPService();
