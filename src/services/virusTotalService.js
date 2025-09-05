const axios = require('axios');
require('dotenv').config();

class VirusTotalService {
  constructor() {
    this.apiKey = process.env.VIRUSTOTAL_API_KEY;
    this.baseURL = 'https://www.virustotal.com/api/v3';
    this.timeout = 10000; // 10 seconds timeout
  }

  // Scan a URL using VirusTotal API
  async scanUrl(url) {
    try {
      if (!this.apiKey) {
        throw new Error('VirusTotal API key not configured');
      }

      // First, submit URL for scanning
      const scanResponse = await this.submitUrlForScan(url);
      
      if (!scanResponse.data) {
        throw new Error('Failed to submit URL for scanning');
      }

      const analysisId = scanResponse.data.id;
      
      // Wait a moment for analysis to complete
      await this.delay(2000);
      
      // Get analysis results
      const analysisResult = await this.getAnalysisResult(analysisId);
      
      return {
        success: true,
        data: analysisResult,
        scanId: analysisId
      };
    } catch (error) {
      console.error('VirusTotal scan error:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  // Submit URL for scanning
  async submitUrlForScan(url) {
    const response = await axios.post(
      `${this.baseURL}/urls`,
      { url: url },
      {
        headers: {
          'x-apikey': this.apiKey,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: this.timeout
      }
    );
    
    return response.data;
  }

  // Get analysis result
  async getAnalysisResult(analysisId) {
    const response = await axios.get(
      `${this.baseURL}/analyses/${analysisId}`,
      {
        headers: {
          'x-apikey': this.apiKey
        },
        timeout: this.timeout
      }
    );
    
    return response.data;
  }

  // Get URL report (if already scanned)
  async getUrlReport(url) {
    try {
      if (!this.apiKey) {
        throw new Error('VirusTotal API key not configured');
      }

      // Encode URL for API request
      const encodedUrl = Buffer.from(url).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      
      const response = await axios.get(
        `${this.baseURL}/urls/${encodedUrl}`,
        {
          headers: {
            'x-apikey': this.apiKey
          },
          timeout: this.timeout
        }
      );
      
      return {
        success: true,
        data: response.data
      };
    } catch (error) {
      if (error.response?.status === 404) {
        return {
          success: false,
          error: 'URL not found in VirusTotal database',
          data: null
        };
      }
      
      console.error('VirusTotal report error:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  // Analyze scan results and determine threat level
  analyzeThreatLevel(scanData) {
    if (!scanData || !scanData.data) {
      return {
        status: 'unknown',
        confidence: 0,
        details: 'No scan data available'
      };
    }

    const attributes = scanData.data.attributes;
    const stats = attributes?.last_analysis_stats;
    
    if (!stats) {
      return {
        status: 'unknown',
        confidence: 0,
        details: 'No analysis statistics available'
      };
    }

    const { malicious, suspicious, harmless, undetected } = stats;
    const total = malicious + suspicious + harmless + undetected;
    
    if (total === 0) {
      return {
        status: 'unknown',
        confidence: 0,
        details: 'No engines analyzed the URL'
      };
    }

    const maliciousPercentage = (malicious / total) * 100;
    const suspiciousPercentage = (suspicious / total) * 100;

    // More conservative thresholds for better accuracy
    if (maliciousPercentage >= 50) {
      return {
        status: 'malicious',
        confidence: maliciousPercentage,
        details: `${malicious} out of ${total} engines detected this as malicious`
      };
    } else if (maliciousPercentage >= 20 || suspiciousPercentage >= 40) {
      return {
        status: 'suspicious',
        confidence: Math.max(maliciousPercentage, suspiciousPercentage),
        details: `${malicious} malicious, ${suspicious} suspicious out of ${total} engines`
      };
    } else if (maliciousPercentage >= 5 || suspiciousPercentage >= 15) {
      return {
        status: 'suspicious',
        confidence: Math.max(maliciousPercentage, suspiciousPercentage),
        details: `${malicious} malicious, ${suspicious} suspicious out of ${total} engines`
      };
    } else {
      return {
        status: 'safe',
        confidence: 100 - maliciousPercentage - suspiciousPercentage,
        details: `${harmless} out of ${total} engines found this safe`
      };
    }
  }

  // Utility function for delays
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = new VirusTotalService();
