const { pool } = require('../config/db');

class ReputationService {
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

  // Check URL reputation in community database
  async checkUrlReputation(url) {
    try {
      const domain = this.extractDomain(url);
      if (!domain) {
        return {
          success: false,
          error: 'Invalid URL format',
          data: null
        };
      }

      // Check if URL is in threat database
      const threatResult = await pool.query(
        'SELECT * FROM threat_urls WHERE url = $1 OR domain = $2 ORDER BY report_count DESC LIMIT 1',
        [url, domain]
      );

      if (threatResult.rows.length > 0) {
        const threat = threatResult.rows[0];
        return {
          success: true,
          data: {
            reputation: 'threat',
            threatType: threat.threat_type,
            severity: threat.severity,
            reportCount: threat.report_count,
            confidence: threat.confidence_score,
            lastReported: threat.last_reported,
            source: 'community'
          }
        };
      }

      // Check if URL is in safe database
      const safeResult = await pool.query(
        'SELECT * FROM safe_urls WHERE url = $1 OR domain = $2 ORDER BY report_count DESC LIMIT 1',
        [url, domain]
      );

      if (safeResult.rows.length > 0) {
        const safe = safeResult.rows[0];
        return {
          success: true,
          data: {
            reputation: 'safe',
            reportCount: safe.report_count,
            confidence: safe.confidence_score,
            lastVerified: safe.last_verified,
            source: 'community'
          }
        };
      }

      // Check URL reputation table for historical data
      const reputationResult = await pool.query(
        'SELECT * FROM url_reputation WHERE url = $1 OR domain = $2 ORDER BY last_updated DESC LIMIT 1',
        [url, domain]
      );

      if (reputationResult.rows.length > 0) {
        const reputation = reputationResult.rows[0];
        const reputationScore = reputation.reputation_score;
        
        let reputationStatus = 'unknown';
        if (reputationScore >= 70) {
          reputationStatus = 'safe';
        } else if (reputationScore <= 30) {
          reputationStatus = 'threat';
        } else {
          reputationStatus = 'suspicious';
        }

        return {
          success: true,
          data: {
            reputation: reputationStatus,
            score: reputationScore,
            safeReports: reputation.safe_reports,
            threatReports: reputation.threat_reports,
            lastUpdated: reputation.last_updated,
            source: 'historical'
          }
        };
      }

      // No reputation data found
      return {
        success: true,
        data: {
          reputation: 'unknown',
          source: 'none'
        }
      };

    } catch (error) {
      console.error('Error checking URL reputation:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  // Report URL as threat
  async reportThreatUrl(url, threatType, severity, reportedBy) {
    try {
      const domain = this.extractDomain(url);
      if (!domain) {
        return {
          success: false,
          error: 'Invalid URL format'
        };
      }

      // Check if URL already exists in threat database
      const existingThreat = await pool.query(
        'SELECT * FROM threat_urls WHERE url = $1',
        [url]
      );

      if (existingThreat.rows.length > 0) {
        // Update existing threat report
        await pool.query(
          'UPDATE threat_urls SET report_count = report_count + 1, last_reported = NOW(), confidence_score = LEAST(confidence_score + 5, 100) WHERE url = $1',
          [url]
        );
      } else {
        // Insert new threat report
        await pool.query(
          'INSERT INTO threat_urls (url, domain, threat_type, severity, reported_by, confidence_score) VALUES ($1, $2, $3, $4, $5, 100)',
          [url, domain, threatType, severity, reportedBy]
        );
      }

      // Update or create URL reputation record
      await this.updateUrlReputation(url, domain, 'threat');

      return {
        success: true,
        message: 'URL reported as threat successfully'
      };

    } catch (error) {
      console.error('Error reporting threat URL:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Report URL as safe
  async reportSafeUrl(url, verifiedBy) {
    try {
      const domain = this.extractDomain(url);
      if (!domain) {
        return {
          success: false,
          error: 'Invalid URL format'
        };
      }

      // Check if URL already exists in safe database
      const existingSafe = await pool.query(
        'SELECT * FROM safe_urls WHERE url = $1',
        [url]
      );

      if (existingSafe.rows.length > 0) {
        // Update existing safe report
        await pool.query(
          'UPDATE safe_urls SET report_count = report_count + 1, last_verified = NOW(), confidence_score = LEAST(confidence_score + 2, 100) WHERE url = $1',
          [url]
        );
      } else {
        // Insert new safe report
        await pool.query(
          'INSERT INTO safe_urls (url, domain, verified_by, confidence_score) VALUES ($1, $2, $3, 100)',
          [url, domain, verifiedBy]
        );
      }

      // Update or create URL reputation record
      await this.updateUrlReputation(url, domain, 'safe');

      return {
        success: true,
        message: 'URL reported as safe successfully'
      };

    } catch (error) {
      console.error('Error reporting safe URL:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Update URL reputation score
  async updateUrlReputation(url, domain, type) {
    try {
      const existingReputation = await pool.query(
        'SELECT * FROM url_reputation WHERE url = $1',
        [url]
      );

      if (existingReputation.rows.length > 0) {
        // Update existing reputation
        const current = existingReputation.rows[0];
        let newScore = current.reputation_score;
        let safeReports = current.safe_reports;
        let threatReports = current.threat_reports;

        if (type === 'safe') {
          safeReports += 1;
          newScore = Math.min(100, newScore + 10);
        } else if (type === 'threat') {
          threatReports += 1;
          newScore = Math.max(0, newScore - 15);
        }

        await pool.query(
          'UPDATE url_reputation SET reputation_score = $1, safe_reports = $2, threat_reports = $3, last_updated = NOW() WHERE url = $4',
          [newScore, safeReports, threatReports, url]
        );
      } else {
        // Create new reputation record
        const initialScore = type === 'safe' ? 80 : (type === 'threat' ? 20 : 50);
        const safeReports = type === 'safe' ? 1 : 0;
        const threatReports = type === 'threat' ? 1 : 0;

        await pool.query(
          'INSERT INTO url_reputation (url, domain, reputation_score, safe_reports, threat_reports) VALUES ($1, $2, $3, $4, $5)',
          [url, domain, initialScore, safeReports, threatReports]
        );
      }

    } catch (error) {
      console.error('Error updating URL reputation:', error);
    }
  }

  // Get reputation statistics
  async getReputationStats() {
    try {
      const [safeCount, threatCount, totalReputation] = await Promise.all([
        pool.query('SELECT COUNT(*) as count FROM safe_urls'),
        pool.query('SELECT COUNT(*) as count FROM threat_urls'),
        pool.query('SELECT COUNT(*) as count FROM url_reputation')
      ]);

      return {
        success: true,
        data: {
          safeUrls: parseInt(safeCount.rows[0].count),
          threatUrls: parseInt(threatCount.rows[0].count),
          totalReputation: parseInt(totalReputation.rows[0].count)
        }
      };

    } catch (error) {
      console.error('Error getting reputation stats:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
}

module.exports = new ReputationService();
