const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');
const crypto = require('crypto');
const dns = require('dns');
const util = require('util');

const dnsLookupPromise = util.promisify(dns.lookup);
const dnsResolvePromise = util.promisify(dns.resolve);

const { websiteSafetyModel } = require('../models/db');
console.log('websiteSafetyModel:', websiteSafetyModel);

class WebsiteSafetyService {
  constructor(config) {
    this.config = config;
    this.threatIntelCache = new Map(); // Cache for threat intelligence
    this.suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']; // Examples of potentially suspicious TLDs

    // Initialize API clients
    this.googleSafeBrowsingClient = axios.create({
      baseURL: 'https://safebrowsing.googleapis.com/v4',
      params: { key: config.googleApiKey },
    });

    this.virusTotalClient = axios.create({
      baseURL: 'https://www.virustotal.com/api/v3',
      headers: { 'x-apikey': config.virusTotalApiKey },
    });

    // Initialize other API clients...
  }

  /**
   * Check if a website is safe
   * @param {string} url - The URL to check
   * @param {boolean} forceRefresh - Force a new scan instead of using cached data
   * @returns {Promise<Object>} Safety assessment
   */
  async checkWebsiteSafety(url, forceRefresh = false) {
    // Normalize URL
    const normalizedUrl = this.normalizeUrl(url);
    const domain = this.extractDomain(normalizedUrl);

    // Check cache or database for recent results
    if (!forceRefresh) {
      const cachedResult = await this.getCachedResult(normalizedUrl);
      if (cachedResult) {
        return cachedResult;
      }
    }

    // Initialize threat assessment
    const assessment = {
      url: normalizedUrl,
      domain,
      safetyScore: 100, // Start with perfect score and deduct points
      threatDetails: {
        malware: false,
        phishing: false,
        suspicious: false,
        maliciousContent: false,
        insecureConnection: false,
        suspiciousTlds: false,
      },
      metadata: {},
      externalReports: {},
      scanDate: new Date(),
    };

    try {
      // 1. Check external threat intelligence APIs
      await Promise.all([
        this.checkGoogleSafeBrowsing(normalizedUrl, assessment),
        this.checkVirusTotal(normalizedUrl, assessment),
        // this.checkPhishTank(normalizedUrl, assessment),
      ]);

      // 2. Perform internal analysis
      await Promise.all([
        this.analyzeUrl(normalizedUrl, assessment),
        this.checkSsl(normalizedUrl, assessment),
        this.getWhoisData(domain, assessment),
        this.getDnsAndGeoData(domain, assessment),
        this.analyzeWebsiteContent(normalizedUrl, assessment),
      ]);

      // 3. Calculate final safety score based on all checks
      this.calculateFinalScore(assessment);

      // 4. Save results to database
      await this.saveResults(assessment);

      return assessment;
    } catch (error) {
      console.error(`Error checking website safety for ${url}:`, error);
      assessment.error = 'Error analyzing website';
      assessment.safetyScore = 50; // Default to moderate risk when error occurs
      return assessment;
    }
  }

  /**
   * Normalize URL for consistent processing
   */
  normalizeUrl(url) {
    // Add protocol if missing
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }

    try {
      const parsedUrl = new URL(url);
      // Remove trailing slash, fragments, etc.
      return `${parsedUrl.protocol}//${parsedUrl.hostname}${parsedUrl.pathname}`.replace(/\/$/, '');
    } catch (error) {
      return url; // Return original if parsing fails
    }
  }

  /**
   * Extract domain name from URL
   */
  extractDomain(url) {
    try {
      return new URL(url).hostname;
    } catch (error) {
      return url;
    }
  }

  /**
   * Check Google Safe Browsing API
   */
  async checkGoogleSafeBrowsing(url, assessment) {
    try {
      const response = await this.googleSafeBrowsingClient.post('/threatMatches:find', {
        client: {
          clientId: this.config.clientId,
          clientVersion: '1.0.0',
        },
        threatInfo: {
          threatTypes: [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION',
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      });

      const threats = response.data.matches || [];
      assessment.externalReports.googleSafeBrowsing = {
        safe: threats.length === 0,
        threats: threats.map((match) => match.threatType),
      };

      if (threats.length > 0) {
        assessment.safetyScore -= 30;
        if (threats.find((t) => t.threatType === 'MALWARE')) {
          assessment.threatDetails.malware = true;
        }
        if (threats.find((t) => t.threatType === 'SOCIAL_ENGINEERING')) {
          assessment.threatDetails.phishing = true;
        }
      }
    } catch (error) {
      console.error('Google Safe Browsing API error:', error.message);
      // Continue with other checks even if this one fails
    }
  }

  /**
   * Check VirusTotal API
   */
  async checkVirusTotal(url, assessment) {
    try {
      // URL ID is a base64 encoded URL
      const urlId = Buffer.from(url)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
      const response = await this.virusTotalClient.get(`/urls/${urlId}`);

      const results = response.data.data.attributes.last_analysis_results;
      const stats = response.data.data.attributes.last_analysis_stats;

      assessment.externalReports.virusTotal = {
        positives: stats.malicious + stats.suspicious,
        total: Object.keys(results).length,
        scanDate: new Date(response.data.data.attributes.last_analysis_date * 1000),
      };

      // Adjust score based on VirusTotal results
      if (assessment.externalReports.virusTotal.positives > 0) {
        const ratio =
          assessment.externalReports.virusTotal.positives /
          assessment.externalReports.virusTotal.total;

        if (ratio > 0.1) {
          assessment.safetyScore -= 25 * ratio;
          assessment.threatDetails.suspicious = true;
        }

        if (ratio > 0.05) {
          assessment.safetyScore -= 10;
        }
      }
    } catch (error) {
      // URL might not be in VirusTotal database yet
      assessment.externalReports.virusTotal = {
        error: 'URL not found in database or API error',
        positives: 0,
        total: 0,
      };
    }
  }

  /**
  //  * Check PhishTank API
  //  */
  // async checkPhishTank(url, assessment) {
  //   try {
  //     const response = await axios.post(
  //       'https://checkurl.phishtank.com/checkurl/',
  //       `url=${encodeURIComponent(url)}`,
  //       {
  //         headers: {
  //           'Content-Type': 'application/x-www-form-urlencoded',
  //           'User-Agent': 'MyCTIApp/1.0',
  //           'X-API-Key': this.config.phishTankApiKey,
  //         },
  //       }
  //     );

  //     assessment.externalReports.phishTank = {
  //       inDatabase: response.data.in_database,
  //       verified: response.data.verified,
  //     };

  //     if (response.data.in_database && response.data.verified) {
  //       assessment.safetyScore -= 40;
  //       assessment.threatDetails.phishing = true;
  //     }
  //   } catch (error) {
  //     assessment.externalReports.phishTank = {
  //       error: 'API error or URL not in database',
  //       inDatabase: false,
  //     };
  //   }
  // }

  /**
   * Analyze URL for suspicious patterns
   */
  analyzeUrl(url, assessment) {
    const parsedUrl = new URL(url);

    // Check for suspicious TLDs
    const tld = parsedUrl.hostname.substring(parsedUrl.hostname.lastIndexOf('.'));
    if (this.suspiciousTlds.includes(tld)) {
      assessment.safetyScore -= 10;
      assessment.threatDetails.suspiciousTlds = true;
    }

    // Check for excessive subdomains
    const subdomainCount = parsedUrl.hostname.split('.').length - 2;
    if (subdomainCount > 3) {
      assessment.safetyScore -= 5;
      assessment.threatDetails.suspicious = true;
    }

    // Check for numeric IP in hostname
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(parsedUrl.hostname)) {
      assessment.safetyScore -= 15;
      assessment.threatDetails.suspicious = true;
    }

    // Check for URL obfuscation techniques
    if (
      parsedUrl.hostname.includes('url=') ||
      parsedUrl.hostname.includes('@') ||
      /[A-F0-9]{32}/.test(parsedUrl.hostname)
    ) {
      assessment.safetyScore -= 20;
      assessment.threatDetails.suspicious = true;
    }

    return Promise.resolve();
  }

  /**
   * Check SSL certificate
   */
  async checkSsl(url, assessment) {
    if (url.startsWith('http://')) {
      assessment.safetyScore -= 15;
      assessment.threatDetails.insecureConnection = true;
      assessment.metadata.ssl = { valid: false };
      return;
    }

    try {
      const parsedUrl = new URL(url);
      const options = {
        hostname: parsedUrl.hostname,
        port: 443,
        method: 'GET',
        path: '/',
        rejectUnauthorized: false, // We want to analyze invalid certs too
        servername: parsedUrl.hostname,
      };

      // This is simplified - in a real implementation you'd use
      // OpenSSL or a dedicated certificate checking library
      const sslInfo = { valid: true }; // Placeholder for actual SSL check

      assessment.metadata.ssl = sslInfo;

      if (!sslInfo.valid) {
        assessment.safetyScore -= 20;
        assessment.threatDetails.insecureConnection = true;
      }
    } catch (error) {
      assessment.metadata.ssl = { valid: false, error: error.message };
      assessment.safetyScore -= 15;
      assessment.threatDetails.insecureConnection = true;
    }
  }

  /**
   * Get WHOIS data
   */
  async getWhoisData(domain, assessment) {
    try {
      // Simplified - in a real implementation you'd use a WHOIS library
      // or service like whois-json or whois-api
      const whoisData = {
        registrationDate: new Date('2020-01-01'), // Placeholder
        expiryDate: new Date('2025-01-01'), // Placeholder
        registrar: 'Example Registrar', // Placeholder
      };

      assessment.metadata.whois = whoisData;

      // Check domain age - new domains are higher risk
      const domainAge = (new Date() - whoisData.registrationDate) / (1000 * 60 * 60 * 24);
      if (domainAge < 30) {
        // Less than 30 days old
        assessment.safetyScore -= 15;
        assessment.threatDetails.suspicious = true;
      } else if (domainAge < 90) {
        // Less than 90 days old
        assessment.safetyScore -= 5;
      }
    } catch (error) {
      assessment.metadata.whois = { error: 'WHOIS data unavailable' };
    }
  }

  /**
   * Get DNS and geographic data
   */
  async getDnsAndGeoData(domain, assessment) {
    try {
      // Resolve IP address
      const { address } = await dnsLookupPromise(domain);

      // In a real implementation, you'd use a geolocation API here
      const geoData = { country: 'Unknown', asn: 'Unknown' };

      assessment.metadata.hostDetails = {
        ip: address,
        country: geoData.country,
        asn: geoData.asn,
      };

      // Optional: Check if IP is in known bad IP ranges
      // This would require integration with IP reputation databases
    } catch (error) {
      assessment.metadata.hostDetails = { error: 'DNS resolution failed' };
    }
  }

  /**
   * Analyze website content for suspicious patterns
   */
  async analyzeWebsiteContent(url, assessment) {
    try {
      const response = await axios.get(url, {
        timeout: 5000,
        maxRedirects: 5,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        },
      });

      const $ = cheerio.load(response.data);

      // Extract metadata
      assessment.metadata.title = $('title').text();
      assessment.metadata.description = $('meta[name="description"]').attr('content');

      // Check for suspicious content patterns
      const htmlContent = response.data.toLowerCase();

      // Check for phishing indicators
      const phishingKeywords = [
        'login',
        'sign in',
        'verify',
        'account',
        'banking',
        'password',
        'credit card',
      ];
      const containsPhishingTerms = phishingKeywords.some((keyword) =>
        htmlContent.includes(keyword)
      );

      // Check for obfuscated JavaScript
      const hasObfuscatedJs =
        $('script').text().includes('eval(') ||
        $('script').text().includes('escape(') ||
        $('script').text().includes('unescape(');

      // Check for hidden form fields that collect sensitive data
      const hasSuspiciousForms =
        $('input[type="hidden"][name*="card"]').length > 0 ||
        $('input[type="hidden"][name*="password"]').length > 0;

      // Check for invisible elements
      const hasInvisibleElements = $('div[style*="display:none"]').find('input').length > 0;

      // Count external links to gauge quality
      const externalLinks = $('a[href^="http"]').length;

      if (hasObfuscatedJs) {
        assessment.safetyScore -= 20;
        assessment.threatDetails.maliciousContent = true;
      }

      if (hasSuspiciousForms || hasInvisibleElements) {
        assessment.safetyScore -= 15;
        assessment.threatDetails.suspicious = true;
      }

      // If page has phishing terms but very few external links, likely a phishing page
      if (containsPhishingTerms && externalLinks < 3) {
        assessment.safetyScore -= 15;
        assessment.threatDetails.suspicious = true;
      }
    } catch (error) {
      console.error('Error analyzing website content:', error.message);
      // Content analysis failed - could be a sign of malicious redirect or other issues
      assessment.safetyScore -= 10;
    }
  }

  /**
   * Calculate final safety score
   */
  calculateFinalScore(assessment) {
    // Ensure score is between 0-100
    assessment.safetyScore = Math.max(0, Math.min(100, assessment.safetyScore));

    // Add final classification based on score
    if (assessment.safetyScore >= 80) {
      assessment.classification = 'Safe';
    } else if (assessment.safetyScore >= 60) {
      assessment.classification = 'Potentially Suspicious';
    } else if (assessment.safetyScore >= 40) {
      assessment.classification = 'Suspicious';
    } else {
      assessment.classification = 'Dangerous';
    }

    return assessment;
  }

  /**
   * Get cached result from database
   */
  async getCachedResult(url) {
    // Check if we have a recent result (less than 24 hours old)
    const cachedResult = await websiteSafetyModel.findOne({
      url,
      lastScanned: { $gt: new Date(Date.now() - 24 * 60 * 60 * 1000) },
    });

    return cachedResult;
  }

  /**
   * Save results to database
   */
  async saveResults(assessment) {
    try {
      // Find existing entry or create new one
      let record = await websiteSafetyModel.findOne({ url: assessment.url });

      if (record) {
        // Update existing record and add to history
        record.history.push({
          scanDate: new Date(),
          safetyScore: assessment.safetyScore,
          threatDetails: assessment.threatDetails,
        });

        // Update main record with latest scan
        record.lastScanned = new Date();
        record.safetyScore = assessment.safetyScore;
        record.threatDetails = assessment.threatDetails;
        record.metadata = assessment.metadata;
        record.externalReports = assessment.externalReports;

        await record.save();
      } else {
        // Create new record
        record = new websiteSafetyModel({
          url: assessment.url,
          domain: assessment.domain,
          lastScanned: new Date(),
          safetyScore: assessment.safetyScore,
          threatDetails: assessment.threatDetails,
          metadata: assessment.metadata,
          externalReports: assessment.externalReports,
          history: [
            {
              scanDate: new Date(),
              safetyScore: assessment.safetyScore,
              threatDetails: assessment.threatDetails,
            },
          ],
        });

        await record.save();
      }

      return record;
    } catch (error) {
      console.error('Error saving website safety data:', error);
      // Continue even if save fails
    }
  }
}

module.exports = WebsiteSafetyService;
