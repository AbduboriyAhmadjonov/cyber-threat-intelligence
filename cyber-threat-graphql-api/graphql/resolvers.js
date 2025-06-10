// graphql/resolvers.js
import Safety from '../models/db.js';
import {
  checkUrlSafetyWithUrlscan,
  checkUrlscanStatus,
} from '../services/checkUrlSafety.js';

// Helper to convert Mongoose document to plain object for GraphQL
const transformSafetyReport = (report) => {
  if (!report) return null;

  const transformed = {
    id: report._id.toString(), // Convert ObjectId to String for GraphQL's ID type
    url: report.url,
    isSafe: report.isSafe,
    // Convert Mongoose Date objects to Unix timestamps (milliseconds)
    createdAt: report.createdAt ? report.createdAt.getTime() : null,
    updatedAt: report.updatedAt ? report.updatedAt.getTime() : null,
  };

  // Ensure externalReports object is properly structured and dates are handled
  if (report.externalReports) {
    transformed.externalReports = {
      googleSafeBrowsing: report.externalReports.googleSafeBrowsing || null,
      virusTotal: report.externalReports.virusTotal
        ? {
            ...report.externalReports.virusTotal,
            // Convert Date object from DB to timestamp
            scanDate: report.externalReports.virusTotal.scanDate
              ? report.externalReports.virusTotal.scanDate.getTime()
              : null,
          }
        : null,
      urlscan: report.externalReports.urlscan
        ? {
            ...report.externalReports.urlscan,
            // Convert Date object from DB to timestamp
            scanDate: report.externalReports.urlscan.scanDate
              ? report.externalReports.urlscan.scanDate.getTime()
              : null,
          }
        : null,
    };
  } else {
    transformed.externalReports = {}; // Ensure it's not null if there are no reports
  }

  return transformed;
};

const resolvers = {
  Query: {
    recentScans: async () => {
      try {
        const reports = await Safety.find().sort({ createdAt: -1 }).limit(10);
        return reports.map(transformSafetyReport);
      } catch (error) {
        console.error('Error fetching recent scans (GraphQL):', error);
        throw new Error('Failed to fetch recent scans.');
      }
    },
    urlscanStatus: async (parent, { scanId }) => {
      try {
        const status = await checkUrlscanStatus(scanId);
        // checkUrlscanStatus now returns the direct structure matching UrlscanReportType,
        // including malicious, score, etc., and also error/message.
        // Ensure scanDate from checkUrlscanStatus (which is a Date object) is converted to timestamp here
        if (status && status.scanDate instanceof Date) {
          status.scanDate = status.scanDate.getTime();
        }
        return status;
      } catch (error) {
        console.error(`Error checking URLScan status for ${scanId}:`, error);
        throw new Error('Failed to retrieve URLScan status.');
      }
    },
  },
  Mutation: {
    scanUrl: async (parent, { url, waitForUrlscan = false }) => {
      // Default value for waitForUrlscan
      try {
        console.log(
          `Scanning URL: ${url} (Wait for URLscan: ${waitForUrlscan})`
        );
        const result = await checkUrlSafetyWithUrlscan(url, waitForUrlscan);

        if (!result) {
          throw new Error('URL safety check returned no data.');
        }

        // Save the *full* and *final* result.externalReports object directly
        // This is crucial: `checkUrlSafetyWithUrlscan` already updates `result.externalReports.urlscan`
        // with the completed scan data if `waitForUrlscan` is true.
        const safetyData = new Safety({
          url: result.url,
          isSafe: result.isSafe,
          externalReports: result.externalReports, // Directly save the complete externalReports
        });
        await safetyData.save();

        console.log('Data saved to database via GraphQL:', safetyData.id);
        return transformSafetyReport(safetyData);
      } catch (error) {
        console.error('Error scanning URL (GraphQL):', error);
        throw new Error(`Failed to scan URL: ${error.message}`);
      }
    },
  },
};

export default resolvers;
