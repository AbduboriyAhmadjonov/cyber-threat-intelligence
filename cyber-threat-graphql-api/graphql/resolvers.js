import Safety from '../models/db.js';
import {
  checkUrlSafetyWithUrlscan,
  checkUrlscanStatus,
} from '../services/checkUrlSafety.js';

const transformSafetyReport = (report) => {
  return {
    ...report._doc, // Get the plain JavaScript object from Mongoose document
    id: report._id.toString(), // Convert ObjectId to String for GraphQL
    createdAt: report.createdAt ? report.createdAt.getTime() : null, // Convert Date to timestamp
    updatedAt: report.updatedAt ? report.updatedAt.getTime() : null, // Convert Date to timestamp
    externalReports: {
      ...report.externalReports,
      virusTotal: report.externalReports.virusTotal
        ? {
            ...report.externalReports.virusTotal,
            scanDate: report.externalReports.virusTotal.scanDate
              ? report.externalReports.virusTotal.scanDate.getTime()
              : null,
          }
        : null,
    },
  };
};

const resolvers = {
  Query: {
    recentScans: async (parent, args, context, info) => {
      try {
        const reports = await Safety.find().sort({ createdAt: -1 }).limit(10);
        return reports.map(transformSafetyReport);
      } catch (error) {
        console.error('Error fetching recent scans (GraphQL):', error);
        throw new Error('Failed to fetch recent scans');
      }
    },

    urlscanStatus: async (parent, { scanId }, context, info) => {
      try {
        const status = await checkUrlscanStatus(scanId);
        return status;
      } catch (error) {
        console.error('Error checking URLScan status (GraphQL):', error);
        throw new Error('Failed to retrieve URLScan status');
      }
    },
  },
  Mutation: {
    scanUrl: async (parent, { url, waitForUrlscan }, context, info) => {
      try {
        const result = await checkUrlSafetyWithUrlscan(url, waitForUrlscan);
        if (!result) {
          throw new Error('URL safety check failed or returned no data.');
        }
        const safetyData = new Safety({
          url: result.url,
          isSafe: result.isSafe,
          externalReports: {
            googleSafeBrowsing:
              result.externalReports.googleSafeBrowsing || null,
            virusTotal: result.externalReports.virusTotal || null,
            urlscan: result.externalReports.urlscan || null,
          },
        });
        await safetyData.save();
        console.log('Data saved to database via GraphQL:', safetyData);
        return transformSafetyReport(safetyData);
      } catch (error) {
        console.error('Error scanning URL (GraphQL):', error);
        throw new Error('Failed to scan URL');
      }
    },
  },
};

export default resolvers;
