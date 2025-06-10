// graphql/schema.js (typeDefs)
import { gql } from 'graphql-tag';

const typeDefs = gql`
  type GoogleSafeBrowsingReport {
    safe: Boolean
    threats: [String]
    error: String # Added for API errors
  }

  type VirusTotalReport {
    positives: Int
    total: Int
    scanDate: Float # Unix timestamp in milliseconds
    message: String # For messages like "URL not found"
    error: String # Added for API errors
  }

  type UrlscanReport {
    status: String # e.g., "pending", "completed", "processing", "error"
    message: String
    scanId: String
    scanUrl: String
    screenshotUrl: String
    score: Int
    malicious: Boolean
    categories: [String]
    tags: [String]
    scanDate: Float # Unix timestamp in milliseconds
    error: String # Added for API errors
  }

  type ExternalReports {
    googleSafeBrowsing: GoogleSafeBrowsingReport
    virusTotal: VirusTotalReport
    urlscan: UrlscanReport
  }

  type SafetyReport {
    id: ID! # MongoDB _id, typically String but semantically ID
    url: String!
    isSafe: Boolean!
    externalReports: ExternalReports!
    createdAt: Float # Unix timestamp in milliseconds
    updatedAt: Float # Unix timestamp in milliseconds
  }

  type Query {
    recentScans: [SafetyReport!]! # Array of SafetyReport, never null
    urlscanStatus(scanId: String!): UrlscanReport! # UrlscanReport is always returned
  }

  type Mutation {
    scanUrl(url: String!, waitForUrlscan: Boolean = false): SafetyReport! # waitForUrlscan default to false
  }
`;

export default typeDefs;
