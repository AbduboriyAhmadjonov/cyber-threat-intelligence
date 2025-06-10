// THIS FILE IS NOW ONLY FOR SDL TYPEDEFS
import { gql } from 'graphql-tag';

const typeDefs = gql`
  type GoogleSafeBrowsingReport {
    safe: Boolean
    threats: [String]
  }
  type VirusTotalReport {
    positives: Int
    total: Int
    scanDate: Float
  }
  type UrlscanReport {
    status: String
    message: String
    scanId: String
    malicious: Boolean
    score: Int
    scanUrl: String
    screenshotUrl: String
    categories: [String]
    tags: [String]
    scanDate: Float
  }
  type ExternalReports {
    googleSafeBrowsing: GoogleSafeBrowsingReport
    virusTotal: VirusTotalReport
    urlscan: UrlscanReport
  }
  type SafetyReport {
    id: String
    url: String
    isSafe: Boolean
    externalReports: ExternalReports
    createdAt: Float
    updatedAt: Float
  }
  type Query {
    recentScans: [SafetyReport]
    urlscanStatus(scanId: String!): UrlscanReport
  }
  type Mutation {
    scanUrl(url: String!, waitForUrlscan: Boolean): SafetyReport
  }
`;

export default typeDefs;
