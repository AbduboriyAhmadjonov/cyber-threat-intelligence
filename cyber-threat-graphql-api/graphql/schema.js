const {
  GraphQLSchema,
  GraphQLObjectType,
  GraphQLString,
  GraphQLFloat,
  GraphQLBoolean,
  GraphQLID,
  GraphQLInt,
  GraphQLList,
  GraphQLEnumType,
  GraphQLNonNull,
  GraphQLScalarType,
  Kind,
} = require('graphql');

// Custom scalar for Date (you can replace this with 'graphql-iso-date' or similar lib)
const DateType = new GraphQLScalarType({
  name: 'Date',
  serialize(value) {
    return value.getTime(); // Convert outgoing Date to integer for JSON
  },
  parseValue(value) {
    return new Date(value); // Convert incoming integer to Date
  },
  parseLiteral(ast) {
    if (ast.kind === Kind.INT) {
      // Convert hard-coded AST string to integer and then to Date
      return new Date(parseInt(ast.value, 10));
    }
    // Invalid hard-coded value (not an integer)
    return null;
  },
});

// Enums
const SafetyClassificationType = new GraphQLEnumType({
  name: 'SafetyClassification',
  values: {
    SAFE: { value: 'SAFE' },
    POTENTIALLY_SUSPICIOUS: { value: 'POTENTIALLY_SUSPICIOUS' },
    SUSPICIOUS: { value: 'SUSPICIOUS' },
    DANGEROUS: { value: 'DANGEROUS' },
  },
});

const ThreatTypeEnum = new GraphQLEnumType({
  name: 'ThreatType',
  values: {
    MALWARE: { value: 'MALWARE' },
    PHISHING: { value: 'PHISHING' },
    SCAM: { value: 'SCAM' },
    SPAM: { value: 'SPAM' },
    BOTNET: { value: 'BOTNET' },
    RANSOMWARE: { value: 'RANSOMWARE' },
    CRYPTOMINING: { value: 'CRYPTOMINING' },
    EXPLOIT_KIT: { value: 'EXPLOIT_KIT' },
    COMMAND_AND_CONTROL: { value: 'COMMAND_AND_CONTROL' },
    MALICIOUS_ADVERTISEMENT: { value: 'MALICIOUS_ADVERTISEMENT' },
    OTHER: { value: 'OTHER' },
  },
});

// Leaf types
const ThreatDetailsType = new GraphQLObjectType({
  name: 'ThreatDetails',
  fields: () => ({
    malware: { type: new GraphQLNonNull(GraphQLBoolean) },
    phishing: { type: new GraphQLNonNull(GraphQLBoolean) },
    suspicious: { type: new GraphQLNonNull(GraphQLBoolean) },
    maliciousContent: { type: new GraphQLNonNull(GraphQLBoolean) },
    insecureConnection: { type: new GraphQLNonNull(GraphQLBoolean) },
    suspiciousTlds: { type: new GraphQLNonNull(GraphQLBoolean) },
  }),
});

const SslDetailsType = new GraphQLObjectType({
  name: 'SslDetails',
  fields: () => ({
    valid: { type: new GraphQLNonNull(GraphQLBoolean) },
    issuer: { type: GraphQLString },
    expiryDate: { type: DateType },
  }),
});

const WhoisDetailsType = new GraphQLObjectType({
  name: 'WhoisDetails',
  fields: () => ({
    registrationDate: { type: DateType },
    expiryDate: { type: DateType },
    registrar: { type: GraphQLString },
  }),
});

const HostDetailsType = new GraphQLObjectType({
  name: 'HostDetails',
  fields: () => ({
    ip: { type: GraphQLString },
    country: { type: GraphQLString },
    asn: { type: GraphQLString },
  }),
});

const GoogleSafeBrowsingReportType = new GraphQLObjectType({
  name: 'GoogleSafeBrowsingReport',
  fields: () => ({
    safe: { type: new GraphQLNonNull(GraphQLBoolean) },
    threats: { type: new GraphQLList(new GraphQLNonNull(GraphQLString)) },
  }),
});

const VirusTotalReportType = new GraphQLObjectType({
  name: 'VirusTotalReport',
  fields: () => ({
    positives: { type: new GraphQLNonNull(GraphQLInt) },
    total: { type: new GraphQLNonNull(GraphQLInt) },
    scanDate: { type: DateType },
  }),
});

const PhishTankReportType = new GraphQLObjectType({
  name: 'PhishTankReport',
  fields: () => ({
    inDatabase: { type: new GraphQLNonNull(GraphQLBoolean) },
    verified: { type: GraphQLBoolean },
  }),
});

const ExternalReportsType = new GraphQLObjectType({
  name: 'ExternalReports',
  fields: () => ({
    googleSafeBrowsing: { type: GoogleSafeBrowsingReportType },
    virusTotal: { type: VirusTotalReportType },
    phishTank: { type: PhishTankReportType },
  }),
});

const WebsiteMetadataType = new GraphQLObjectType({
  name: 'WebsiteMetadata',
  fields: () => ({
    title: { type: GraphQLString },
    description: { type: GraphQLString },
    screenshot: { type: GraphQLString },
    ssl: { type: SslDetailsType },
    whois: { type: WhoisDetailsType },
    hostDetails: { type: HostDetailsType },
  }),
});

const WebsiteSafetyResultType = new GraphQLObjectType({
  name: 'WebsiteSafetyResult',
  fields: () => ({
    url: { type: new GraphQLNonNull(GraphQLString) },
    domain: { type: new GraphQLNonNull(GraphQLString) },
    scanDate: { type: DateType },
    safetyScore: { type: new GraphQLNonNull(GraphQLFloat) },
    classification: { type: new GraphQLNonNull(SafetyClassificationType) },
    threatDetails: { type: new GraphQLNonNull(ThreatDetailsType) },
    metadata: { type: WebsiteMetadataType },
    externalReports: { type: ExternalReportsType },
  }),
});

const WebsiteSafetyHistoryType = new GraphQLObjectType({
  name: 'WebsiteSafetyHistory',
  fields: () => ({
    scanDate: { type: DateType },
    safetyScore: { type: new GraphQLNonNull(GraphQLFloat) },
    classification: { type: new GraphQLNonNull(SafetyClassificationType) },
    threatDetails: { type: new GraphQLNonNull(ThreatDetailsType) },
  }),
});

// Handle circular reference for ThreatIntelligenceType
let ThreatIntelligenceType;

ThreatIntelligenceType = new GraphQLObjectType({
  name: 'ThreatIntelligence',
  fields: () => ({
    id: { type: new GraphQLNonNull(GraphQLID) },
    url: { type: GraphQLString },
    domain: { type: GraphQLString },
    ip: { type: GraphQLString },
    type: { type: new GraphQLNonNull(ThreatTypeEnum) },
    confidence: { type: new GraphQLNonNull(GraphQLFloat) },
    discoveredAt: { type: new GraphQLNonNull(DateType) },
    description: { type: GraphQLString },
    relatedThreats: {
      type: new GraphQLList(new GraphQLNonNull(ThreatIntelligenceType)),
      resolve(parent) {
        // Implement resolver for related threats
        return []; // Placeholder
      },
    },
  }),
});

// Root Query
const QueryType = new GraphQLObjectType({
  name: 'Query',
  fields: () => ({
    // Simple hello world query for testing
    // hello: {
    //   type: GraphQLString,
    //   resolve: () => 'Hello World!!!!!!!!',
    // },

    checkWebsiteSafety: {
      type: new GraphQLNonNull(WebsiteSafetyResultType),
      args: {
        url: { type: new GraphQLNonNull(GraphQLString) },
        forceRefresh: { type: GraphQLBoolean },
      },
      resolve: (_, args, context) => {
        return context.safetyService.checkWebsiteSafety(args.url, args.forceRefresh);
      },
    },

    getWebsiteSafetyHistory: {
      type: new GraphQLList(new GraphQLNonNull(WebsiteSafetyHistoryType)),
      args: {
        domain: { type: new GraphQLNonNull(GraphQLString) },
        limit: { type: GraphQLInt },
      },
      resolve: (_, args, context) => {
        return context.safetyService.getHistory(args.domain, args.limit);
      },
    },

    getRecentThreats: {
      type: new GraphQLList(new GraphQLNonNull(ThreatIntelligenceType)),
      args: {
        limit: { type: GraphQLInt },
        threatType: { type: ThreatTypeEnum },
      },
      resolve: (_, args, context) => {
        return context.safetyService.getRecentThreats(args.limit, args.threatType);
      },
    },

    searchByClassification: {
      type: new GraphQLList(new GraphQLNonNull(WebsiteSafetyResultType)),
      args: {
        classification: { type: new GraphQLNonNull(SafetyClassificationType) },
        limit: { type: GraphQLInt },
      },
      resolve: (_, args, context) => {
        return context.safetyService.searchByClassification(args.classification, args.limit);
      },
    },
  }),
});

// Final Schema
const schema = new GraphQLSchema({
  query: QueryType,
});

module.exports = schema;
