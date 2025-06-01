const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const { createHandler } = require('graphql-http/lib/use/express');
const schema = require('./graphql/schema');
const resolvers = require('./graphql/resolver');
const WebsiteSafetyService = require('./services/websiteSafetyService');
const { ruruHTML } = require('ruru/server');
require('dotenv').config();

const app = express();

const MONGODB_URI = process.env.MONGODB_URI;

app.use(express.json()); // Needed to parse JSON bodies
// Enable CORS
app.use(
  cors({
    origin: ['http://localhost:3000', 'http://localhost:8080', 'http://localhost:5173'],
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  })
);

// Initialize the safety service
const safetyService = new WebsiteSafetyService({
  googleApiKey: process.env.GOOGLE_API_KEY,
  virusTotalApiKey: process.env.VIRUSTOTAL_API_KEY,
  URL_SCAN_IO: process.env.URL_SCAN_IO,
  clientId: 'my-client-id',
});

// app.use((req, res, next) => {
//   console.log(`${req.method} ${req.path}`);
//   if (req.method === 'POST') {
//     console.log('Request body:', req.body);
//   }
//   next();
// });

// GraphQL endpoint
app.use(
  '/graphql',
  createHandler({
    schema: schema,
    rootValue: resolvers,
    context: { safetyService }, // Pass services through context
    graphiql: true, // Enable GraphiQL UI in browser
    formatError: (err) => {
      console.error('GraphQL Error:', err);
      return {
        message: err.message,
        path: err.path,
        locations: err.locations,
        // Don't expose internal details in production
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
      };
    },
  })
);

// Serve the GraphiQL IDE.
app.get('/ruru', (_req, res) => {
  res.type('html');
  res.end(ruruHTML({ endpoint: '/graphql' }));
});

// Test endpoint
app.get('/', (req, res) => {
  res.send('GraphQL API Server is running. Visit /graphql to access GraphiQL.');
});

mongoose
  .connect(MONGODB_URI)
  .then((result) => {
    app.listen(8080, () => {
      console.log('🚀 Server running at http://localhost:8080/graphql');
      console.log('🚀 For running ruru http://localhost:8080/ruru');
    });
  })
  .catch((err) => console.log(`Database connection failed: ${err}`));
