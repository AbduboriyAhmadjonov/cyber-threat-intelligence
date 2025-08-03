import { startStandaloneServer } from '@apollo/server/standalone';
import { ApolloServer } from '@apollo/server';
import { configDotenv } from 'dotenv';
import mongoose from 'mongoose';
import { makeExecutableSchema } from '@graphql-tools/schema';

import typeDefs from './graphql/schema.js';
import resolvers from './graphql/resolvers.js';

configDotenv(); // Load environment variables

const schema = makeExecutableSchema({
  typeDefs,
  resolvers,
});

const server = new ApolloServer({ schema });

// Connect to MongoDB before starting Apollo Server
await mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('Database connected successfully');
  })
  .catch((err) => {
    console.log(`Database connection failed: ${err}`);
    process.exit(1);
  });

const { url } = await startStandaloneServer(server, {
  listen: { port: 8004 },
});
console.log(`🚀 Server ready at ${url}`);
