const cookieParser = require('cookie-parser')
require('dotenv').config();
const createServer = require('./createServer');
const db = require('./db');

const server = createServer();

server.express.use(cookieParser());
// TODO: Use express middlware to populate current user

server.express.use((req, res, next) => {
console.log('Hey I\'m a middleware');
next();

});

server.start(
  {
    cors: {
      credentials: true,
      origin: process.env.FRONTEND_URL,
    },
  },
  deets => {
    console.log(`Server is now running on port http://localhost:${deets.port}`);
  }
);
