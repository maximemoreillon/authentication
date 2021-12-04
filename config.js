const dotenv = require('dotenv')
dotenv.config()

// Reading environment variables
const {
  APP_PORT: app_port = 80,
  NEO4J_URL: neo4j_url = 'bolt://neo4j',
  NEO4J_USERNAME: neo4j_username = 'neo4j',
  NEO4J_PASSWORD: neo4j_password = 'neo4j',
  JWT_SECRET: jwt_secret,
} = process.env

// Exporting
exports.jwt_secret = jwt_secret
exports.app_port = app_port
exports.neo4j = {
  url: neo4j_url,
  auth: {
    username: neo4j_username,
    password: neo4j_password,
  }
}
