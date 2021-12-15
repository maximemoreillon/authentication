// modules
const express = require('express')
const cors = require('cors')
const dotenv = require('dotenv')
const apiMetrics = require('prometheus-api-metrics')
const v1_router = require('./routes/v1/auth.js')
const v2_router = require('./routes/v2/auth.js')
const v3_router = require('./routes/v3/auth.js')
const { version, author } = require('./package.json')
const {
  url: neo4j_url,
  get_connected,
  connection_check: db_connection_check,
 } = require('./db.js')
const {
  app_port,
  jwt_secret,
} = require('./config.js')
// Parse .env file
dotenv.config()

console.log(`Authentication microservice v${version}`)

db_connection_check()

// Instanciate an express server
const app = express()

// Expressing settings
app.use(express.json())
app.use(cors())
app.use(apiMetrics())

// Express routes
app.get('/', (req, res) => {
  res.send({
    application_name: 'Authentication API',
    author,
    version,
    neo4j: {
      url: neo4j_url,
      connected: get_connected()
    },
    jwt_secret_set: !!jwt_secret,
  })
})

app.use('/', v1_router)
app.use('/v1', v1_router)
app.use('/v2', v2_router)
app.use('/v3', v3_router)

// Start server
app.listen(app_port, () => {
  console.log(`[Express] Express listening on *:${app_port}`);
})

exports.app = app
