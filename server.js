// modules
const express = require('express')
const bodyParser = require('body-parser')
const cors = require('cors')
const dotenv = require('dotenv')
const apiMetrics = require('prometheus-api-metrics')
const v1_router = require('./routes/v1/auth.js')
const v2_router = require('./routes/v2/auth.js')
const pjson = require('./package.json')

// Parse .env file
dotenv.config()

console.log(`Authentication microservice v${pjson.version}`)
// Get app port from env varialbes if available, otherwise use 80
const app_port = process.env.APP_PORT || 80

// Instanciate an express server
const app = express()

// Expressing settings
app.use(bodyParser.json())
app.use(cors())
app.use(apiMetrics())

// Express routes
app.get('/', (req, res) => {
  res.send({
    application_name: 'Authentication API',
    author: pjson.author,
    version: pjson.version,
    neo4j_url: process.env.NEO4J_URL,
    jwt_secret_set: !!process.env.JWT_SECRET,
  })
})

app.use('/', v1_router)
app.use('/v2', v2_router)


// Start server
app.listen(app_port, () => {
  console.log(`[Express] Express listening on *:${app_port}`);
});
