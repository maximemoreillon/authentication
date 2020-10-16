// modules
const express = require('express')
const bodyParser = require('body-parser')
const cors = require('cors')
const dotenv = require('dotenv')
const pjson = require('./package.json')
const controller = require('./controllers/authentication.js')

// Parse .env file
dotenv.config()


// Get app port from env varialbes if available, otherwise use 80
const app_port = process.env.APP_PORT || 80

// Instanciate an express server
const app = express()

// Expressing settings
app.use(bodyParser.json())
app.use(cors())

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

app.route('/login')
  .post(controller.login)

app.route('/whoami')
  .post(controller.whoami)
  .get(controller.whoami)

app.route('/user_from_jwt')
  .post(controller.get_user_from_jwt)
  .get(controller.get_user_from_jwt)

app.route('/user_from_token')
  .post(controller.get_user_from_jwt)
  .get(controller.get_user_from_jwt)

app.route('/decode_jwt')
  .get(controller.get_user_from_jwt) // wrong controller but used by other services
  .post(controller.get_user_from_jwt) // wrong controller but used by other services

app.route('/decode_token')
  .get(controller.get_user_from_jwt) // wrong controller but used by other services
  .post(controller.get_user_from_jwt) // wrong controller but used by other services

app.route('/verify_jwt')
  .get(controller.decode_token)
  .post(controller.decode_token)

app.route('/verify_token')
  .get(controller.decode_token)
  .post(controller.decode_token)

// Start server
app.listen(app_port, () => {
  console.log(`[Express] Authentication microservice listening on *:${app_port}`);
});
