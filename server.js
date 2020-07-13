// modules
const express = require('express')
const bodyParser = require('body-parser')
const cors = require('cors')
const dotenv = require('dotenv')
const pjson = require('./package.json')


// Parse .env file
dotenv.config()

// Database configurattion
const driver = require('./neo4j_driver.js')
const controller = require('./controllers/authentication.js')

// Get app port from env varialbes if available, otherwise use 80
const app_port = process.env.APP_PORT || 80

const app = express()
app.use(bodyParser.json())
app.use(cors())

// Express routes
app.get('/', (req, res) => {
  res.send(`Authentication API ${pjson.version}, Maxime MOREILLON`)
})

app.route('/login')
  .post(controller.login)

app.route('/whoami')
  .post(controller.whoami)
  .get(controller.whoami)

app.route('/user_from_jwt')
  .post(controller.get_user_from_jwt)
  .get(controller.get_user_from_jwt)

app.route('/decode_jwt')
  .get(controller.get_user_from_jwt)
  .post(controller.get_user_from_jwt)


// Start server
app.listen(app_port, () => {
  console.log(`Authentication microservice listening on *:${app_port}`);
});
