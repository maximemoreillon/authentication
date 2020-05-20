// modules
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors')
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const neo4j = require('neo4j-driver');
const dotenv = require('dotenv');

// Parse .env file
dotenv.config();

const driver = neo4j.driver(
  process.env.NEO4J_URL,
  neo4j.auth.basic(
    process.env.NEO4J_USERNAME,
    process.env.NEO4J_PASSWORD
  )
)

var app_port = 80
if(process.env.APP_PORT) app_port=process.env.APP_PORT

const saltRounds = 10;

function verify_jwt_and_respond_with_user(token, res){
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if(err) return res.status(403).send('Invalid JWT')

    // Here, could think of getting user from user management microservice
    const field_name = 'user'
    var session = driver.session()
    session
    .run(`
      MATCH (${field_name}:User)
      WHERE id(${field_name}) = toInt({user_id})
      RETURN ${field_name}
      `, {
        user_id: decoded.user_id,
      })
    .then(result => {

      // If the user has not been found in the database
      if(result.records.length === 0) return res.status(400).send('User not found in the database')

      // if there is at least a match, take the first one (a bit dirty)
      let record = result.records[0]
      let user = record.get(field_name)

      res.send(user)

    })
    .catch(error => { res.status(500).send(`Error while looking for user: ${error}`) })
    .finally( () => session.close())
  });
}

// Express configuration
const app = express()
app.use(bodyParser.json())
app.use(cors())

// Express routes
app.get('/', (req, res) => {
  res.send(`Authentication API, Maxime MOREILLON`)
})

app.post('/login', (req, res) => {

  // Check if all necessary login information is provided
  if( !('username' in req.body) ) return res.status(400).send('Missing username')
  if( !('password' in req.body) ) return res.status(400).send('Missing password')

  // Here, could think of getting user from user management microservice
  const field_name = 'user'
  var session = driver.session()
  session
  .run(`
    MATCH (${field_name}:User)
    WHERE user.username={username}
    RETURN ${field_name}
    `, {
      username: req.body.username,
    })
  .then(result => {

    // If the user has not been found in the database
    if(result.records.length === 0) return res.status(400).send('User not found in the database')

    // if there is at least a match, take the first one (a bit dirty)
    let record = result.records[0]
    let user = record.get(field_name)

    // Check if user has a password
    if(!user.properties.password_hashed) return res.status(500).send('User does not have a password')

    // Now check if the password is correct
    bcrypt.compare(req.body.password, user.properties.password_hashed, (err, result) => {

      // Handle hashing errors
      if(err) return res.status(500).send(`Error while verifying password for user ${user.properties.username}: ${err}`)

      // Check validity of result
      if(!result) return res.status(403).send(`Incorrect password for user ${user.properties.username}`)

      // Generate JWT
      jwt.sign({ user_id: user.identity.low }, process.env.JWT_SECRET, (err, token) => {

        // handle signing errors
        if(err) return res.status(500).send(`Error while generating token for user ${user.properties.username}: ${err}`)

        // Respond with JWT
        res.send({jwt: token});

      })
    })

  })
  .catch(error => { res.status(500).send(`Error while looking for user: ${error}`) })
  .finally( () => session.close())

})


function whoami(req, res){
  // Retrieves user information based on JWT present in auth header

  // Check if authorization header set
  if(!req.headers.authorization) return res.status(403).send('Authorization header not set')
  // parse the headers to get the token
  let token = req.headers.authorization.split(" ")[1];
  if(!token) return res.status(403).send('Token not found in authorization header')

  // Verify the token and respond
  verify_jwt_and_respond_with_user(token, res)
}

app.post('/whoami', whoami)
app.get('/whoami', whoami)


app.post('/decode_jwt', (req, res) => {
  if(! ('jwt' in req.body)) return res.status(400).send('JWT not present in body')

  // Todo: This should just return the content of the decoded JWT

  // Verify the token and respond
  verify_jwt_and_respond_with_user(req.body.jwt, res)
})

app.get('/user_from_jwt', (req, res) => {
  if(! ('jwt' in req.query)) return res.status(400).send('JWT not present in query')

  // Verify the token and respond
  verify_jwt_and_respond_with_user(req.query.jwt, res)
})


// Start server
app.listen(app_port, () => {
  console.log(`Authentication microservice listening on *:${app_port}`);
});
