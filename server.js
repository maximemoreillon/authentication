// modules
const process = require('process');
const path = require('path');
const http = require('http');
const express = require('express');
const cookieSession = require('cookie-session')
const bodyParser = require('body-parser');
const cors = require('cors')
const history = require('connect-history-api-fallback');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const neo4j = require('neo4j-driver');

// custom modules
const secrets = require('./secrets');

const driver = neo4j.driver(
  secrets.neo4j.url,
  neo4j.auth.basic(secrets.neo4j.username, secrets.neo4j.password)
)

// Config
const app_port = 7088;
const saltRounds = 10;

// Express configuration
const app = express();
app.use(bodyParser.json());
app.use(history());

// Serve the front end (single page application created in Vue)
app.use(express.static(path.join(__dirname, 'dist')));

app.use(cors());

app.post('/login', (req, res) => {

  // Check if all necessary login information is provided
  if( !('username' in req.body && 'password' in req.body) ) return res.status(400).send('Missing username or password')

  console.log(`Login attempt from user identifying as ${req.body.username}`)

  const field_name = 'user'
  var session = driver.session()
  session
  .run(`
    MATCH (${field_name}:User {username: {username}})
    RETURN ${field_name}
    `, {
      username: req.body.username,
    })
  .then(result => {
    session.close()

    // If the user has not been found in the database
    if(result.records.length === 0) return res.status(400).send('User not found in the database')
    else console.log(`Database match for user ${req.body.username}`)

    // if there is at least a match, take the first one (a bit dirty)
    let record = result.records[0]
    let user = record.get(field_name)

    // Check if user has a password
    if(!user.properties.password_hashed) return res.status(500).send('User does not have a password')
    else console.log(`User ${req.body.username} has a password`)

    // Now check if the password is correct
    bcrypt.compare(req.body.password, user.properties.password_hashed, (err, result) => {

      // Handle hashing errors
      if(err) {
        console.log(`Error while verifying password for user ${user.properties.username}: ${err}`)
        return res.status(500).send(`Error while verifying password for user ${user.properties.username}: ${err}`)
      }
      else console.log(`Password verification successful for user ${user.properties.username}`)

      // Check validity of result
      if(!result) {
        console.log(`Incorrect password for user ${user.properties.username}`)
        return res.status(403).send(`Incorrect password for user ${user.properties.username}`)
      }
      else console.log(`Password for user ${user.properties.username} is correct`)

      // Generate JWT
      jwt.sign({ username: user.properties.username }, secrets.jwt_secret, (err, token) => {

        // handle signing errors
        if(err) {
          console.log(`Error while generating token for user ${user.properties.username}: ${err}`)
          return res.status(500).send(`Error while generating token for user ${user.properties.username}: ${err}`)
        }
        else console.log(`Successful signing of JWT for user ${user.properties.username}`)

        // Respond with JWT
        console.log(`Login procedure completed successfully for user ${user.properties.username}`)
        res.send({jwt: token});

      })
    })

  })
  .catch(error => { res.status(500).send(`Error while looking for user: ${error}`) })

})

app.post('/whoami', (req, res) => {

  if(!req.headers.authorization) return res.status(403).send('Authorization header not set')

  // parse the headers to get the token
  let token = req.headers.authorization.split(" ")[1];

  jwt.verify(token, secrets.jwt_secret, (err, decoded) => {
    if(err) return res.status(403).send('Invalid JWT')

    const field_name = 'user'
    var session = driver.session()
    session
    .run(`
      MATCH (${field_name}:User {username: {username}})
      RETURN ${field_name}
      `, {
        username: decoded.username,
      })
    .then(result => {
      session.close()

      // If the user has not been found in the database
      if(result.records.length === 0) return res.status(400).send('User not found in the database')

      // if there is at least a match, take the first one (a bit dirty)
      let record = result.records[0]
      let user = record.get(field_name)

      res.send(user)

    })
    .catch(error => { res.status(500).send(`Error while looking for user: ${error}`) })
  });

})


// Start server
app.listen(app_port, () => {
  console.log(`Authentication manager listening on *:${app_port}`);
});
