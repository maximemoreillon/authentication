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
app.use(history({
  // Ignore GET routes
  rewrites: [
    { from: '/status', to: '/status'},
  ]
}));

// Serve the front end (single page application created in Vue)
app.use(express.static(path.join(__dirname, 'dist')));

app.use(cors());

app.post('/login', (req, res) => {

  // Check if all necessary login information is provided
  if( !('username' in req.body && 'password' in req.body) ){
    // 400: Bad request
    return res.status(400).send('Missing username or password');
  }

  var session = driver.session()
  session
  .run(`
    MATCH (user:User {username: {username}})
    RETURN user
    `, {
      username: req.body.username,
    })
  .then(result => {
    session.close()

    if(result.records.length === 0) return res.status(400).send('Invalid username')

    let user_from_DB = result.records[0]._fields[result.records[0]._fieldLookup['user']]

    // Now check if the password is correct
    bcrypt.compare(req.body.password, user_from_DB.properties.password_hashed, (err, result) => {
      if(err) return res.status(500).send('Error while verifying password')
      if(result) {

        // Generate JWT
        jwt.sign({ username: req.body.username }, secrets.jwt_secret, (err, token) => {
          if(err) return res.status(500).send('Error generating token')

          // Respond with JWT
          res.send({jwt: token});

        });
      }
      else res.status(403).send('Incorrect password');
    });

  })
  .catch(error => {
    res.status(500).send(`Error getting articles: ${error}`)
  })


})


// Start server
app.listen(app_port, () => {
  console.log(`Authentication manager listening on *:${app_port}`);
});
