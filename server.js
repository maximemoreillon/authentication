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

// custom modules
const secrets = require('./secrets');

const app_port = 8088;
const saltRounds = 10;


const send_login_status = (req, res) => {
  res.send("Not implemented yet");
}

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

  // Check if username matches
  // (Only one user at the moment)
  if(req.body.username !== secrets.username){
    return res.status(400).send('Invalid username')
  }

  // Now check if the password is correct
  bcrypt.compare(req.body.password, secrets.password_hashed, (err, result) => {
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


// Start server
app.listen(app_port, () => {
  console.log(`Authentication manager listening on *:${app_port}`);
});
