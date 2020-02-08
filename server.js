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
var jwt = require('jsonwebtoken');

// custom modules
const secrets = require('./secrets');

const app_port = 8088;
const saltRounds = 10;

const login_status = (req) => {
  return typeof(req.session.username) !== 'undefined'
}

const send_login_status = (req, res) => {
  res.send({
    logged_in: login_status(req),
    username:req.session.username,
  });
}

// Express configuration
const app = express();
app.use(bodyParser.json());
app.use(history({
  // Ignore GET routes
  rewrites: [
    { from: '/status', to: '/status'},
    { from: '/logout', to: '/logout'},
  ]
}));

// Serve the front end (single page application created in Vue)
app.use(express.static(path.join(__dirname, 'dist')));

app.use(cors({
  //origin: misc.cors_origins,
  origin: (origin, callback) => {
    callback(null, true)
  },
  credentials: true,
}));

app.use(cookieSession({
  name: 'session',
  secret: secrets.session_secret,
  maxAge: 253402300000000,
  sameSite: false,
  domain: secrets.cookies_domain
}));

app.post('/status', send_login_status);
app.get('/status', send_login_status);

app.post('/login', (req, res) => {

  // Check if all necessary login information is provided
  if( !('username' in req.body && 'password' in req.body) ){
    return res.status(403).send({
      logged_in: login_status(req),
      error: 'Missing username or password',
    });
  }

  // Check if username matches
  if(req.body.username !== secrets.username){
    return res.status(403).send({
      logged_in: login_status(req),
      error: "Invalid username",
    })
  }

  // Now check if the password is correct
  bcrypt.compare(req.body.password, secrets.password_hashed, (err, result) => {
    if(err) return res.status(500).send({
      logged_in: login_status(req),
      error: "Error checking password",
    })
    if(result) {

      // Setting session variable
      req.session.username = req.body.username;

      // Generate JWT
      jwt.sign({ username: req.body.username }, secrets.jwt_secret, (err, token) => {
        if(err) return res.status(500).send({
          logged_in: login_status(req),
          error: "Error generating token",
        })

        // Send success acknowledgement
        res.send({
          logged_in: login_status(req),
          username: req.session.username,
          jwt: token
        });

      });
    }
    else {
      res.status(403).send({
        logged_in: login_status(req),
        error: "Incorrect password",
      });
    }
  });
})

app.post('/logout', (req, res) => {
  delete req.session.username;
  res.send({
    logged_in: typeof(req.session.username) !== 'undefined',
  });
});

app.get('/logout', (req, res) => {
  delete req.session.username;
  res.redirect(req.get('Referrer'));
});


// Start server
app.listen(app_port, () => {
  console.log(`Authentication manager listening on *:${app_port}`);
});
