const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const dotenv = require('dotenv')

const driver = require('../neo4j_driver.js')

dotenv.config()

exports.login = (req, res) => {

  // Check if all necessary login information is provided
  if( !('password' in req.body) ) {
    console.log(`Missing password`)
    return res.status(400).send('Missing password')
  }


  let identifier = req.body.email
    || req.body.email_address
    || req.body.username
    || req.body.identifier

  if(!identifier) {
    console.log(`Missing username or email address`)
    return res.status(401).send(`Missing username or email address`)
  }

  // Here, could think of getting user from user management microservice
  const field_name = 'user'
  var session = driver.session()
  session
  .run(`
    MATCH (${field_name}:User)

    // Allow user to identify using either userrname or email address
    WHERE ${field_name}.username={identifier}
      OR ${field_name}.email_address={identifier}

    // Return user if found
    RETURN ${field_name}
    `, {
      identifier: identifier,
    })
  .then(result => {

    // If no or too many users have been found
    if(result.records.length === 0) {
      console.log(`User not found in the database`)
      return res.status(400).send('User not found in the database')
    }

    if(result.records.length > 1) {
      console.log(`Multiple users found in the database`)
      return res.status(400).send('Multiple users found in the database')
    }

    // if there is at least a match, take the first one (a bit dirty)
    let user = result.records[0].get(field_name)

    // Check if user has a password
    if(!user.properties.password_hashed) {
      console.log(`User ${user.identity.low} does not have a password`)
      return res.status(500).send('User does not have a password')
    }

    // Now check if the password is correct
    bcrypt.compare(req.body.password, user.properties.password_hashed, (err, result) => {

      // Handle hashing errors
      if(err) {
        console.log(`Error while verifying password for user ${user.identity.low}`)
        console.log(err)
        return res.status(500).send(`Error while verifying password: ${err}`)
      }

      // Check validity of result
      if(!result) {
        console.log(`Incorrect password for user ${user.identity.low}`)
        return res.status(403).send(`Incorrect password`)
      }

      // Generate JWT
      jwt.sign({ user_id: user.identity.low }, process.env.JWT_SECRET, (err, token) => {

        // handle signing errors
        if(err) {
          console.log(`Error generating token for user ${user.identity.low}`)
          console.log(err)
          return res.status(500).send(`Error while generating token: ${err}`)
        }

        console.log(`Successful login from user ${user.identity.low}`)

        // Respond with JWT
        res.send({jwt: token});

      })
    })

  })
  .catch(error => { res.status(500).send(`Error while looking for user: ${error}`) })
  .finally( () => session.close())

}


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
      let user = result.records[0].get(field_name)


      res.send(user)

    })
    .catch(error => { res.status(500).send(`Error while looking for user: ${error}`) })
    .finally( () => session.close())
  });
}

exports.whoami = (req, res) => {
  // Retrieves user information based on JWT present in auth header

  // Check if authorization header set
  if(!req.headers.authorization) return res.status(403).send('Authorization header not set')
  // parse the headers to get the token
  let token = req.headers.authorization.split(" ")[1];
  if(!token) return res.status(403).send('Token not found in authorization header')

  // Verify the token and respond
  verify_jwt_and_respond_with_user(token, res)
}

exports.get_user_from_jwt = (req, res) => {
  console.log('Hello')

  let jwt = req.query.jwt
    || req.body.jwt

  if(! jwt) {
    console.log(`JWT not provided`)
    return res.status(400).send('JWT not provided')
  }

  // Verify the token and respond
  verify_jwt_and_respond_with_user(jwt, res)
}


exports.password_update = (req, res) => {

  // Currently only works to update one's own password

  if(!req.headers.authorization) return res.status(403).send('Authorization header not set')

  // parse the headers to get the token
  let token = req.headers.authorization.split(" ")[1];
  if(!token) return res.status(403).send('Token not found in authorization header')

  // Check if necessary information provided
  if( !('new_password' in req.body) ) return res.status(400).send('Missing new password')

  // Verify JWT
  jwt.verify(token, secrets.jwt_secret, (err, decoded) => {
    if(err) return res.status(403).send('Invalid JWT')

    // Encrypt new password
    bcrypt.hash(req.body.new_password, 10, (err, hash) => {
      if(err) return res.status(500).send(`Error hashing password ${err}`)

      // Update DB
      const field_name = 'user'
      var session = driver.session()
      session
      .run(`
        MATCH (${field_name}:User)
        WHERE id(${field_name}) = toInteger({id})
        RETURN ${field_name}
        `, {
          id: decoded.id,
        })
      .then(result => {})
      .catch(error => { res.status(500).send(`Error accessing DB: ${error}`) })
      .finally(() => session.close())

    });
  })

}
