const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const driver = require('../../utils/neo4j_driver_v2.js')
const {jwt_secret} = require('../../config.js')



const register_last_login = (user_id) => {

  const field_name = 'user'
  const query = `
    MATCH (${field_name}:User)
    WHERE id(${field_name}) = toInteger($user_id)

    SET ${field_name}.last_login = date()

    // Return user if found
    RETURN ${field_name}
    `
  const parameters = { user_id }
  const session = driver.session()

  session
    .run( query, parameters )
    .then(() => { console.log(`[Auth] Successfully registered last login for user ${user_id}`) })
    .catch((error) => { console.log(`[Auth] Error setting last login: ${error}`) })
    .finally( () => { session.close() })

}

const find_user_in_db = (identifier) => {

  return new Promise ( (resolve, reject) => {

    const query = `
      MATCH (user:User)

      // Allow user to identify using either userrname or email address
      WHERE user.username=$identifier
        OR user.email_address=$identifier
        OR id(user) = toInteger($identifier)

      // Return user if found
      RETURN user
      `

    const parameters = {identifier}

    const session = driver.session()
    session
    .run(query, parameters)
    .then( ({records}) => {

      if(records.length < 1) return reject({code: 400, message: `User ${identifier} not found`})
      if(records.length > 1) return reject({code: 500, message: `Multiple users found`})

      const user = records[0].get('user')

      if(user.properties.locked) return reject({code: 500, message: `User account ${user.identity} is locked`})

      resolve(user)

      console.log(`[Neo4J] User ${user.identity} found in the DB`)

    })
    .catch(error => { reject({code: 500, message:error}) })
    .finally( () => session.close())

  })
}

const check_password = (password_plain, user) => {
  return new Promise ( (resolve, reject) => {

    // Retrieve hashed password from user properties
    const password_hashed = user.properties.password_hashed

    // check if the user has a password
    if(!password_hashed) return reject({code: 500, message: `User ${user.identity} does not have a password`})

    bcrypt.compare(password_plain, password_hashed, (error, password_correct) => {

      // Handle check errors
      if(error) return reject({code: 500, message: error})

      // Handle incoree
      if(!password_correct) return reject({code: 403, message: `Incorrect password`})

      resolve(user)

      console.log(`[Auth] Password correct for user ${user.identity}`)

    })

  })
}

const generate_token = (user) => {
  return new Promise( (resolve, reject) => {

    // Check if the secret is set
    if(!jwt_secret) return reject({code: 500, message: `Token secret not set`})

    const token_content = { user_id: user.identity }

    jwt.sign(token_content, jwt_secret, (error, token) => {

      // handle signing errors
      if(error) return reject({code: 500, message: error})

      // Resolve with token
      resolve(token)

      console.log(`[Auth] Token generated for user ${user.identity}`)

    })
  })
}

const verify_token = (token) => {
  return new Promise ( (resolve, reject) => {

    // Check if the secret is set
    if(!jwt_secret) return reject({code: 500, message: `Token secret not set`})

    jwt.verify(token, jwt_secret, (error, decoded_token) => {

      if(error) return reject({code: 403, message: `Invalid JWT`})

      resolve(decoded_token)

      console.log(`[Auth] Token decoded successfully`)

    })
  })
}

const retrieve_token_from_body_or_query = (req) => {
  return new Promise ( (resolve, reject) => {

    const token = req.body.token
      || req.body.jwt
      || req.query.jwt
      || req.query.token

    if(!token) return reject({code: 400, message: `Missing token`})

    resolve(token)

    console.log(`[Auth] Token retrieved from body or query`)

  })
}

const retrieve_token_from_headers = (req) => {
  return new Promise ( (resolve, reject) => {

    // Check if authorization header set
    if(!req.headers.authorization) return reject({code: 400, message: `Authorization header not set`})
    // parse the headers to get the token
    const token = req.headers.authorization.split(" ")[1];
    if(!token) return reject({code: 400, message: `Token not found in authorization header`})

    resolve(token)

    console.log(`[Auth] Token retrieved from headers`)

  })
}



exports.login = (req, res) => {

  // Input sanitation
  const identifier = req.body.username
    || req.body.email_address
    || req.body.email
    || req.body.identifier

  const password = req.body.password

  if(!identifier) return res.status(400).send(`Missing username or e-mail address`)
  if(!password) return res.status(400).send(`Missing password`)

  console.log(`[Auth] Login attempt from user identified as ${identifier}`)

  find_user_in_db(identifier)
  .then( user =>  check_password(password, user) )
  .then( user => {
    // Save the last login time of the user
    register_last_login(user.identity)

    return generate_token(user)
  })
  .then( token => { res.send({ jwt: token }) })
  .catch(error => {
    console.log(error.message || error)
    res.status(error.code || 500).send(error.message || error)
  })
}

exports.whoami = (req, res) => {
  // Retrieves user information based on JWT present in auth header

  retrieve_token_from_headers(req)
  .then( token =>  verify_token(token) )
  .then( decoded_token => {

    const user_id = decoded_token.user_id
    if(!user_id) throw {code: 400, message: `No user ID in token`}

    return find_user_in_db(user_id)

  })
  .then( user => {
    delete user.properties.password_hashed
    res.send(user)
    console.log(`[Auth] user ${user.identity} retrieved using token`)
  })
  .catch(error => {
    console.log(`[Auth] ${error.message || error}`)
    res.status(error.code || 500).send(error.message || error)
  })
}

exports.decode_token = (req, res) => {

  // Not useful not widely used

  retrieve_token_from_body_or_query(req)
  .then( token => verify_token(token) )
  .then( decoded_token => { res.send(decoded_token) })
  .catch(error => {
    console.log(error.message || error)
    res.status(error.code || 500).send(error.message || error)
  })

}

exports.get_user_from_jwt = (req, res) => {

  retrieve_token_from_body_or_query(req)
  .then( token => verify_token(token) )
  .then( decoded_token => {

    const user_id = decoded_token.user_id
    if(!user_id) throw {code: 400, message: `No user ID in token`}

    return find_user_in_db(user_id)

  })
  .then( user => {
    delete user.properties.password_hashed
    res.send(user)
    console.log(`[Auth] user ${user.identity} retrieved using token`)
  })
  .catch(error => {
    console.log(`[Auth] ${error.message || error}`)
    res.status(error.code || 500).send(error.message || error)
  })
}
