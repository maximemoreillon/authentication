const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const dotenv = require('dotenv')
const {drivers: {v1: driver}} = require('../../db.js')
const {
  error_handling,
  user_query,
  user_id_filter,
  verify_token,
  generate_token,
  retrieve_token_from_body_or_query,
  retrieve_jwt,
  check_password,
} = require('../../utils.js')

dotenv.config()


const register_last_login = (user_id) => {
  const session = driver.session()
  const query = `
    ${user_query}
    SET user.last_login = date()
    RETURN user
    `
  session.run(query, { user_id })
  .then(() => { console.log(`[Auth] Successfully registered last login for user ${user_id}`) })
  .catch((error) => { console.log(`[Auth] Error setting last login: ${error}`) })
  .finally( () => { session.close() })

}

const find_user_in_db = (identifier) => new Promise ( (resolve, reject) => {

  const session = driver.session()

  const query = `
    MATCH (user:User)

    // Allow user to identify using either userrname or email address
    WHERE user.username=$identifier
      OR user.email_address = $identifier
      OR user._id = $identifier // <= WARNING! No longer using identity

    // Return user if found
    RETURN user
    `

  const params = {identifier}

  session.run(query, params)
  .then( ({records}) => {

    if(!records.length) return reject({code: 403, message: `User ${identifier} not found`})
    if(records.length > 1) return reject({code: 500, message: `Multiple users found`})

    const user = records[0].get('user')

    if(user.properties.locked) return reject({code: 500, message: `User account ${identifier} is locked`})

    resolve(user)

    console.log(`[Neo4J] User ${identifier} found in the DB`)

  })
  .catch(error => { reject({code: 500, message:error}) })
  .finally( () => session.close())

})





exports.login = async (req, res) => {

  try {
    const identifier = req.body.username
      || req.body.email_address
      || req.body.email
      || req.body.identifier

    const {password} = req.body

    if(!identifier) return res.status(400).send(`Missing username or e-mail address`)
    if(!password) return res.status(400).send(`Missing password`)

    console.log(`[Auth] Login attempt from user identified as ${identifier}`)

    const user = await find_user_in_db(identifier)
    const {password_hashed, _id} = user.properties
    if(!password_hashed) throw {code: 500, message: 'User does not have a password'}

    await check_password(password, password_hashed)

    await register_last_login(_id)

    const token = await generate_token(user)
    res.send({ jwt: token })

  }

  catch (error) {
    error_handling(error, res)
  }

}

exports.whoami = (req, res) => {
  // Retrieves user information based on JWT present in auth header

  retrieve_jwt(req)
  .then( token => {return verify_token(token)})
  .then( decoded_token => {

    // low should not be a thing!
    const user_id = decoded_token.user_id.low || decoded_token.user_id
    if(!user_id) throw {code: 400, message: `No user ID in token`}

    return find_user_in_db(user_id)

  })
  .then( user => {
    delete user.properties.password_hashed
    res.send(user)
    console.log(`[Auth] user ${user_id} retrieved using token`)
  })
  .catch(error => {
    console.log(`[Auth] ${error.message || error}`)
    res.status(error.code || 500).send(error.message || error)
  })
}

exports.decode_token = (req, res) => {

  retrieve_token_from_body_or_query(req)
  .then( token => {return verify_token(token)})
  .then(decoded_token => { res.send(decoded_token) })
  .catch(error => {
    console.log(error.message || error)
    res.status(error.code || 500).send(error.message || error)
  })

}

exports.get_user_from_jwt = (req, res) => {

  // wrongly used in router
  retrieve_token_from_body_or_query(req)
  .then( token => {return verify_token(token)})
  .then( decoded_token => {

    const user_id = decoded_token.user_id
    if(!user_id) throw {code: 400, message: `No user ID in token`}

    console.log(user_id)

    return find_user_in_db(user_id)

  })
  .then( user => {
    delete user.properties.password_hashed
    res.send(user)
  })
  .catch(error => {
    console.log(`[Auth] ${error.message || error}`)
    res.status(error.code || 500).send(error.message || error)
  })
}
