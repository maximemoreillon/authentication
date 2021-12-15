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
  find_user_in_db,
  find_user_by_id,
  register_last_login,
} = require('../../utils.js')

dotenv.config()










exports.login = async (req, res) => {

  try {
    const identifier = req.body.username
      || req.body.email_address
      || req.body.email
      || req.body.identifier

    const {password} = req.body

    if(!identifier) return res.status(400).send(`Missing username or e-mail address`)
    if(!password) return res.status(400).send(`Missing password`)

    console.log(`[Auth V1] Login attempt from user identified as ${identifier}`)

    const user = await find_user_in_db({driver,identifier})

    if(user.properties.locked) throw {code: 403, message: `User account ${identifier} is locked`}

    const {password_hashed, _id} = user.properties
    if(!password_hashed) throw {code: 500, message: 'User does not have a password'}

    await check_password(password, password_hashed)

    await register_last_login({driver, user_id:_id })

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

    return find_user_by_id({driver,user_id})

  })
  .then( user => {
    delete user.properties.password_hashed
    console.log(`[Auth v1] user ${user.properties._id} retrieved using token`)
    res.send(user)
  })
  .catch(error => {
    error_handling(error, res)
  })
}

exports.decode_token = (req, res) => {
  retrieve_token_from_body_or_query(req)
  .then( token => {return verify_token(token)})
  .then(decoded_token => { res.send(decoded_token) })
  .catch(error => {
    error_handling(error, res)
  })
}

exports.get_user_from_jwt = (req, res) => {

  // wrongly used in router
  retrieve_token_from_body_or_query(req)
  .then( token => {return verify_token(token)})
  .then( decoded_token => {

    const user_id = decoded_token.user_id.low || decoded_token.user_id
    if(!user_id) throw {code: 400, message: `No user ID in token`}

    return find_user_by_id({driver,user_id})

  })
  .then( user => {
    delete user.properties.password_hashed
    res.send(user)
  })
  .catch(error => {
    error_handling(error, res)
  })
}
