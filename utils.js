const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const {jwt_secret} = require('./config.js')
const Cookies = require('cookies')

exports.error_handling = (error, res) => {
  const {tag} = error
  let status_code = error.code || 500
  const message = error.message || error
  if(isNaN(status_code)) status_code = 500
  res.status(status_code).send(message)
  console.log(message)
}

// THIS HAS CHANGED
const user_id_filter = ` WHERE user._id = $user_id `
exports.user_id_filter = user_id_filter
exports.user_query = `MATCH (user:User) ${user_id_filter}`


exports.check_password = (password_plain, password_hashed) => bcrypt.compare(password_plain, password_hashed)

exports.generate_token = (user) => new Promise( (resolve, reject) => {

  // Check if the secret is set
  if(!jwt_secret) return reject({code: 500, message: `Token secret not set`})

  // WARNING: no longer using identity
  const user_id = user._id || user.properties._id

  if(!user_id) return reject({code: 500, message: `User does not have an ID`})

  const token_content = { user_id }

  jwt.sign(token_content, jwt_secret, (error, token) => {

    // handle signing errors
    if(error) return reject({code: 500, message: error})

    // Resolve with token
    resolve(token)

    console.log(`[Auth] Token generated for user ${user_id}`)

  })
})

exports.verify_token = (token) => new Promise ( (resolve, reject) => {

  // Check if the secret is set
  if(!jwt_secret) return reject({code: 500, message: `Token secret not set`})

  jwt.verify(token, jwt_secret, (error, decoded_token) => {

    if(error) return reject({code: 403, message: `Invalid JWT`})

    resolve(decoded_token)

    console.log(`[Auth] Token decoded successfully`)

  })
})

exports.retrieve_jwt = (req, res) => new Promise( (resolve, reject) => {
  // retrieve JWT from anywhere

  const jwt = req.headers.authorization?.split(" ")[1]
    || (new Cookies(req, res)).get('jwt')
    || (new Cookies(req, res)).get('token')
    || req.query.jwt
    || req.query.token

  if(!jwt) return reject(`JWT not provided`)

  resolve(jwt)
})



exports.retrieve_token_from_body_or_query = (req) => new Promise ( (resolve, reject) => {

  const token = req.body.token
    || req.body.jwt
    || req.query.jwt
    || req.query.token

  if(!token) return reject({code: 403, message: `Missing token`})

  resolve(token)

  console.log(`[Auth] Token retrieved from body or query`)

})
