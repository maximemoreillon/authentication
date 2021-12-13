const {drivers: {v2: driver}} = require('../../db.js')
const {
  error_handling,
  user_query,
  user_id_filter,
  check_password,
  verify_token,
  generate_token,
  retrieve_jwt,
  retrieve_token_from_body_or_query
} = require('../../utils.js')


const register_last_login = (user_id) => {

  const query = `
    ${user_query}
    SET user.last_login = date()
    RETURN user
    `
  const parameters = { user_id }
  const session = driver.session()

  return session.run( query, parameters )


}

const find_user_in_db = (identifier) => new Promise ( (resolve, reject) => {

  const query = `
    MATCH (user:User)

    // Allow user to identify using either userrname or email address
    WHERE user.username = $identifier
      OR user.email_address  = $identifier
      OR user._id = $identifier // <= No longer using identity

    // Return user if found
    RETURN user
    `

  const parameters = {identifier}

  const session = driver.session()
  session
  .run(query, parameters)
  .then( ({records}) => {

    if(!records.length) return reject({code: 403, message: `User ${identifier} not found`})
    if(records.length > 1) return reject({code: 500, message: `Multiple users found`})

    const user = records[0].get('user')

    if(user.properties.locked) return reject({code: 500, message: `User account ${identifier} is locked`})

    resolve(user)

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

    console.log(`[Auth v2] Login attempt from user identified as ${identifier}`)

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

exports.whoami = async (req, res) => {
  // Retrieves user information based on JWT present in auth header

  try {
    const token = await retrieve_jwt(req, res)
    const {user_id} = await verify_token(token)
    if(!user_id) throw {code: 400, message: `No user ID in token`}
    const user = await find_user_in_db(user_id)

    // Hide password_hashed from response
    delete user.properties.password_hashed

    res.send(user)
    console.log(`[Auth v2] user ${user_id} retrieved using token`)

  } catch (error) {
    console.log(error.message || error)
    res.status(error.code || 500).send(error.message || error)
  }

}

exports.decode_token = async (req, res) => {

  // Not useful nor widely used

  try {
    const token = await retrieve_token_from_body_or_query(req)
    const decoded_token = await verify_token(token)
    res.send(decoded_token)
    console.log(`[Auth v2] Token with content ${decoded_token} decoded`)

  } catch (error) {
    console.log(error.message || error)
    res.status(error.code || 500).send(error.message || error)
  }

}

exports.get_user_from_jwt = async (req, res) => {

  try {
    const token = await retrieve_token_from_body_or_query(req)
    const {user_id} = await verify_token(token)
    if(!user_id) throw {code: 400, message: `No user ID in token`}
    const user = await find_user_in_db(user_id)
    // Hide password_hashed from response
    delete user.properties.password_hashed
    res.send(user)
    console.log(`[Auth v2] user ${user_id} retrieved using token`)

  } catch (error) {
    console.log(error.message || error)
    res.status(error.code || 500).send(error.message || error)
  }

}
