const {
  drivers: { v2: driver },
} = require("../../db.js")
const {
  error_handling,
  user_query,
  user_id_filter,
  check_password,
  verify_token,
  generate_token,
  retrieve_jwt,
  retrieve_token_from_body_or_query,
  find_user_in_db,
  find_user_by_id,
  register_last_login,
} = require("../../utils.js")

exports.login = async (req, res) => {
  const referrer = req.get("Referrer")
  console.log(`[/v3/login] referrer: ${referrer}`)

  try {
    const identifier =
      req.body.username ||
      req.body.email_address ||
      req.body.email ||
      req.body.identifier

    const { password } = req.body

    if (!identifier)
      return res.status(400).send(`Missing username or e-mail address`)
    if (!password) return res.status(400).send(`Missing password`)

    console.log(`[Auth v2] Login attempt from user identified as ${identifier}`)

    const user = await find_user_in_db({ driver, identifier })

    if (user.properties.locked)
      throw { code: 403, message: `User account ${identifier} is locked` }

    const { password_hashed, _id } = user.properties
    if (!password_hashed)
      throw { code: 500, message: "User does not have a password" }
    await check_password(password, password_hashed)

    await register_last_login({ driver, user_id: _id })

    const token = await generate_token(user)
    res.send({ jwt: token })
  } catch (error) {
    error_handling(error, res)
  }
}

exports.whoami = async (req, res) => {
  // Retrieves user information based on JWT present in auth header

  const referrer = req.get("Referrer")
  console.log(`[/v2/whoami] referrer: ${referrer}`)

  try {
    const token = await retrieve_jwt(req, res)
    const { user_id } = await verify_token(token)
    if (!user_id) throw { code: 400, message: `No user ID in token` }
    const user = await find_user_by_id({ driver, user_id })

    // Hide password_hashed from response
    delete user.properties.password_hashed

    res.send(user)
    console.log(`[Auth v2] user ${user_id} retrieved using token`)
  } catch (error) {
    error_handling(error, res)
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
    error_handling(error, res)
  }
}

exports.get_user_from_jwt = async (req, res) => {
  const referrer = req.get("Referrer")
  console.log(`[/v2/user_from_jwt] referrer: ${referrer}`)

  try {
    const token = await retrieve_token_from_body_or_query(req)
    const { user_id } = await verify_token(token)
    if (!user_id) throw { code: 400, message: `No user ID in token` }
    const user = await find_user_by_id({ driver, user_id })
    // Hide password_hashed from response
    delete user.properties.password_hashed
    res.send(user)
    console.log(`[Auth v2] user ${user_id} retrieved using token`)
  } catch (error) {
    error_handling(error, res)
  }
}
