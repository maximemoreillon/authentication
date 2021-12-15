const express = require('express')
const controller = require('../../controllers/v3/authentication.js')

const router = express.Router()

router.route('/login')
  .post(controller.login)

router.route('/whoami')
  .post(controller.whoami)
  .get(controller.whoami)

router.route('/user_from_jwt')
  .post(controller.get_user_from_jwt)
  .get(controller.get_user_from_jwt)

router.route('/user_from_token')
  .post(controller.get_user_from_jwt)
  .get(controller.get_user_from_jwt)

router.route('/decode_jwt')
  .get(controller.decode_token)
  .post(controller.decode_token)

router.route('/decode_token')
  .get(controller.decode_token)
  .post(controller.decode_token)


module.exports = router
