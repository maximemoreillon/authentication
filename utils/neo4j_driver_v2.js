const neo4j = require('neo4j-driver')
const {
  neo4j: {
    url,
    auth: { username, password }
  }
} = require('../config.js')

const auth = neo4j.auth.basic(username, password)
const options = { disableLosslessIntegers: true }
const driver = neo4j.driver(url, auth, options)

module.exports = driver
