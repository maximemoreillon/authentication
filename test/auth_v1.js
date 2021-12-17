const request = require("supertest")
const {expect} = require("chai")
const {app} = require("../server.js")
const dotenv = require('dotenv')
dotenv.config()

const {
  TEST_USERNAME = 'admin',
  TEST_PASSWORD = 'admin',
} = process.env

const sleep = (delay) => new Promise(resolve => setTimeout(resolve,delay))

// We will test for api users
describe("/v1", () => {

  let jwt

  before( async () => {
    //console.log = function () {}
    await sleep(5000) // wait for admin account to create (DIRTY)

  })

  describe("POST /v1/login", () => {

    // What should it do
    it("Should allow login with correct credentials", async () => {
      const {status, body} = await request(app)
        .post("/v1/login")
        .send({username: TEST_USERNAME, password: TEST_PASSWORD})

      jwt = body.jwt

      expect(status).to.equal(200)
    })

    it("Should not allow random user login", async () => {
      const {status} = await request(app)
        .post("/v1/login")
        .send({username: 'roger', password: 'banana'})

      expect(status).to.equal(403)
    })
  })

  describe("GET /v1/whoami", () => {

    // What should it do
    it("Should allow identification of user", async () => {
      const {status, body} = await request(app)
        .get("/v1/whoami")
        .set('Authorization', `Bearer ${jwt}`)

      expect(status).to.equal(200)
    })

  })

  describe("POST /v1/decode_token", () => {

    // What should it do
    it("Should return user details", async () => {
      const {status, body} = await request(app)
        .post("/v1/decode_token")
        .send({jwt})


      expect(status).to.equal(200)
    })

  })

  describe("POST /v1/verify_token", () => {

    // What should it do
    it("Should return user details", async () => {
      const {status, body} = await request(app)
        .post("/v1/verify_token")
        .send({jwt})


      expect(status).to.equal(200)
    })

  })
})
