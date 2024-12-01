const express = require('express')
const users = require('../../controllers/users/users.js')
const router = express.Router()


router.post('/users/signup', users.signUpUser)
router.post('/users/login', users.signIpUser)

module.exports = router
