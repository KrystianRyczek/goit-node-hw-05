const express = require('express')
const users = require('../../controllers/users/users.js')
const router = express.Router()
const {uploadMiddleware} = require('../../middlewares/multer.js')

router.get('/users/logout', users.signOutUser)
router.get('/users/current', users.currentUser)
router.post('/users/avatars',uploadMiddleware.single("avatar"), users.createAvatar)

module.exports = router

