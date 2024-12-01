const express = require('express')
const logger = require('morgan')
const cors = require('cors')
const path = require('path')
const contactsRouter = require('./routes/api/contacts')
const newUsersRouter = require('./routes/api/newUsers')
const usersRouter = require('./routes/api/users')
const JWTStrategy = require('./config/jwt')
const authMiddleware = require('./middlewares/jwt')
const app = express()

const formatsLogger = app.get('env') === 'development' ? 'dev' : 'short'


app.set('viev engine', 'ejs')
app.use(express.static(path.resolve(__dirname, "./public")))
app.use(express.json())
app.use(cors())
app.use(logger(formatsLogger))




JWTStrategy()
app.use('/api', newUsersRouter)
//app.use('/api', usersRouter)
app.use('/api', authMiddleware, usersRouter)
app.use('/api/contacts', authMiddleware ,contactsRouter)


app.use((req, res) => {
  res.status(404).json({ message: `Not found - ${req.path}` })
})

app.use((err, req, res, next) => {
  console.log(err.name)
  if(err.name === 'ValidationError'){
    return res.status(400).json({ message: err.message })
  }
  if(err.name === 'BodyData'){
    return res.status(400).json({ message: err.message })
  }
  if(err.name === 'IncorrectCredentials'){
    return res.status(401).json({ message: err.message })
  }
  if(err.name === 'OcupatedEmail'){
    return res.status(409).json({ message: err.message })
  }





  res.status(500).json({ message: err.message })
})

module.exports = app
