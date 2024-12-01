const Passport = require('passport')
const PassportJWT = require('passport-jwt')
const Users = require('../models/UsersDB')
require('dotenv').config()


function JWTStrategy(){
    const {SECRET:secret}=process.env
    const params ={
        secretOrKey: secret,
        jwtFromRequest: PassportJWT.ExtractJwt.fromAuthHeaderAsBearerToken()
    }
    Passport.use(
        new PassportJWT.Strategy(
            params,
            async function (payload, done) {
                try{
                    const user = await Users.findOne({ _id: payload.id }).lean()
                    if(!user){
                        return done (new Error('User not found.'))
                    }
                    return done(null, user)
                }catch(err){
                    return done(err)
                }
            }

        )

    )
} 


module.exports = JWTStrategy