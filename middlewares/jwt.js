const Passport = require('passport')


function authMiddleware (req, res, next){
    Passport.authenticate(
        'jwt',
        {
            session: false,
        },
        (err, user)=>{
            if(!user||err||user.token===null){
                return res.status(401).json({message: "Unauthorized"})
            }
            res.locals.user = user;
            
            next()
        }
    )(req, res, next)
}


module.exports = authMiddleware