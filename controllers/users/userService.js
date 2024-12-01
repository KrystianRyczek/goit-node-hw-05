const Users = require('../../models/UsersDB')
const gravatar = require('gravatar')

const  fetchAddUser = async (newUser ) => {
    newUser.avatarURL = gravatar.url(newUser.email)
    console.log(newUser)
    newUser.save()
}

const fetchFind = (filter) => {
    return Users.findOne(filter)
}

const fetchFindAndUpdate= (filter, update) => {
    return Users.findOneAndUpdate(filter, update, {new:true})
}

module.exports = { fetchAddUser,
                   fetchFind,
                   fetchFindAndUpdate,
                };