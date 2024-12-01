const Contacts = require('../../models/ContactsDB')



const fetchContacts = () => {
    return Contacts.find();
}
const fetchContact = (id) => {
    return Contacts.findById({ _id: id })
}
const fetchAddContact = (bodyData) => {
    return Contacts.create({ ...bodyData });
}
const fetchRemoveContact = (id) => {
    return Contacts.deleteOne({ _id: id })}
    
const fetchUpdateContact = (id, body, params) => {
    return Contacts.findByIdAndUpdate(id, { ...body }, params)}

const fetchUpdateContactFavorite = (id, body, params) =>{
    console.log(id)
    return Contacts.findByIdAndUpdate(id, { ...body }, params)
}
module.exports = { fetchContacts,
                   fetchContact, 
                   fetchAddContact, 
                   fetchRemoveContact, 
                   fetchUpdateContact, 
                   fetchUpdateContactFavorite 
                 };