const Joi = require('joi');
const { fetchContacts,
        fetchContact, 
        fetchAddContact, 
        fetchRemoveContact, 
        fetchUpdateContact, 
        fetchUpdateContactFavorite 
      } =require("./contactsService")
      
const schema = Joi.object({ 
  name: Joi.string().pattern(/[a-zA-Z]{2,}[/ /][a-zA-Z]{2,}/),

  phone: Joi.string().pattern(/^[/(/][0-9]{3}[/)/][/ /][0-9]{3}[/\-/][0-9]{4}/),

  email: Joi.string().pattern(/^[a-zA-Z0-9]{2,}[/@/][a-zA-Z]{2,}[/./][a-zA-Z]{2,}/),

  favorite: Joi.boolean()
})

const listContacts = async (req, res, next) => {
  try{
    const contactsList = await fetchContacts()
    res.json(contactsList)
  }catch(error){
    next(error)
  }
}

const getContactById = async (req, res, next)  => {
  try{
    const contact = await fetchContact(req.params.contactId)
    if(contact){
      res.json(contact)
    }else{
      next()
    }
  }catch(error){
    next(error)
  }
}

const addContact = async (req, res, next) => {
  try{
    if (JSON.stringify(req.body) === '{}'){
      throw new Error('No body data!')
  }
  }catch(error){
    error.name = "BodyData"
    console.log(error.name)
      return next(error)
  }

  const { error } = schema.validate({...req.body});
  if (error){
    return next(error)
  }

  try{
    const contact = await fetchAddContact(req.body)
      res.status(201).json(contact)
  }catch(error){
    next(error)
  }

}

const removeContact = async (req, res, next) => {
    try{
    const contact = await fetchRemoveContact(req.params.contactId)
    if(contact){
      res.json(contact)
    }else{
      next()
    }
  }catch(error){
    next(error)
  }
}

const updateContact = async (req, res, next) => {
  try{
    if (JSON.stringify(req.body) === '{}'){
      throw new Error('No body data!')
  }
  }catch(error){
      error.name = "BodyData"
      return next(error)
  }
  const { error } = schema.validate({...req.body});
  if (error){
    return next(error)
  }

  try{
    const contact = await fetchUpdateContact(req.params.contactId, req.body , {new:true, runValidators:true})
    if(contact){
      res.json(contact)
    }else{
      next()
    }
  }catch(error){
    next(error)
  }

}

const updateContactFavorite = async (req, res, next) => {
  try{
    if (JSON.stringify(req.body) === '{}'){
      throw new Error('No body data!')
  }
  }catch(error){
      error.name = "BodyData"
      return next(error)
  }

  try{
    const contact = await fetchUpdateContactFavorite(req.params.contactId, req.body , {new:true, runValidators:true})
    if(contact){
      res.json(contact)
    }else{
      next()
    }
  }catch(error){
    next(error)
  }

}

module.exports = {
  listContacts,
  getContactById,
  removeContact,
  addContact,
  updateContact,
  updateContactFavorite,
}
