const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken')

const restricted = (req, res, next) => {
  let token = req.headers.authorization
  if (!token) {
    return next( {status : 401 , message: 'Token required'})
  }
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      next({status: 401, message: 'Token invalid'})
    } else {
      req.decodedToken = decoded
      next()
    }
  })
}

const only = role_name => (req, res, next) => {
  if (req.decodedToken.role_name !== role_name) {
    res.status(403).json({message: 'This is not for you'})
  } else {
    next()
  }
}

const checkUsernameExists = (req, res, next) => {
  const {username} = req.body
  console.log(username)
  if (!username || username.length <= 0) {
    res.status(401).json({message:"Invalid credentials"})
  } else {
    next()
  }
}

const validateRoleName = (req, res, next) => {
  let {role_name} = req.body
  if (!role_name || role_name.length === 0){
    role_name = 'student'
    next()
  }
  else if (role_name.trim() === 'admin'){
    res.status(422).json({message: 'Role name can not be admin'})
    next()
  }
  else if (role_name.trim().length > 32) {
    res.status(422).json({message: 'Role name can not be longer than 32 chars'})
    next()
  }
  else {
    req.body = {...req.body, role_name: role_name.trim()}
    next()
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
