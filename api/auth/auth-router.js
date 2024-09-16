const router = require("express").Router();
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const Users = require('../users/users-model')
const { JWT_SECRET } = require("../secrets"); // use this secret!

router.post("/register", validateRoleName, async (req, res, next) => {
    let user = req.body
    if (!user.role_name) {
      user = {...user, role_name: 'student'}
    }
    const hash = bcrypt.hashSync(user.password, 8)
    user.password = hash
    try {
      const regUser = await Users.add(user)
      res.status(201).json(regUser)
    } catch (err) {
      next(err)
    }
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
  const {username, password} = req.body 
  try {
    const check = await Users.findBy(username)
    if(check && bcrypt.compareSync(password, check.password)) {
      let token = generateToken(check)
      //req.headers.authorization = token
      res.status(200).json({message: `${username} is back!`, token: token})
    } else {
      res.status(401).json({message: 'Invalid credentials!'})
    }   
  } catch (err) {
    next(err)
  }
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

function generateToken (check) {
  const payload = {
    subject: check.user_id,
    username: check.username,
    role_name: check.role_name,
  };
  const options = {
    expiresIn: '1d'
  }

  return jwt.sign(payload, JWT_SECRET, options)
}

module.exports = router;
