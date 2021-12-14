const router = require('express').Router();
const Users = require('../users/users-model');
const {
  checkUsernameExists,
  validateRoleName,
  hashPassword,
  checkPassword,
} = require('./auth-middleware');

router.post('/register', validateRoleName, hashPassword, (req, res, next) => {
  Users.add(req.body)
    .then((user) => {
      res.status(201).json(user);
    })
    .catch(next);
});

router.post('/login', checkUsernameExists, checkPassword, (req, res, next) => {
  res.status(200).json({
    message: `${req.body.username} is back!`,
    token: req.token,
  });
  next();
});

module.exports = router;
