const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../secrets'); // use this secret!
const tokenBuilder = require('./token-builder');
const bcrypt = require('bcryptjs');
const Users = require('../users/users-model');

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    next({
      status: 401,
      message: 'Token required',
    });
  } else {
    jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
      if (err) {
        next({
          status: 401,
          message: 'Token invalid',
        });
      } else {
        req.decodedToken = decodedToken;
        next();
      }
    });
  }
};

const only = (role_name) => (req, res, next) => {
  if (req.decodedToken.role_name !== role_name) {
    next({
      status: 403,
      message: 'This is not for you',
    });
  } else {
    next();
  }
};

const checkUsernameExists = async (req, res, next) => {
  const usernameExists = await Users.findBy({ username: req.body.username });
  if (!usernameExists) {
    next({
      status: 401,
      message: 'Invalid credentials',
    });
  } else {
    next();
  }
};

const validateRoleName = async (req, res, next) => {
  const role_name = req.body.role_name;
  if (!role_name || role_name.trim().length < 1) {
    req.role_name = 'student';
    next();
  } else if (role_name.trim() === 'admin') {
    next({
      status: 422,
      message: 'Role name can not be admin',
    });
  } else if (role_name.trim().length > 32) {
    next({
      status: 422,
      message: 'Role name can not be longer than 32 chars',
    });
  } else {
    req.role_name = role_name.trim();
    next();
  }
};

const hashPassword = (req, res, next) => {
  const { password } = req.body;
  const rounds = process.env.BCRYPT_ROUNDS || 10;
  const hash = bcrypt.hashSync(password, rounds);
  req.body.password = hash;
  next();
};

const checkPassword = async (req, res, next) => {
  const { username, password } = req.body;
  const user = await Users.findBy({ username });
  if (user && bcrypt.compareSync(password, user.password)) {
    const token = tokenBuilder(user);
    req.token = token;
    next();
  } else {
    next({
      status: 401,
      message: 'Invalid credentials',
    });
  }
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
  hashPassword,
  checkPassword,
};
