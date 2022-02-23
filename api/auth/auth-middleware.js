const { JWT_SECRET } = require('../secrets'); // use this secret!
const jwt = require('jsonwebtoken');
const User = require('../users/users-model');

const restricted = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
        next({ status: 401, message: 'Token required' });
    } else {
        jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
            if (err) {
                next({ status: 401, message: 'Token invalid' });
            } else {
                req.decodedJWT = decodedToken;
                next();
            }
        });
    }
};

const only = (role_name) => (req, res, next) => {
    if (role_name !== req.decodedJWT.role_name) {
        next({ status: 403, message: 'This is not for you' });
    } else {
        next();
    }
};

const checkUsernameExists = async (req, res, next) => {
    try {
        const { username } = req.body;
        const [user] = await User.findBy({ username: username });
;        if (!user) {
            next({ status: 401, message: 'Invalid credentials' });
        } else {
            next();
        }
    } catch (err) {
        next(err);
    }
};

const validateRoleName = (req, res, next) => {
    const role = req.body.role_name = typeof(req.body.role_name) === 'string' && req.body.role_name.trim();

    if (!role || !role.trim()) {
      req.body.role_name = 'student';
      next();
    } else if (role.trim() === 'admin') {
      next({ status: 422, message: "Role name can not be admin" });
    } else if (role.trim().length > 32) {
      next({ status: 422, message: "Role name can not be longer than 32 chars" });
    } else {
      next();
    }
};

module.exports = {
    restricted,
    checkUsernameExists,
    validateRoleName,
    only,
};
