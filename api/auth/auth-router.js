const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../users/users-model');

const router = require('express').Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require('../secrets'); // use this secret!

router.post('/register', validateRoleName, async (req, res, next) => {
    try {
        const { username, password, role_name } = req.body;
        const passwordHash = bcrypt.hashSync(password, 8);

        await User.add({ username, password: passwordHash, role_name })
            .then((addedUser) => {
                res.status(201).json(addedUser);
            }).catch(next);
    } catch (err) {
        next(err);
    }
});

router.post('/login', checkUsernameExists, (req, res, next) => {
    const { username, password } = req.body;
    User.findBy({ username })
        .then(([user]) => {
            if (user && bcrypt.compareSync(password, user.password)) {
                const token = generateToken(user);

                res.status(200).json({
                    message: `${user.username} is back!`,
                    token,
                });
            } else {
                next({ status: 401, message: 'Invalid Credentials' });
            }
        })
        .catch(next);
});

const generateToken = (user) => {
    const payload = {
        subject: user.user_id,
        username: user.username,
        role_name: user.role_name,
    };

    return jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' });
};

module.exports = router;
