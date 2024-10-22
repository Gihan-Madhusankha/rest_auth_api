const express = require('express');
const Datastore = require('nedb-promises');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const crypto = require('crypto');
const NodeCache = require('node-cache');

const config = require('./config');

// initialize express
const app = express();

// configure body parser 
app.use(express.json());

const cache = new NodeCache();

const users = Datastore.create('db/Users.db');
const userRefreshTokens = Datastore.create('db/UserRefreshTokens.db');
const userInvalidtokens = Datastore.create('db/UserInvalidTokens.db');

app.get('/', (req, res) => {
    return res.status(200).json({
        message: 'Welcome to the API',
    })
});

app.get('/api/users', async (req, res) => {
    try {
        const allUsers = await users.find({});
        return res.status(200).json(allUsers);
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        if (!name || !email || !password) {
            return res.status(422).json({ message: 'Please enter all fields' });
        }

        if (await users.findOne({ email })) {
            return res.status(409).json({
                message: 'email already exists',
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await users.insert({
            name,
            email,
            password: hashedPassword,
            role: role ?? 'member',
            '2faEnable': false,
            '2faSecret': null
        });

        return res.status(201).json({ message: 'user registered successfully', user: newUser });

    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(422).json({
                message: 'please enter all fields',
            })
        }

        const user = await users.findOne({ email });

        if (!user) {
            return res.status(401).json({
                message: 'email or password is invalid'
            })
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({
                message: 'email or password is invalid'
            })
        }

        if (user['2faEnable']) {
            const tempToken = crypto.randomUUID();

            cache.set(config.cacheTemporaryTokenPrefix + tempToken, user._id, config.cacheTemporaryTokenExpiresInSeconds);

            return res.status(200).json({
                tempToken, expiresInSeconds: config.cacheTemporaryTokenExpiresInSeconds
            })
        } else {
            const accessToken = jwt.sign({ userId: user._id, name: user.name }, config.accessTokenSecret, { subject: 'accessApi', expiresIn: config.accessTokenExpiresIn })

            const refreshToken = jwt.sign({ userId: user._id }, config.refreshTokenSecret, { subject: 'refreshToken', expiresIn: config.refreshTokenExpiresIn });

            await userRefreshTokens.insert({
                refreshToken,
                userId: user._id
            });

            return res.status(200).json({
                id: user._id,
                name: user.name,
                email: user.email,
                accessToken,
                refreshToken
            });
        }

    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

app.post('/api/auth/login/2fa', async (req, res) => {
    try {
        const { tempToken, totp } = req.body;

        if (!tempToken || !totp) {
            return res.status(422).json({ message: 'Please enter the temporary token and TOTP' });
        }

        const userId = cache.get(config.cacheTemporaryTokenPrefix + tempToken);

        if (!userId) {
            return res.status(400).json({
                message: 'Temporary token is invalid or expired'
            });
        }

        const user = await users.findOne({ _id: userId })

        const verified = authenticator.check(totp, user['2faSecret']);

        if (!verified) {
            return res.status(401).json({
                message: 'The provided TOTP incorrect or expired'
            })
        }

        const accessToken = jwt.sign({ userId: user._id, name: user.name }, config.accessTokenSecret, { subject: 'accessApi', expiresIn: config.accessTokenExpiresIn })

        const refreshToken = jwt.sign({ userId: user._id }, config.refreshTokenSecret, { subject: 'refreshToken', expiresIn: config.refreshTokenExpiresIn });

        await userRefreshTokens.insert({
            refreshToken,
            userId: user._id
        });

        return res.status(200).json({
            id: user._id,
            name: user.name,
            email: user.email,
            accessToken,
            refreshToken
        });

    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

app.post('/api/auth/refresh-token', async (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            if (error instanceof jwt.TokenExpiredError || error instanceof jwt.JsonWebTokenError) {
                return res.status(401).json({
                    message: 'Invalid or expired'
                });
            }

            return res.status(401).json({
                message: 'Refresh token is not found'
            })
        }

        const decodedRefreshToken = jwt.verify(refreshToken, config.refreshTokenSecret);

        const userRefreshToken = await userRefreshTokens.findOne({ refreshToken, userId: decodedRefreshToken.userId });
        console.log('userRefreshToken ', userRefreshToken);
        

        if (!userRefreshToken) {
            return res.status(401).json({
                message: 'Refresh token is invalid or expired'
            });
        }

        await userRefreshTokens.remove({ _id: userRefreshToken._id });
        await userRefreshTokens.compactDatafile();

        const accessToken = jwt.sign({ userId: decodedRefreshToken.userId }, config.accessTokenSecret, { subject: 'accessApi', expiresIn: config.accessTokenExpiresIn })

        const newRefreshToken = jwt.sign({ userId: decodedRefreshToken.userId }, config.refreshTokenSecret, { subject: 'refreshToken', expiresIn: config.refreshTokenExpiresIn });

        await userRefreshTokens.insert({
            refreshToken: newRefreshToken,
            userId: decodedRefreshToken.userId
        });

        return res.status(200).json({
            accessToken,
            refreshToken: newRefreshToken
        });

    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
})

app.get('/api/auth/2fa/generate', ensureAuthentication, async (req, res) => {
    try {
        const user = await users.findOne({ _id: req.user.id });
        const secret = authenticator.generateSecret();
        const uri = authenticator.keyuri(user.email, 'manfra.io', secret);

        await users.update({ _id: req.user.id }, { $set: { '2faSecret': secret } });
        await users.compactDatafile();

        const qr = await qrcode.toBuffer(uri, { type: 'image/png', margin: 1 });

        res.setHeader('Content-Disposition', 'attachment; filename=qrcode.png');
        return res.status(200).type('image/png').send(qr);

    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

app.post('/api/auth/2fa/enable', ensureAuthentication, async (req, res) => {
    try {
        const { totp } = req.body;
        if (!totp) {
            return res.status(422).json({ message: 'Please enter the TOTP' });
        }

        const user = await users.findOne({ _id: req.user.id });

        const verified = authenticator.check(totp, user['2faSecret']);

        if (!verified) {
            return res.status(400).json({
                message: 'Invalid TOTP or expired'
            });
        }

        await users.update({ _id: req.user.id }, { $set: { '2faEnable': true } });
        await users.compactDatafile();

        return res.status(200).json({
            message: 'TOTP validated successfully'
        })

    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
})

app.get('/api/auth/logout', ensureAuthentication, async (req, res) => {
    try {
        await userRefreshTokens.removeMany({ userId: req.user.id });
        await userRefreshTokens.compactDatafile();

        await userInvalidtokens.insert({
            accessToken: req.accessToken.value,
            userId: req.user.id,
            expirationTime: req.accessToken.exp
        });

        return res.status(204).send();

    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
})

app.get('/api/users/current', ensureAuthentication, async (req, res) => {
    try {
        const user = await users.findOne({ _id: req.user.id });

        return res.status(200).json({
            id: user._id,
            name: user.name,
            email: user.email
        })
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
})

app.get('/api/admin', ensureAuthentication, authorize(['admin']), async (req, res) => {
    return res.status(200).json({
        message: 'only admin can access this route'
    })
});

app.get('/api/moderator', ensureAuthentication, authorize(['admin', 'moderator']), async (req, res) => {
    return res.status(200).json({
        message: 'only admin and moderators can access this route'
    })
});


// middlewares
async function ensureAuthentication(req, res, next) {
    const accessToken = req.headers.authorization;

    if (!accessToken) {
        return res.status(401).json({
            message: 'Access token not found'
        })
    }

    if (await userInvalidtokens.findOne({ accessToken })) {
        return res.status(401).json({
            message: 'Access token is invalid',
            code: 'AccessTokenInvalid'
        })
    }

    try {
        const decodedAccessToken = jwt.verify(accessToken, config.accessTokenSecret);
        console.log(decodedAccessToken);

        req.accessToken = { value: accessToken, exp: decodedAccessToken.exp }
        req.user = { id: decodedAccessToken.userId }

        next();

    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return res.status(401).json({
                message: 'Access token expired',
                code: 'AccessTokenExpired'
            })
        } else if (error instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({
                message: 'Access token invalid',
                code: 'AccessTokenInvalid'
            })
        } else {
            return res.status(500).json({
                message: error.message
            })
        }
    }
}

function authorize(roles = []) {
    return async function (req, res, next) {
        const user = await users.findOne({ _id: req.user.id });

        if (!user || !roles.includes(user.role)) {
            return res.status(403).json({
                message: 'Access denied'
            })
        }

        next();
    }
}


const PORT = 4000;
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
