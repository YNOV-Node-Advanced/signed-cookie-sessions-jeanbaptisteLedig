const express = require('express');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const app = express();
const SECRET = 'a_very_strong_password';
const COOKIE_KEY = 'CUSTOM_SESSID';

const users = {
    admin: 'admin',
    user: 'user'
};

function hashCookie(value) {
    return crypto.createHmac('sha256', SECRET)
        .update(value)
        .digest('hex');
}

function auth(request) {
    var data = (request.get('authorization') || ':').replace('Basic ', '');
    data = Buffer.from(data, 'base64').toString().split(':', 2);
    var user = {
        name: data[0],
        password: data[1] || ''
    };
    return user;
}
app.use(cookieParser());
app.use((request, response, next) => {
    let session = request.cookies[COOKIE_KEY];
    if (session != undefined) {
        session = JSON.parse(session);
        if(hashCookie(session.user) !== session.signature) {
            return response.status(401).send('Access denied');
        } else {
            request.session = session;
            return next();
        }
    }
    var user = auth(request);
    if (!user || !users[user.name] || users[user.name] !== user.password) {
        response.set('WWW-Authenticate', 'Basic realm="Vos identifiants"');
        return response.status(401).send('Access denied');
    }
    request.session = {
        user: user.name,
        signature: hashCookie(user.name)
    };
    response.cookie(COOKIE_KEY, JSON.stringify(request.session), { expires: new Date(Date.now() + 3600 * 24 * 365), httpOnly: true });
    return next();
});

app.get('/', function (req, res) {
    res.send('Session var: ' + req.session.user);
});

app.listen(3000);