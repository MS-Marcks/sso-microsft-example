/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */


require('dotenv').config();

var path = require('path');
var express = require('express');
const https = require('https');
const fs = require('fs');
var session = require('express-session');
var createError = require('http-errors');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
var authRouter = require('./routes/auth');
const helmet = require("helmet");
// initialize express
var app = express();

app.use((req, res, next) => {
    if (!req.secure) {
        return res.redirect(`https://${req.headers.host}${req.url}`);
    }
    next();
});

const privateKey = fs.readFileSync('path/to/private-key/key.pem', 'utf8');
const certificate = fs.readFileSync('path/to/certificate/cert.pem', 'utf8');
const credentials = { key: privateKey, cert: certificate };

/**
 * Using express-session middleware for persistent user session. Be sure to
 * familiarize yourself with available options. Visit: https://www.npmjs.com/package/express-session
 */
app.use(session({
    secret: process.env.EXPRESS_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false, // set this to true on production
    }
}));

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');

app.use(logger('dev'));
app.use(express.json());
app.use(cookieParser());

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            "default-src": `'none'`,
            "img-src": 'https://localhost:3000',
            "child-src": `'none'`,
            "frame-ancestors": `'none'`,
            "form-action": `'none'`,
            "style-src": 'nonce-2726c7f26c',
            "font-src": `'none'`,
        }
    }
}));

app.use((req, res, next) => {
    const cookies = req.cookies;
    for (let key in cookies) {
        if (cookies.hasOwnProperty(key)) {
            res.cookie(key, cookies[key], { sameSite: 'strict', httpOnly: true });
        }
    }
    next();
});

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', indexRouter);
app.use('/users', usersRouter);
app.use('/auth', authRouter);

// catch 404 and forward to error handler
app.use(function (req, res, next) {
    next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
    // set locals, only providing error in development
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};

    // render the error page
    res.status(err.status || 500);
    res.render('error');
});
const httpsServer = https.createServer(credentials, app);

module.exports = httpsServer;
