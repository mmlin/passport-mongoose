
/**
 * Module dependencies.
 */

var express = require('express')
  , routes = require('./routes')
  , http = require('http')
  , path = require('path')
  , flash = require('connect-flash');
  
// Require Passport and the Passport-Mongoose authentication strategy.
var passport = require('passport')
  , passportMongoose = require('passport-mongoose');

// Enable the Passport-Mongoose authenticiation strategy.
// Uses reasonable defaults that can be overridden.
passport.use(new passportMongoose.Strategy);

// To support persistent login sessions, Passport needs to know
// how to serialize a user instance.
passport.serializeUser(function(user, done) {
  done(null, user.username);
});

// To support persistent login sessions, Passport needs to know
// how to deserialize a user instance.
passport.deserializeUser(function(username, done) {
  done(null, {username: username});
});

var app = express();

app.configure(function(){
  app.set('port', process.env.PORT || 3000);
  app.set('views', __dirname + '/views');
  app.set('view engine', 'jade');
  app.use(express.favicon());
  app.use(express.logger('dev'));
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(express.cookieParser('All your secret are belong to us!'));
  app.use(express.session());
  app.use(flash());
  app.use(passport.initialize()); // Enable Passport authentication.
  app.use(passport.session());    // Enable persistent login sessions.
  app.use(app.router);
  app.use(express.static(path.join(__dirname, 'public')));
});

app.configure(function(){
  app.set('port', process.env.PORT || 3000);
  app.set('views', __dirname + '/views');
  app.set('view engine', 'jade');
  app.use(express.favicon());
  app.use(express.logger('dev'));
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(express.cookieParser('All your secret are belong to us!'));
  app.use(express.session());
  app.use(flash());
  app.use(passport.initialize()); // Enable Passport authentication.
  app.use(passport.session());    // Enable persistent login sessions.
  app.use(app.router);
  app.use(express.static(path.join(__dirname, 'public')));
});

app.configure('development', function(){
  app.use(express.errorHandler());
});


/**
 * Routes.
 */

app.get('/', requireAuthentication, routes.index);

app.get('/login', routes.login);
app.post('/login',
  passport.authenticate('mongoose', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
  })
);

app.get('/logout', function(req, res) {
  req.logout();
  res.redirect('/');
});


http.createServer(app).listen(app.get('port'), function(){
  console.log("Express server listening on port " + app.get('port'));
});

function requireAuthentication(req, res, next) {
  console.log('req.user: ' + req.user);
  console.log('req.isAuthenticated(): ' + req.isAuthenticated());
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login');
}
