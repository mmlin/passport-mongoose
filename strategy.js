/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util')
  , BadRequestError = require('./errors/badrequesterror')
  , mongoose = require('mongoose')
  , crypto = require('crypto');

/**
 * `Strategy` constructor.
 *
 * The local authentication strategy authenticates requests based on the
 * credentials submitted through an HTML-based login form.
 *
 * Applications must supply a `verify` callback which accepts `username` and
 * `password` credentials, and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `usernameField`  field name where the username is found, defaults to _username_
 *   - `passwordField`  field name where the password is found, defaults to _password_
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new LocalStrategy(
 *       function(username, password, done) {
 *         User.findOne({ username: username, password: password }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  options = options || {};
  //if (!verify) throw new Error('local authentication strategy requires a verify function');
  
  this._usernameField = options.usernameField || 'username';
  this._passwordField = options.passwordField || 'password';
  this._saltField = options.saltField || 'salt';
  this._modelName = options.modelName || 'User';
  this._db = options.connection || mongoose.createConnection('localhost', 'test');
  try {
    this._model = this._db.model(this._modelName);
  } catch (e) {
    var schemaConfig = {};
    schemaConfig[this._usernameField] = String;
    schemaConfig[this._passwordField] = String;
    schemaConfig[this._saltField] = String;
    this._model = this._db.model(this._modelName, new mongoose.Schema(schemaConfig));
  }
  
  passport.Strategy.call(this);
  this.name = 'mongoose';
  //this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

Strategy.prototype._verify = function(username, password, done) {
  
  var usernameField = this._usernameField;
  var passwordField = this._passwordField;
  var saltField = this._saltField;
  var query = {};
  
  query[usernameField] = username;
  
  var strategy = this;
  this._model.findOne(query, function(err, user) {
  
    // Something went terribly wrong.
    if (err)
      return done(null, false, { message: err.toString() })
      
    // The user doesn't exist.
    if (!user)
      return done(null, false, { message: 'User not found' });
    
    var hashedPassword = user[passwordField];
    var salt = user[saltField];
    strategy.hashPassword(password, salt, function(err, derivedKey) {
      if (err) return done(err);
      
      // If the password isn't correct.
      if (derivedKey != hashedPassword)
        return done(null, false, { message: 'Bad password' });
      
      // Everything looks good.
      return done(null, user);
    });
  });
};

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var username = lookup(req.body, this._usernameField) || lookup(req.query, this._usernameField);
  var password = lookup(req.body, this._passwordField) || lookup(req.query, this._passwordField);
  
  if (!username || !password) {
    return this.fail(new BadRequestError(options.badRequestMessage || 'Missing credentials'));
  }
  
  var self = this;
  
  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }
  
  if (self._passReqToCallback) {
    this._verify(req, username, password, verified);
  } else {
    this._verify(username, password, verified);
  }
  
  function lookup(obj, field) {
    if (!obj) { return null; }
    var chain = field.split(']').join('').split('[');
    for (var i = 0, len = chain.length; i < len; i++) {
      var prop = obj[chain[i]];
      if (typeof(prop) === 'undefined') { return null; }
      if (typeof(prop) !== 'object') { return prop; }
      obj = prop;
    }
    return null;
  }
};

/**
 * Create a user with a given password.
 *
 * @param {String} username
 * @param {String} password
 * @param {Function} done(err, user)
 */
Strategy.prototype.createUser = function(username, password, done) {
  var user = new this._model();
  user[this._usernameField] = username;
  var salt = this.generateSalt();
  var strategy = this;
  this.hashPassword(password, salt, function(err, derivedKey) {
    if (err) return done(err);
    var user = new strategy._model();
    user[strategy._usernameField] = username;
    user[strategy._passwordField] = derivedKey;
    user[strategy._saltField] = salt;
    user.save(function(err) { done(err); });
    done(null, user);
  });
};

/**
 * Generate a salt with a given length.
 *
 * @param {Integer} length of the salt (defaults to 128)
 */
Strategy.prototype.generateSalt = function(len) {
  var set = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  var setLen = set.length;
  var salt = '';
  
  len || (len = 128);
  
  for (var i = 0; i < len; i++) {
    var p = Math.floor(Math.random() * setLen);
    salt += set[p];
  }
  return salt;
};

/**
 * Hash a password with a given salt.
 *
 * @param {String} password in plain-text
 * @param {String} salt
 * @param {Function} done(err, derivedKey)
 */
Strategy.prototype.hashPassword = function(password, salt, done) {
  var iterations = 10000;
  var keylen = 128;
  crypto.pbkdf2(password, salt, iterations, keylen, done);
};


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
