
/*
 * GET home page.
 */

exports.index = function(req, res) {
  res.render('index', { title: 'Passport-Mongoose' });
};

exports.login = function(req, res) {
  res.render('login', { title: 'Passport-Mongoose', error: req.flash('error') });
};

exports.login__post = function(req, res) {
  res.redirect('/');
};