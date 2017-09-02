var url = require('url')
  , util = require('util')
  , utils = require('passport-oauth2/lib/utils')
  , AuthorizationError = require('passport-oauth2/lib/errors/authorizationerror')
  , request = require('superagent')
  , Profile = require('./profile')
  ;

exports.authenticate = function (req, options) {
  options = options || {};
  var self = this;
  if (req.query) {
    if (req.query.error) {
      if (req.query.error == 'access_denied') {
        return this.fail({
          message: req.query.error_description
        });
      } else {
        return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
      }
    } else if (!req.query.code) {
      return this.fail({
        message: 'no code'
      });
    }
  } else {
    return this.fail({
      message: 'no code'
    });
  }

  var params = this.tokenParams(options);
  params.js_code = req.query.code;
  params.grant_type = 'authorization_code';
  request.get(self._authorizationURL)
    .accept('json')
    .query(params)
    .end(function done(err, res) {
      if (err) {
        return self.error(self._createOAuthError('Failed to obtain session_key', err));
      }

      if (res.header['content-type'] === "text/plain") {
        res.body = JSON.parse(res.text);
      }
      if (res.body.errcode) {
        return self.fail(res.body.errmsg);
      }
      var profile = Profile.parse(res.body);
      profile.provider = 'weixin';
      profile._json = res.body;

      function verified(err, user, info) {
        if (err) {
          return self.error(err);
        }
        if (!user) {
          return self.fail(info);
        }
        self.success(user, info);
      }

      try {
        if (self._passReqToCallback) {
          var arity = self._verify.length;
          if (arity == 6) {
            self._verify(req, null, null, params, profile, verified);
          } else { // arity == 5
            self._verify(req, null, null, profile, verified);
          }
        } else {
          var arity = self._verify.length;
          if (arity == 5) {
            self._verify(null, null, params, profile, verified);
          } else { // arity == 4
            self._verify(null, null, profile, verified);
          }
        }
      } catch (ex) {
        return self.error(ex);
      }
    });
}