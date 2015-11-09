var url = require('url')
  , util = require('util')
  , utils = require('passport-oauth2/lib/utils')
  , AuthorizationError = require('passport-oauth2/lib/errors/authorizationerror')
  ;

exports.authenticate = function(req, options) {
  options = options || {};
  var self = this;
  if (req.query && req.query.error) {
    if (req.query.error == 'access_denied') {
      return this.fail({
        message: req.query.error_description
      });
    } else {
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }
  }

  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req, {
        proxy: this._trustProxy
      }), callbackURL);
    }
  }

  if (req.query && req.query.code) {
    var code = req.query.code;

    if (this._state) {
      if (!req.session) {
        return this.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?'));
      }

      var key = this._key;
      if (!req.session[key]) {
        return this.fail({
          message: 'Unable to verify authorization request state.'
        }, 403);
      }
      var state = req.session[key].state;
      if (!state) {
        return this.fail({
          message: 'Unable to verify authorization request state.'
        }, 403);
      }

      delete req.session[key].state;
      if (Object.keys(req.session[key]).length === 0) {
        delete req.session[key];
      }

      if (state !== req.query.state) {
        return this.fail({
          message: 'Invalid authorization request state.'
        }, 403);
      }
    }

    var params = this.tokenParams(options);
    params.grant_type = 'authorization_code';
    params.redirect_uri = callbackURL;
    this._oauth2.getOAuthAccessToken(code, params,
      function(err, accessToken, refreshToken, params) {
        if (err) {
          return self.error(self._createOAuthError('Failed to obtain access token', err));
        }

        if (params.errcode) {
          return self.error(new Error(params.errmsg));
        }

        self._loadUserProfile(accessToken, params.openid, function(err, profile) {
          if (err) {
            return self.error(err);
          }

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
                self._verify(req, accessToken, refreshToken, params, profile, verified);
              } else { // arity == 5
                self._verify(req, accessToken, refreshToken, profile, verified);
              }
            } else {
              var arity = self._verify.length;
              if (arity == 5) {
                self._verify(accessToken, refreshToken, params, profile, verified);
              } else { // arity == 4
                self._verify(accessToken, refreshToken, profile, verified);
              }
            }
          } catch (ex) {
            return self.error(ex);
          }
        });
      }
    );
  } else {
    var params = this.authorizationParams(options);
    params.redirect_uri = callbackURL;
    params.response_type = 'code';

    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) {
        scope = scope.join(this._scopeSeparator);
      }
      params.scope = scope;
    }
    var state = options.state;
    if (state) {
      params.state = state;
    } else if (this._state) {
      if (!req.session) {
        return this.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?'));
      }

      var key = this._key;
      state = uid(24);
      if (!req.session[key]) {
        req.session[key] = {};
      }
      req.session[key].state = state;
      params.state = state;
    }
    var location = this.getAuthorizeUrl(params);
    this.redirect(location);
  }
};

exports._loadUserProfile = function(accessToken, openid, done) {
  var self = this;

  function loadIt() {
    return self.userProfile(accessToken, openid, done);
  }

  function skipIt() {
    return done(null);
  }

  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(accessToken, openid, function(err, skip) {
      if (err) {
        return done(err);
      }
      if (!skip) {
        return loadIt();
      }
      return skipIt();
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
    if (!skip) {
      return loadIt();
    }
    return skipIt();
  }
};
