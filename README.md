## passport-weixin
passport oauth2 strategy for weixin

### Install

    npm install passport-weixin

### Usage

    var passport = require('passport')
      , WeixinStrategy = require('passport-weixin')
      ;

    passport.use(new WeixinStrategy({
      clientID: 'CLIENTID'
      , clientSecret: 'CLIENT SECRET'
      , callbackURL: 'CALLBACK URL'
      , requireState: false
    }, function(accessToken, refreshToken, profile, done){
      done(null, profile);
    }));

### License
MIT