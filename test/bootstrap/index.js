let express = require('express');
let app = express();
let passport = require('passport');
let WeixinStrategy = require('../..');

let providers = require('./providers.json');
let locals = require('./providers.local.js');


app.use(passport.initialize());

for (let name in providers) {
  if (providers.hasOwnProperty(name)) {
    let provider = Object.assign(providers[name], locals[name]);
    passport.use(name, new WeixinStrategy(provider, (accessToken, refreshToekn, profile, done) => {
      done(null, profile);
    }));

    app.get('/auth/' + name, passport.authenticate(name, {
      session: false, successRedirect: '/auth/account'
    }));
  }
}

app.get('/auth/account', (req, res) => {
  res.json(Object.assign({result_status:'ok'}, req.params, req.query));
});

app.listen(3000, () => {
  console.log('Weixin passport listen: http://0.0.0.0:3000');
})
