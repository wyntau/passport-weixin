/**
 * Parse profile.
 *
 * @param {Object|String} json
 * @return {Object}
 * @api private
 */
exports.parse = function(json) {
  if ('string' == typeof json) {
    json = JSON.parse(json);
  }

  var profile = {};
  profile.id = String(json.unionid);
  profile.displayName = json.nickname;
  profile.profileUrl = json.headimgurl;
  if (json.email) {
    profile.emails = [{
      value: json.email
    }];
  }

  return profile;
};