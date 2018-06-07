/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
var url = require('url')
var util = require('util')
import utils from './utils'
var OAuth2 = require('./oauth')
var async = require('async')

function WechatWorkStrategy(options, verify, getAccessToken, saveAccessToken) {
  options = options || {}

  if (!verify) {
    throw new Error('WechatWorkStrategy requires a verify callback')
  }

  if (!options.corpId) {
    throw new Error('WechatWorkStrategy requires a corpId option')
  }
  if (!options.suiteSecret) {
    throw new Error('WechatWorkStrategy requires a suiteSecret option')
  }
  if (!options.agentId) {
    throw new Error('WechatWorkStrategy requires a agentId option')
  }

  var _getAccessToken = getAccessToken || options.getAccessToken
  var _saveAccessToken = saveAccessToken || options.saveAccessToken

  if (!_getAccessToken || !_saveAccessToken) {
    throw new Error('WechatWorkStrategy requires \'getAccessToken\' and \'saveAccessToken\'')
  }

  passport.Strategy.call(this)
  this.name = 'wechat-work'
  this._verify = verify
  this._oauth = new OAuth2(options.corpId, options.suiteSecret, options.agentId, options.suiteId, _getAccessToken, _saveAccessToken)
  this._callbackURL = options.callbackURL
  this._scope = options.scope
  this._scopeSeparator = options.scopeSeparator || ' '
  this._state = options.state
  this._suiteId = options.suiteId
  this._getAccessToken = _getAccessToken
  this._saveAccessToken = _saveAccessToken
  this._passReqToCallback = options.passReqToCallback
  this._options = options;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(WechatWorkStrategy, passport.Strategy)


/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
WechatWorkStrategy.prototype.authenticate = function(req, options) {
  options = options || {}

  var self = this
  var callbackURL = options.callbackURL || this._callbackURL
  if (callbackURL) {
    var parsed = url.parse(callbackURL)
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req, {
        proxy: this._trustProxy
      }), callbackURL)
    }
  }
  var params = {}
  params = this._options;
  params.redirect_uri = callbackURL

  let corp_id = '';
  let agent_id = '';
  if (req.query.from) {
    params.redirect_uri += '?from=' + req.query.from
    const from = req.query.from;
    const items = from.split('/');
    corp_id = items[0];
    agent_id = items[1];
    this._oauth = new OAuth2(corp_id, '00', agent_id, this._suiteId, this._getAccessToken, this._saveAccessToken)
  }

  if (req.query && req.query.code) {
    var code = req.query.code
    let saveAccessToken = null
    async.waterfall([
      function(cb) {
        self._oauth.getAccessToken(cb)
      },
      function(accessToken, cb) {
        saveAccessToken = accessToken
        self._oauth.getUserInfo(accessToken, code, cb)
      },
      function(user, cb) {
        self._oauth.getUserDetail(saveAccessToken, user.user_ticket, cb)
      }
    ], function(err, profile) {
      if (err) {
        return self.error(err)
      }
      profile.id = profile.userid
      profile.displayName = profile.name
      profile.picture = profile.avatar
      if (profile.userid) {
        verifyResult(profile, verified)
      } else {
        self.fail()
      }
    })
  } else {
    var scope = options.scope || this._scope
    if (scope) {
      params.scope = scope
    }
    params.state = options.state || this._state
    params.agentId = agent_id;
    var location = this._oauth.getAuthorizeUrl(params)
    this.redirect(location, 302)
  }

  function verified(err, user, info) {
    if (err) {
      return self.error(err)
    }
    if (!user) {
      return self.fail(info)
    }
    self.success(user, info)
  }

  function verifyResult(profile, verified) {
    try {
      if (self._passReqToCallback) {
        self._verify(req, null, null, null, profile, verified)
      } else {
        self._verify(profile, verified)
      }
    } catch (ex) {
      return self.error(ex)
    }
  }
}

module.exports = WechatWorkStrategy
