const querystring = require('querystring')
const request = require('request')
const AccessToken = require('./access_token.js')
import { postJSON, url_request } from './utils'

// const AuthorizeUrl = 'https://open.work.weixin.qq.com/wwopen/sso/qrConnect'
const AuthorizeUrl = 'https://open.weixin.qq.com/connect/oauth2/authorize'
const AccessTokenUrl = 'https://qyapi.weixin.qq.com/cgi-bin/gettoken'
const UserInfoUrl = 'https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo'
const UserDetailUrl = 'https://qyapi.weixin.qq.com/cgi-bin/user/getuserdetail'


const OAuth = function(corpId, suiteSecret, agentId, appId, getAccessToken, saveAccessToken) {
  if (!corpId || !suiteSecret || !agentId) {
    throw new Error('Wechat Work OAuth requires \'corpId\', \'suiteSecret\' and  \'agentId\'')
  }
  if (!getAccessToken || !saveAccessToken) {
    throw new Error('Wechat Work OAuth requires \'getAccessToken\' and \'saveAccessToken\'')
  }

  if (!(this instanceof OAuth)) {
    return new OAuth(corpId, suiteSecret, agentId, appId, getAccessToken, saveAccessToken)
  }
  this._corpId = corpId
  this._suiteSecret = suiteSecret
  this._agentId = agentId
  this._appId = appId
  this._getAccessToken = getAccessToken
  this._saveAccessToken = saveAccessToken
}

OAuth.prototype.getAuthorizeUrl = function(options) {
  const params = {}
  params['appid'] = this._corpId // this._appId
  params['agentid'] = options.agentId
  params['redirect_uri'] = options.redirect_uri
  params['response_type'] = "code"
  params['href'] = options.href
  params['scope'] = options.scope || 'snsapi_userinfo' // 'snsapi_login'
  params['state'] = options.state || 'state'
  return AuthorizeUrl + '?' + querystring.stringify(params) + '#wechat_redirect'
}

OAuth.prototype.getOAuthAccessToken = function(callback) {
  const params = {}
  params['corpid'] = this._corpId
  params['suiteSecret'] = this._suiteSecret
  const url = AccessTokenUrl + '?' + querystring.stringify(params)
  const self = this
  wechatRequest(url, function(err, result) {
    if (err) {
      return callback(err)
    }
    const accessToken = new AccessToken(result.access_token, result.expires_in, Date.now())
    self._saveAccessToken(accessToken)
    callback(null, accessToken)
  })
}

OAuth.prototype.getAccessToken = function(callback) {
  const self = this
  this._getAccessToken(this._corpId, function(err, accessToken) {
    if (err || !accessToken || accessToken.isExpired()) {
      self.getOAuthAccessToken(callback)
    } else {
      callback(null, accessToken)
    }
  })
}

OAuth.prototype.getUserInfo = function(accessToken, code, callback) {
  const params = {}
  params['access_token'] = accessToken.access_token
  params['code'] = code
  const url = UserInfoUrl + '?' + querystring.stringify(params)
  wechatRequest(url, callback)
}

OAuth.prototype.getUserDetail = function(accessToken, userTicket, callback) {
  const params = {}
  params['access_token'] = accessToken.access_token
  const postData = {}
  postData['user_ticket'] = userTicket
  const url = UserDetailUrl + '?' + querystring.stringify(params)
  wechatRequest2(url, postData, callback)
}

function wechatRequest(url, callback) {
  request(url, function(err, res, body) {
    if (err) return callback(err)
    var result = null
    try {
      result = JSON.parse(body)
    } catch (e) {
      return callback(e)
    }
    if (result.errcode) return callback(result)
    callback(null, result)
  })
}

function wechatRequest2(url, requestData, callback) {
  url_request(url, postJSON(requestData), function(err, res, body) {
    if (err) return callback(err)
    var result = body
    if (result.errcode) return callback(result)
    callback(null, result)
  })
}

module.exports = OAuth
