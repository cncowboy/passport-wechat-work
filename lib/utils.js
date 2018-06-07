import urllib from 'urllib'
/**
 * Reconstructs the original URL of the request.
 *
 * This function builds a URL that corresponds the original URL requested by the
 * client, including the protocol (http or https) and host.
 *
 * If the request passed through any proxies that terminate SSL, the
 * `X-Forwarded-Proto` header is used to detect if the request was encrypted to
 * the proxy, assuming that the proxy has been flagged as trusted.
 *
 * @param {http.IncomingMessage} req
 * @param {Object} [options]
 * @return {String}
 * @api private
 */
exports.originalURL = function(req, options) {
  options = options || {}
  var app = req.app
  if (app && app.get && app.get('trust proxy')) {
    options.proxy = true
  }
  var trustProxy = options.proxy

  var proto = (req.headers['x-forwarded-proto'] || '').toLowerCase(),
    tls = req.connection.encrypted || (trustProxy && 'https' == proto.split(/\s*,\s*/)[0]),
    host = (trustProxy && req.headers['x-forwarded-host']) || req.headers.host,
    protocol = tls ? 'https' : 'http',
    path = req.url || ''
  return protocol + '://' + host + path
}

/**
 * 设置urllib的options
 *
 */
exports.url_request = function (url, opts, callback) {
  var options = {};
  extend(options, this.defaults);
  if (typeof opts === 'function') {
    callback = opts;
    opts = {};
  }
  for (var key in opts) {
    if (key !== 'headers') {
      options[key] = opts[key];
    } else {
      if (opts.headers) {
        options.headers = options.headers || {};
        extend(options.headers, opts.headers);
      }
    }
  }
  urllib.request(url, options, callback);
};

/*!
 * 对提交参数一层封装，当POST JSON，并且结果也为JSON时使用
 */
exports.postJSON = function (data) {
  return {
    dataType: 'json',
    type: 'POST',
    data: data,
    headers: {
      'Content-Type': 'application/json'
    }
  };
};
