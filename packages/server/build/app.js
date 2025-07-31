require("source-map-support").install();
/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ "../../node_modules/cookie-parser/index.js":
/*!*************************************************!*\
  !*** ../../node_modules/cookie-parser/index.js ***!
  \*************************************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";
/*!
 * cookie-parser
 * Copyright(c) 2014 TJ Holowaychuk
 * Copyright(c) 2015 Douglas Christopher Wilson
 * MIT Licensed
 */



/**
 * Module dependencies.
 * @private
 */

var cookie = __webpack_require__(/*! cookie */ "../../node_modules/cookie/index.js")
var signature = __webpack_require__(/*! cookie-signature */ "../../node_modules/cookie-signature/index.js")

/**
 * Module exports.
 * @public
 */

module.exports = cookieParser
module.exports.JSONCookie = JSONCookie
module.exports.JSONCookies = JSONCookies
module.exports.signedCookie = signedCookie
module.exports.signedCookies = signedCookies

/**
 * Parse Cookie header and populate `req.cookies`
 * with an object keyed by the cookie names.
 *
 * @param {string|array} [secret] A string (or array of strings) representing cookie signing secret(s).
 * @param {Object} [options]
 * @return {Function}
 * @public
 */

function cookieParser (secret, options) {
  var secrets = !secret || Array.isArray(secret)
    ? (secret || [])
    : [secret]

  return function cookieParser (req, res, next) {
    if (req.cookies) {
      return next()
    }

    var cookies = req.headers.cookie

    req.secret = secrets[0]
    req.cookies = Object.create(null)
    req.signedCookies = Object.create(null)

    // no cookies
    if (!cookies) {
      return next()
    }

    req.cookies = cookie.parse(cookies, options)

    // parse signed cookies
    if (secrets.length !== 0) {
      req.signedCookies = signedCookies(req.cookies, secrets)
      req.signedCookies = JSONCookies(req.signedCookies)
    }

    // parse JSON cookies
    req.cookies = JSONCookies(req.cookies)

    next()
  }
}

/**
 * Parse JSON cookie string.
 *
 * @param {String} str
 * @return {Object} Parsed object or undefined if not json cookie
 * @public
 */

function JSONCookie (str) {
  if (typeof str !== 'string' || str.substr(0, 2) !== 'j:') {
    return undefined
  }

  try {
    return JSON.parse(str.slice(2))
  } catch (err) {
    return undefined
  }
}

/**
 * Parse JSON cookies.
 *
 * @param {Object} obj
 * @return {Object}
 * @public
 */

function JSONCookies (obj) {
  var cookies = Object.keys(obj)
  var key
  var val

  for (var i = 0; i < cookies.length; i++) {
    key = cookies[i]
    val = JSONCookie(obj[key])

    if (val) {
      obj[key] = val
    }
  }

  return obj
}

/**
 * Parse a signed cookie string, return the decoded value.
 *
 * @param {String} str signed cookie string
 * @param {string|array} secret
 * @return {String} decoded value
 * @public
 */

function signedCookie (str, secret) {
  if (typeof str !== 'string') {
    return undefined
  }

  if (str.substr(0, 2) !== 's:') {
    return str
  }

  var secrets = !secret || Array.isArray(secret)
    ? (secret || [])
    : [secret]

  for (var i = 0; i < secrets.length; i++) {
    var val = signature.unsign(str.slice(2), secrets[i])

    if (val !== false) {
      return val
    }
  }

  return false
}

/**
 * Parse signed cookies, returning an object containing the decoded key/value
 * pairs, while removing the signed key from obj.
 *
 * @param {Object} obj
 * @param {string|array} secret
 * @return {Object}
 * @public
 */

function signedCookies (obj, secret) {
  var cookies = Object.keys(obj)
  var dec
  var key
  var ret = Object.create(null)
  var val

  for (var i = 0; i < cookies.length; i++) {
    key = cookies[i]
    val = obj[key]
    dec = signedCookie(val, secret)

    if (val !== dec) {
      ret[key] = dec
      delete obj[key]
    }
  }

  return ret
}


/***/ }),

/***/ "../../node_modules/cookie-signature/index.js":
/*!****************************************************!*\
  !*** ../../node_modules/cookie-signature/index.js ***!
  \****************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

/**
 * Module dependencies.
 */

var crypto = __webpack_require__(/*! crypto */ "crypto");

/**
 * Sign the given `val` with `secret`.
 *
 * @param {String} val
 * @param {String} secret
 * @return {String}
 * @api private
 */

exports.sign = function(val, secret){
  if ('string' != typeof val) throw new TypeError("Cookie value must be provided as a string.");
  if ('string' != typeof secret) throw new TypeError("Secret string must be provided.");
  return val + '.' + crypto
    .createHmac('sha256', secret)
    .update(val)
    .digest('base64')
    .replace(/\=+$/, '');
};

/**
 * Unsign and decode the given `val` with `secret`,
 * returning `false` if the signature is invalid.
 *
 * @param {String} val
 * @param {String} secret
 * @return {String|Boolean}
 * @api private
 */

exports.unsign = function(val, secret){
  if ('string' != typeof val) throw new TypeError("Signed cookie string must be provided.");
  if ('string' != typeof secret) throw new TypeError("Secret string must be provided.");
  var str = val.slice(0, val.lastIndexOf('.'))
    , mac = exports.sign(str, secret);
  
  return sha1(mac) == sha1(val) ? str : false;
};

/**
 * Private
 */

function sha1(str){
  return crypto.createHash('sha1').update(str).digest('hex');
}


/***/ }),

/***/ "../../node_modules/cookie/index.js":
/*!******************************************!*\
  !*** ../../node_modules/cookie/index.js ***!
  \******************************************/
/***/ ((__unused_webpack_module, exports) => {

"use strict";
/*!
 * cookie
 * Copyright(c) 2012-2014 Roman Shtylman
 * Copyright(c) 2015 Douglas Christopher Wilson
 * MIT Licensed
 */



/**
 * Module exports.
 * @public
 */

exports.parse = parse;
exports.serialize = serialize;

/**
 * Module variables.
 * @private
 */

var __toString = Object.prototype.toString
var __hasOwnProperty = Object.prototype.hasOwnProperty

/**
 * RegExp to match cookie-name in RFC 6265 sec 4.1.1
 * This refers out to the obsoleted definition of token in RFC 2616 sec 2.2
 * which has been replaced by the token definition in RFC 7230 appendix B.
 *
 * cookie-name       = token
 * token             = 1*tchar
 * tchar             = "!" / "#" / "$" / "%" / "&" / "'" /
 *                     "*" / "+" / "-" / "." / "^" / "_" /
 *                     "`" / "|" / "~" / DIGIT / ALPHA
 */

var cookieNameRegExp = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/**
 * RegExp to match cookie-value in RFC 6265 sec 4.1.1
 *
 * cookie-value      = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
 * cookie-octet      = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
 *                     ; US-ASCII characters excluding CTLs,
 *                     ; whitespace DQUOTE, comma, semicolon,
 *                     ; and backslash
 */

var cookieValueRegExp = /^("?)[\u0021\u0023-\u002B\u002D-\u003A\u003C-\u005B\u005D-\u007E]*\1$/;

/**
 * RegExp to match domain-value in RFC 6265 sec 4.1.1
 *
 * domain-value      = <subdomain>
 *                     ; defined in [RFC1034], Section 3.5, as
 *                     ; enhanced by [RFC1123], Section 2.1
 * <subdomain>       = <label> | <subdomain> "." <label>
 * <label>           = <let-dig> [ [ <ldh-str> ] <let-dig> ]
 *                     Labels must be 63 characters or less.
 *                     'let-dig' not 'letter' in the first char, per RFC1123
 * <ldh-str>         = <let-dig-hyp> | <let-dig-hyp> <ldh-str>
 * <let-dig-hyp>     = <let-dig> | "-"
 * <let-dig>         = <letter> | <digit>
 * <letter>          = any one of the 52 alphabetic characters A through Z in
 *                     upper case and a through z in lower case
 * <digit>           = any one of the ten digits 0 through 9
 *
 * Keep support for leading dot: https://github.com/jshttp/cookie/issues/173
 *
 * > (Note that a leading %x2E ("."), if present, is ignored even though that
 * character is not permitted, but a trailing %x2E ("."), if present, will
 * cause the user agent to ignore the attribute.)
 */

var domainValueRegExp = /^([.]?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;

/**
 * RegExp to match path-value in RFC 6265 sec 4.1.1
 *
 * path-value        = <any CHAR except CTLs or ";">
 * CHAR              = %x01-7F
 *                     ; defined in RFC 5234 appendix B.1
 */

var pathValueRegExp = /^[\u0020-\u003A\u003D-\u007E]*$/;

/**
 * Parse a cookie header.
 *
 * Parse the given cookie header string into an object
 * The object has the various cookies as keys(names) => values
 *
 * @param {string} str
 * @param {object} [opt]
 * @return {object}
 * @public
 */

function parse(str, opt) {
  if (typeof str !== 'string') {
    throw new TypeError('argument str must be a string');
  }

  var obj = {};
  var len = str.length;
  // RFC 6265 sec 4.1.1, RFC 2616 2.2 defines a cookie name consists of one char minimum, plus '='.
  if (len < 2) return obj;

  var dec = (opt && opt.decode) || decode;
  var index = 0;
  var eqIdx = 0;
  var endIdx = 0;

  do {
    eqIdx = str.indexOf('=', index);
    if (eqIdx === -1) break; // No more cookie pairs.

    endIdx = str.indexOf(';', index);

    if (endIdx === -1) {
      endIdx = len;
    } else if (eqIdx > endIdx) {
      // backtrack on prior semicolon
      index = str.lastIndexOf(';', eqIdx - 1) + 1;
      continue;
    }

    var keyStartIdx = startIndex(str, index, eqIdx);
    var keyEndIdx = endIndex(str, eqIdx, keyStartIdx);
    var key = str.slice(keyStartIdx, keyEndIdx);

    // only assign once
    if (!__hasOwnProperty.call(obj, key)) {
      var valStartIdx = startIndex(str, eqIdx + 1, endIdx);
      var valEndIdx = endIndex(str, endIdx, valStartIdx);

      if (str.charCodeAt(valStartIdx) === 0x22 /* " */ && str.charCodeAt(valEndIdx - 1) === 0x22 /* " */) {
        valStartIdx++;
        valEndIdx--;
      }

      var val = str.slice(valStartIdx, valEndIdx);
      obj[key] = tryDecode(val, dec);
    }

    index = endIdx + 1
  } while (index < len);

  return obj;
}

function startIndex(str, index, max) {
  do {
    var code = str.charCodeAt(index);
    if (code !== 0x20 /*   */ && code !== 0x09 /* \t */) return index;
  } while (++index < max);
  return max;
}

function endIndex(str, index, min) {
  while (index > min) {
    var code = str.charCodeAt(--index);
    if (code !== 0x20 /*   */ && code !== 0x09 /* \t */) return index + 1;
  }
  return min;
}

/**
 * Serialize data into a cookie header.
 *
 * Serialize a name value pair into a cookie string suitable for
 * http headers. An optional options object specifies cookie parameters.
 *
 * serialize('foo', 'bar', { httpOnly: true })
 *   => "foo=bar; httpOnly"
 *
 * @param {string} name
 * @param {string} val
 * @param {object} [opt]
 * @return {string}
 * @public
 */

function serialize(name, val, opt) {
  var enc = (opt && opt.encode) || encodeURIComponent;

  if (typeof enc !== 'function') {
    throw new TypeError('option encode is invalid');
  }

  if (!cookieNameRegExp.test(name)) {
    throw new TypeError('argument name is invalid');
  }

  var value = enc(val);

  if (!cookieValueRegExp.test(value)) {
    throw new TypeError('argument val is invalid');
  }

  var str = name + '=' + value;
  if (!opt) return str;

  if (null != opt.maxAge) {
    var maxAge = Math.floor(opt.maxAge);

    if (!isFinite(maxAge)) {
      throw new TypeError('option maxAge is invalid')
    }

    str += '; Max-Age=' + maxAge;
  }

  if (opt.domain) {
    if (!domainValueRegExp.test(opt.domain)) {
      throw new TypeError('option domain is invalid');
    }

    str += '; Domain=' + opt.domain;
  }

  if (opt.path) {
    if (!pathValueRegExp.test(opt.path)) {
      throw new TypeError('option path is invalid');
    }

    str += '; Path=' + opt.path;
  }

  if (opt.expires) {
    var expires = opt.expires

    if (!isDate(expires) || isNaN(expires.valueOf())) {
      throw new TypeError('option expires is invalid');
    }

    str += '; Expires=' + expires.toUTCString()
  }

  if (opt.httpOnly) {
    str += '; HttpOnly';
  }

  if (opt.secure) {
    str += '; Secure';
  }

  if (opt.partitioned) {
    str += '; Partitioned'
  }

  if (opt.priority) {
    var priority = typeof opt.priority === 'string'
      ? opt.priority.toLowerCase() : opt.priority;

    switch (priority) {
      case 'low':
        str += '; Priority=Low'
        break
      case 'medium':
        str += '; Priority=Medium'
        break
      case 'high':
        str += '; Priority=High'
        break
      default:
        throw new TypeError('option priority is invalid')
    }
  }

  if (opt.sameSite) {
    var sameSite = typeof opt.sameSite === 'string'
      ? opt.sameSite.toLowerCase() : opt.sameSite;

    switch (sameSite) {
      case true:
        str += '; SameSite=Strict';
        break;
      case 'lax':
        str += '; SameSite=Lax';
        break;
      case 'strict':
        str += '; SameSite=Strict';
        break;
      case 'none':
        str += '; SameSite=None';
        break;
      default:
        throw new TypeError('option sameSite is invalid');
    }
  }

  return str;
}

/**
 * URL-decode string value. Optimized to skip native call when no %.
 *
 * @param {string} str
 * @returns {string}
 */

function decode (str) {
  return str.indexOf('%') !== -1
    ? decodeURIComponent(str)
    : str
}

/**
 * Determine if value is a Date.
 *
 * @param {*} val
 * @private
 */

function isDate (val) {
  return __toString.call(val) === '[object Date]';
}

/**
 * Try decoding a string using a decoding function.
 *
 * @param {string} str
 * @param {function} decode
 * @private
 */

function tryDecode(str, decode) {
  try {
    return decode(str);
  } catch (e) {
    return str;
  }
}


/***/ }),

/***/ "../../node_modules/cors/lib/index.js":
/*!********************************************!*\
  !*** ../../node_modules/cors/lib/index.js ***!
  \********************************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

(function () {

  'use strict';

  var assign = __webpack_require__(/*! object-assign */ "../../node_modules/object-assign/index.js");
  var vary = __webpack_require__(/*! vary */ "../../node_modules/vary/index.js");

  var defaults = {
    origin: '*',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    preflightContinue: false,
    optionsSuccessStatus: 204
  };

  function isString(s) {
    return typeof s === 'string' || s instanceof String;
  }

  function isOriginAllowed(origin, allowedOrigin) {
    if (Array.isArray(allowedOrigin)) {
      for (var i = 0; i < allowedOrigin.length; ++i) {
        if (isOriginAllowed(origin, allowedOrigin[i])) {
          return true;
        }
      }
      return false;
    } else if (isString(allowedOrigin)) {
      return origin === allowedOrigin;
    } else if (allowedOrigin instanceof RegExp) {
      return allowedOrigin.test(origin);
    } else {
      return !!allowedOrigin;
    }
  }

  function configureOrigin(options, req) {
    var requestOrigin = req.headers.origin,
      headers = [],
      isAllowed;

    if (!options.origin || options.origin === '*') {
      // allow any origin
      headers.push([{
        key: 'Access-Control-Allow-Origin',
        value: '*'
      }]);
    } else if (isString(options.origin)) {
      // fixed origin
      headers.push([{
        key: 'Access-Control-Allow-Origin',
        value: options.origin
      }]);
      headers.push([{
        key: 'Vary',
        value: 'Origin'
      }]);
    } else {
      isAllowed = isOriginAllowed(requestOrigin, options.origin);
      // reflect origin
      headers.push([{
        key: 'Access-Control-Allow-Origin',
        value: isAllowed ? requestOrigin : false
      }]);
      headers.push([{
        key: 'Vary',
        value: 'Origin'
      }]);
    }

    return headers;
  }

  function configureMethods(options) {
    var methods = options.methods;
    if (methods.join) {
      methods = options.methods.join(','); // .methods is an array, so turn it into a string
    }
    return {
      key: 'Access-Control-Allow-Methods',
      value: methods
    };
  }

  function configureCredentials(options) {
    if (options.credentials === true) {
      return {
        key: 'Access-Control-Allow-Credentials',
        value: 'true'
      };
    }
    return null;
  }

  function configureAllowedHeaders(options, req) {
    var allowedHeaders = options.allowedHeaders || options.headers;
    var headers = [];

    if (!allowedHeaders) {
      allowedHeaders = req.headers['access-control-request-headers']; // .headers wasn't specified, so reflect the request headers
      headers.push([{
        key: 'Vary',
        value: 'Access-Control-Request-Headers'
      }]);
    } else if (allowedHeaders.join) {
      allowedHeaders = allowedHeaders.join(','); // .headers is an array, so turn it into a string
    }
    if (allowedHeaders && allowedHeaders.length) {
      headers.push([{
        key: 'Access-Control-Allow-Headers',
        value: allowedHeaders
      }]);
    }

    return headers;
  }

  function configureExposedHeaders(options) {
    var headers = options.exposedHeaders;
    if (!headers) {
      return null;
    } else if (headers.join) {
      headers = headers.join(','); // .headers is an array, so turn it into a string
    }
    if (headers && headers.length) {
      return {
        key: 'Access-Control-Expose-Headers',
        value: headers
      };
    }
    return null;
  }

  function configureMaxAge(options) {
    var maxAge = (typeof options.maxAge === 'number' || options.maxAge) && options.maxAge.toString()
    if (maxAge && maxAge.length) {
      return {
        key: 'Access-Control-Max-Age',
        value: maxAge
      };
    }
    return null;
  }

  function applyHeaders(headers, res) {
    for (var i = 0, n = headers.length; i < n; i++) {
      var header = headers[i];
      if (header) {
        if (Array.isArray(header)) {
          applyHeaders(header, res);
        } else if (header.key === 'Vary' && header.value) {
          vary(res, header.value);
        } else if (header.value) {
          res.setHeader(header.key, header.value);
        }
      }
    }
  }

  function cors(options, req, res, next) {
    var headers = [],
      method = req.method && req.method.toUpperCase && req.method.toUpperCase();

    if (method === 'OPTIONS') {
      // preflight
      headers.push(configureOrigin(options, req));
      headers.push(configureCredentials(options, req));
      headers.push(configureMethods(options, req));
      headers.push(configureAllowedHeaders(options, req));
      headers.push(configureMaxAge(options, req));
      headers.push(configureExposedHeaders(options, req));
      applyHeaders(headers, res);

      if (options.preflightContinue) {
        next();
      } else {
        // Safari (and potentially other browsers) need content-length 0,
        //   for 204 or they just hang waiting for a body
        res.statusCode = options.optionsSuccessStatus;
        res.setHeader('Content-Length', '0');
        res.end();
      }
    } else {
      // actual response
      headers.push(configureOrigin(options, req));
      headers.push(configureCredentials(options, req));
      headers.push(configureExposedHeaders(options, req));
      applyHeaders(headers, res);
      next();
    }
  }

  function middlewareWrapper(o) {
    // if options are static (either via defaults or custom options passed in), wrap in a function
    var optionsCallback = null;
    if (typeof o === 'function') {
      optionsCallback = o;
    } else {
      optionsCallback = function (req, cb) {
        cb(null, o);
      };
    }

    return function corsMiddleware(req, res, next) {
      optionsCallback(req, function (err, options) {
        if (err) {
          next(err);
        } else {
          var corsOptions = assign({}, defaults, options);
          var originCallback = null;
          if (corsOptions.origin && typeof corsOptions.origin === 'function') {
            originCallback = corsOptions.origin;
          } else if (corsOptions.origin) {
            originCallback = function (origin, cb) {
              cb(null, corsOptions.origin);
            };
          }

          if (originCallback) {
            originCallback(req.headers.origin, function (err2, origin) {
              if (err2 || !origin) {
                next(err2);
              } else {
                corsOptions.origin = origin;
                cors(corsOptions, req, res, next);
              }
            });
          } else {
            next();
          }
        }
      });
    };
  }

  // can pass either an options hash, an options delegate, or nothing
  module.exports = middlewareWrapper;

}());


/***/ }),

/***/ "../../node_modules/object-assign/index.js":
/*!*************************************************!*\
  !*** ../../node_modules/object-assign/index.js ***!
  \*************************************************/
/***/ ((module) => {

"use strict";
/*
object-assign
(c) Sindre Sorhus
@license MIT
*/


/* eslint-disable no-unused-vars */
var getOwnPropertySymbols = Object.getOwnPropertySymbols;
var hasOwnProperty = Object.prototype.hasOwnProperty;
var propIsEnumerable = Object.prototype.propertyIsEnumerable;

function toObject(val) {
	if (val === null || val === undefined) {
		throw new TypeError('Object.assign cannot be called with null or undefined');
	}

	return Object(val);
}

function shouldUseNative() {
	try {
		if (!Object.assign) {
			return false;
		}

		// Detect buggy property enumeration order in older V8 versions.

		// https://bugs.chromium.org/p/v8/issues/detail?id=4118
		var test1 = new String('abc');  // eslint-disable-line no-new-wrappers
		test1[5] = 'de';
		if (Object.getOwnPropertyNames(test1)[0] === '5') {
			return false;
		}

		// https://bugs.chromium.org/p/v8/issues/detail?id=3056
		var test2 = {};
		for (var i = 0; i < 10; i++) {
			test2['_' + String.fromCharCode(i)] = i;
		}
		var order2 = Object.getOwnPropertyNames(test2).map(function (n) {
			return test2[n];
		});
		if (order2.join('') !== '0123456789') {
			return false;
		}

		// https://bugs.chromium.org/p/v8/issues/detail?id=3056
		var test3 = {};
		'abcdefghijklmnopqrst'.split('').forEach(function (letter) {
			test3[letter] = letter;
		});
		if (Object.keys(Object.assign({}, test3)).join('') !==
				'abcdefghijklmnopqrst') {
			return false;
		}

		return true;
	} catch (err) {
		// We don't expect any of the above to throw, but better to be safe.
		return false;
	}
}

module.exports = shouldUseNative() ? Object.assign : function (target, source) {
	var from;
	var to = toObject(target);
	var symbols;

	for (var s = 1; s < arguments.length; s++) {
		from = Object(arguments[s]);

		for (var key in from) {
			if (hasOwnProperty.call(from, key)) {
				to[key] = from[key];
			}
		}

		if (getOwnPropertySymbols) {
			symbols = getOwnPropertySymbols(from);
			for (var i = 0; i < symbols.length; i++) {
				if (propIsEnumerable.call(from, symbols[i])) {
					to[symbols[i]] = from[symbols[i]];
				}
			}
		}
	}

	return to;
};


/***/ }),

/***/ "../../node_modules/vary/index.js":
/*!****************************************!*\
  !*** ../../node_modules/vary/index.js ***!
  \****************************************/
/***/ ((module) => {

"use strict";
/*!
 * vary
 * Copyright(c) 2014-2017 Douglas Christopher Wilson
 * MIT Licensed
 */



/**
 * Module exports.
 */

module.exports = vary
module.exports.append = append

/**
 * RegExp to match field-name in RFC 7230 sec 3.2
 *
 * field-name    = token
 * token         = 1*tchar
 * tchar         = "!" / "#" / "$" / "%" / "&" / "'" / "*"
 *               / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
 *               / DIGIT / ALPHA
 *               ; any VCHAR, except delimiters
 */

var FIELD_NAME_REGEXP = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/

/**
 * Append a field to a vary header.
 *
 * @param {String} header
 * @param {String|Array} field
 * @return {String}
 * @public
 */

function append (header, field) {
  if (typeof header !== 'string') {
    throw new TypeError('header argument is required')
  }

  if (!field) {
    throw new TypeError('field argument is required')
  }

  // get fields array
  var fields = !Array.isArray(field)
    ? parse(String(field))
    : field

  // assert on invalid field names
  for (var j = 0; j < fields.length; j++) {
    if (!FIELD_NAME_REGEXP.test(fields[j])) {
      throw new TypeError('field argument contains an invalid header name')
    }
  }

  // existing, unspecified vary
  if (header === '*') {
    return header
  }

  // enumerate current values
  var val = header
  var vals = parse(header.toLowerCase())

  // unspecified vary
  if (fields.indexOf('*') !== -1 || vals.indexOf('*') !== -1) {
    return '*'
  }

  for (var i = 0; i < fields.length; i++) {
    var fld = fields[i].toLowerCase()

    // append value (case-preserving)
    if (vals.indexOf(fld) === -1) {
      vals.push(fld)
      val = val
        ? val + ', ' + fields[i]
        : fields[i]
    }
  }

  return val
}

/**
 * Parse a vary header into an array.
 *
 * @param {String} header
 * @return {Array}
 * @private
 */

function parse (header) {
  var end = 0
  var list = []
  var start = 0

  // gather tokens
  for (var i = 0, len = header.length; i < len; i++) {
    switch (header.charCodeAt(i)) {
      case 0x20: /*   */
        if (start === end) {
          start = end = i + 1
        }
        break
      case 0x2c: /* , */
        list.push(header.substring(start, end))
        start = end = i + 1
        break
      default:
        end = i + 1
        break
    }
  }

  // final token
  list.push(header.substring(start, end))

  return list
}

/**
 * Mark that a request is varied on a header field.
 *
 * @param {Object} res
 * @param {String|Array} field
 * @public
 */

function vary (res, field) {
  if (!res || !res.getHeader || !res.setHeader) {
    // quack quack
    throw new TypeError('res argument is required')
  }

  // get existing header
  var val = res.getHeader('Vary') || ''
  var header = Array.isArray(val)
    ? val.join(', ')
    : String(val)

  // set new header
  if ((val = append(header, field))) {
    res.setHeader('Vary', val)
  }
}


/***/ }),

/***/ "../shared/src/constants.ts":
/*!**********************************!*\
  !*** ../shared/src/constants.ts ***!
  \**********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   LOG_1_ID: () => (/* binding */ LOG_1_ID),
/* harmony export */   LOG_2_ID: () => (/* binding */ LOG_2_ID),
/* harmony export */   PROJECT_ID: () => (/* binding */ PROJECT_ID)
/* harmony export */ });
const PROJECT_ID = '987zyx';
const LOG_1_ID = 'abc123';
const LOG_2_ID = 'def456';


/***/ }),

/***/ "../shared/src/index.ts":
/*!******************************!*\
  !*** ../shared/src/index.ts ***!
  \******************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   HttpStatusCode: () => (/* reexport safe */ _types__WEBPACK_IMPORTED_MODULE_1__.HttpStatusCode),
/* harmony export */   LOG_1_ID: () => (/* reexport safe */ _constants__WEBPACK_IMPORTED_MODULE_0__.LOG_1_ID),
/* harmony export */   LOG_2_ID: () => (/* reexport safe */ _constants__WEBPACK_IMPORTED_MODULE_0__.LOG_2_ID),
/* harmony export */   PROJECT_ID: () => (/* reexport safe */ _constants__WEBPACK_IMPORTED_MODULE_0__.PROJECT_ID)
/* harmony export */ });
/* harmony import */ var _constants__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./constants */ "../shared/src/constants.ts");
/* harmony import */ var _types__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./types */ "../shared/src/types.ts");




/***/ }),

/***/ "../shared/src/types.ts":
/*!******************************!*\
  !*** ../shared/src/types.ts ***!
  \******************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   HttpStatusCode: () => (/* binding */ HttpStatusCode)
/* harmony export */ });
var HttpStatusCode;
(function (HttpStatusCode) {
    HttpStatusCode[HttpStatusCode["OK"] = 200] = "OK";
    HttpStatusCode[HttpStatusCode["CREATED"] = 201] = "CREATED";
    HttpStatusCode[HttpStatusCode["TEMPORARY_REDIRECT"] = 302] = "TEMPORARY_REDIRECT";
    HttpStatusCode[HttpStatusCode["INVALID_REQUEST"] = 400] = "INVALID_REQUEST";
    HttpStatusCode[HttpStatusCode["INVALID_CREDENTIALS"] = 401] = "INVALID_CREDENTIALS";
    HttpStatusCode[HttpStatusCode["UNAUTHORIZED_REQUEST"] = 403] = "UNAUTHORIZED_REQUEST";
    HttpStatusCode[HttpStatusCode["NOT_FOUND"] = 404] = "NOT_FOUND";
    HttpStatusCode[HttpStatusCode["CONFLICT"] = 409] = "CONFLICT";
    HttpStatusCode[HttpStatusCode["MISSING_QUERY_PARAM"] = 422] = "MISSING_QUERY_PARAM";
    HttpStatusCode[HttpStatusCode["MISSING_DATA"] = 422] = "MISSING_DATA";
    HttpStatusCode[HttpStatusCode["INVALID_DATA"] = 422] = "INVALID_DATA";
    HttpStatusCode[HttpStatusCode["SERVER_ERROR"] = 500] = "SERVER_ERROR";
    HttpStatusCode[HttpStatusCode["UNIMPLEMENTED_ERROR"] = 501] = "UNIMPLEMENTED_ERROR";
})(HttpStatusCode || (HttpStatusCode = {}));


/***/ }),

/***/ "./src/application/mappers/LogEntriesApiMapper.ts":
/*!********************************************************!*\
  !*** ./src/application/mappers/LogEntriesApiMapper.ts ***!
  \********************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   LogEntriesApiMapper: () => (/* binding */ LogEntriesApiMapper)
/* harmony export */ });
/* harmony import */ var _domain_entities_LogEntry__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../domain/entities/LogEntry */ "./src/domain/entities/LogEntry.ts");

class LogEntriesApiMapper {
    toResponse(logEntry) {
        return {
            id: logEntry.id.toString(),
            logId: logEntry.logId,
            logDate: logEntry.logDate,
            logValue: logEntry.logValue,
        };
    }
    fromRequest(logId, createLogEntry) {
        return _domain_entities_LogEntry__WEBPACK_IMPORTED_MODULE_0__.LogEntry.create({
            logId,
            logDate: new Date(createLogEntry.logDate),
            logValue: createLogEntry.logValue,
        });
    }
}


/***/ }),

/***/ "./src/application/services/LogEntriesService.ts":
/*!*******************************************************!*\
  !*** ./src/application/services/LogEntriesService.ts ***!
  \*******************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   LogEntriesService: () => (/* binding */ LogEntriesService)
/* harmony export */ });
/* harmony import */ var _persistence_repositories_LogEntriesQueryRepository__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../persistence/repositories/LogEntriesQueryRepository */ "./src/persistence/repositories/LogEntriesQueryRepository.ts");
/* harmony import */ var _persistence_repositories_LogEntriesRepository__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../persistence/repositories/LogEntriesRepository */ "./src/persistence/repositories/LogEntriesRepository.ts");
/* harmony import */ var _mappers_LogEntriesApiMapper__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../mappers/LogEntriesApiMapper */ "./src/application/mappers/LogEntriesApiMapper.ts");



class LogEntriesService {
    getLogEntries(logId) {
        const logEntryRepository = new _persistence_repositories_LogEntriesQueryRepository__WEBPACK_IMPORTED_MODULE_0__.LogEntriesQueryRepository();
        return logEntryRepository.findLogEntries(logId);
    }
    async createLogEntry(logId, createLogEntry) {
        const mapper = new _mappers_LogEntriesApiMapper__WEBPACK_IMPORTED_MODULE_2__.LogEntriesApiMapper();
        const logEntry = mapper.fromRequest(logId, createLogEntry);
        const repository = new _persistence_repositories_LogEntriesRepository__WEBPACK_IMPORTED_MODULE_1__.LogEntriesRepository(logId);
        const newEntry = await repository.createLogEntry(logEntry);
        return mapper.toResponse(newEntry);
    }
    async deleteLogEntry(logId, logEntryId) {
        const logEntryRepository = new _persistence_repositories_LogEntriesRepository__WEBPACK_IMPORTED_MODULE_1__.LogEntriesRepository(logId);
        const logEntry = await logEntryRepository.findById(logEntryId);
        return logEntryRepository.destroyLogEntry(logEntry);
    }
}


/***/ }),

/***/ "./src/domain/entities/Entity.ts":
/*!***************************************!*\
  !*** ./src/domain/entities/Entity.ts ***!
  \***************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Entity: () => (/* binding */ Entity)
/* harmony export */ });
/* harmony import */ var _Uuid__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./Uuid */ "./src/domain/entities/Uuid.ts");

class Entity {
    constructor(props, id) {
        this.props = props;
        this._id = id || _Uuid__WEBPACK_IMPORTED_MODULE_0__.Uuid.create();
    }
    get id() {
        return this._id;
    }
}


/***/ }),

/***/ "./src/domain/entities/LogEntry.ts":
/*!*****************************************!*\
  !*** ./src/domain/entities/LogEntry.ts ***!
  \*****************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   LogEntry: () => (/* binding */ LogEntry)
/* harmony export */ });
/* harmony import */ var _shared_errors__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../shared/errors */ "./src/shared/errors.ts");
/* harmony import */ var _Entity__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./Entity */ "./src/domain/entities/Entity.ts");
/* harmony import */ var _Uuid__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./Uuid */ "./src/domain/entities/Uuid.ts");



class LogEntry extends _Entity__WEBPACK_IMPORTED_MODULE_1__.Entity {
    static createFromPersistence(props, id) {
        return new LogEntry(props, _Uuid__WEBPACK_IMPORTED_MODULE_2__.Uuid.create(id));
    }
    static create(createLogEntryProps) {
        if (!this.isValid(createLogEntryProps)) {
            throw new _shared_errors__WEBPACK_IMPORTED_MODULE_0__.ValidationError('Cannot create log entry. Props are not valid.');
        }
        return new LogEntry(createLogEntryProps);
    }
    static isValid(createLogEntryProps) {
        return typeof createLogEntryProps.logValue === 'number';
    }
    get logDate() {
        return this.props.logDate;
    }
    get logValue() {
        return this.props.logValue;
    }
    get logId() {
        return this.props.logId;
    }
}


/***/ }),

/***/ "./src/domain/entities/Uuid.ts":
/*!*************************************!*\
  !*** ./src/domain/entities/Uuid.ts ***!
  \*************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Uuid: () => (/* binding */ Uuid)
/* harmony export */ });
/* harmony import */ var crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! crypto */ "crypto");
/* harmony import */ var crypto__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(crypto__WEBPACK_IMPORTED_MODULE_0__);

class Uuid {
    constructor(id) {
        this._id = id;
    }
    get value() {
        return this._id;
    }
    toString() {
        return this.value;
    }
    equals(id) {
        if (id instanceof Uuid) {
            return id.value === this.value;
        }
        if (typeof id === 'string') {
            return id === this._id;
        }
        return false;
    }
    static create(givenId) {
        if (!givenId)
            return new Uuid(crypto__WEBPACK_IMPORTED_MODULE_0___default().randomUUID());
        // we don't validate that it's a proper uuid so we can support composite IDs
        return new Uuid(givenId);
    }
    static isValid(givenId) {
        return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(givenId);
    }
}


/***/ }),

/***/ "./src/persistence/mappers/LogEntriesPersistenceMapper.ts":
/*!****************************************************************!*\
  !*** ./src/persistence/mappers/LogEntriesPersistenceMapper.ts ***!
  \****************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   LogEntriesPersistenceMapper: () => (/* binding */ LogEntriesPersistenceMapper)
/* harmony export */ });
/* harmony import */ var _domain_entities_LogEntry__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../domain/entities/LogEntry */ "./src/domain/entities/LogEntry.ts");

class LogEntriesPersistenceMapper {
    static toPersistence(logEntry) {
        return {
            id: logEntry.id.toString(),
            logId: logEntry.logId,
            logDate: logEntry.logDate,
            logValue: logEntry.logValue,
        };
    }
    static fromPersistence(logEntriesRecord) {
        return _domain_entities_LogEntry__WEBPACK_IMPORTED_MODULE_0__.LogEntry.createFromPersistence(logEntriesRecord, logEntriesRecord.id);
    }
}


/***/ }),

/***/ "./src/persistence/repositories/LogEntriesQueryRepository.ts":
/*!*******************************************************************!*\
  !*** ./src/persistence/repositories/LogEntriesQueryRepository.ts ***!
  \*******************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   LogEntriesQueryRepository: () => (/* binding */ LogEntriesQueryRepository)
/* harmony export */ });
/* harmony import */ var _shared_database__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../shared/database */ "./src/shared/database.ts");

class LogEntriesQueryRepository {
    async findLogEntries(logId) {
        return _shared_database__WEBPACK_IMPORTED_MODULE_0__.Database.getAllLogEntries(logId);
    }
}


/***/ }),

/***/ "./src/persistence/repositories/LogEntriesRepository.ts":
/*!**************************************************************!*\
  !*** ./src/persistence/repositories/LogEntriesRepository.ts ***!
  \**************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   LogEntriesRepository: () => (/* binding */ LogEntriesRepository)
/* harmony export */ });
/* harmony import */ var _shared_database__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../shared/database */ "./src/shared/database.ts");
/* harmony import */ var _shared_errors__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../shared/errors */ "./src/shared/errors.ts");
/* harmony import */ var _mappers_LogEntriesPersistenceMapper__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../mappers/LogEntriesPersistenceMapper */ "./src/persistence/mappers/LogEntriesPersistenceMapper.ts");



class LogEntriesRepository {
    constructor(logId) {
        this.logId = logId;
    }
    async createLogEntry(logEntry) {
        const dto = _mappers_LogEntriesPersistenceMapper__WEBPACK_IMPORTED_MODULE_2__.LogEntriesPersistenceMapper.toPersistence(logEntry);
        await _shared_database__WEBPACK_IMPORTED_MODULE_0__.Database.createLogEntry(dto);
        return logEntry;
    }
    async findById(logEntryId) {
        const record = await _shared_database__WEBPACK_IMPORTED_MODULE_0__.Database.findById(logEntryId);
        if (!record) {
            throw new _shared_errors__WEBPACK_IMPORTED_MODULE_1__.RecordNotFoundError(`log entry not found for id: ${logEntryId}`);
        }
        return _mappers_LogEntriesPersistenceMapper__WEBPACK_IMPORTED_MODULE_2__.LogEntriesPersistenceMapper.fromPersistence(record);
    }
    async destroyLogEntry(logEntry) {
        await _shared_database__WEBPACK_IMPORTED_MODULE_0__.Database.deleteLogEntry(logEntry.id.value);
        return logEntry.id.value;
    }
}


/***/ }),

/***/ "./src/presentation/controllers/logEntriesController.ts":
/*!**************************************************************!*\
  !*** ./src/presentation/controllers/logEntriesController.ts ***!
  \**************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   logEntriesController: () => (/* binding */ logEntriesController)
/* harmony export */ });
/* harmony import */ var _mapistry_take_home_challenge_shared__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @mapistry/take-home-challenge-shared */ "../shared/src/index.ts");
/* harmony import */ var express__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! express */ "express");
/* harmony import */ var express__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(express__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var _application_services_LogEntriesService__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../application/services/LogEntriesService */ "./src/application/services/LogEntriesService.ts");
/* harmony import */ var _shared_errors__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../shared/errors */ "./src/shared/errors.ts");




const logEntriesController = (0,express__WEBPACK_IMPORTED_MODULE_1__.Router)();
logEntriesController.get('/logs/:logId/log-entries', async (req, res) => {
    const { logId } = req.params;
    const logEntryService = new _application_services_LogEntriesService__WEBPACK_IMPORTED_MODULE_2__.LogEntriesService();
    const logEntries = await logEntryService.getLogEntries(logId);
    res.json(logEntries);
});
logEntriesController.post('/logs/:logId/log-entries', async (req, res) => {
    const { logId } = req.params;
    const { logEntry } = req.body;
    const logEntryService = new _application_services_LogEntriesService__WEBPACK_IMPORTED_MODULE_2__.LogEntriesService();
    try {
        const logEntries = await logEntryService.createLogEntry(logId, logEntry);
        res.json(logEntries);
    }
    catch (e) {
        if (e instanceof _shared_errors__WEBPACK_IMPORTED_MODULE_3__.ValidationError) {
            res.status(_mapistry_take_home_challenge_shared__WEBPACK_IMPORTED_MODULE_0__.HttpStatusCode.INVALID_DATA);
            res.send(e.toString());
        }
        else {
            res.status(_mapistry_take_home_challenge_shared__WEBPACK_IMPORTED_MODULE_0__.HttpStatusCode.SERVER_ERROR);
            res.send();
        }
    }
});
logEntriesController.delete('/logs/:logId/log-entries/:logEntryId', async (req, res) => {
    const { logId, logEntryId } = req.params;
    const logEntryService = new _application_services_LogEntriesService__WEBPACK_IMPORTED_MODULE_2__.LogEntriesService();
    try {
        const logEntries = await logEntryService.deleteLogEntry(logId, logEntryId);
        res.json(logEntries);
    }
    catch (e) {
        if (e instanceof _shared_errors__WEBPACK_IMPORTED_MODULE_3__.RecordNotFoundError) {
            res.status(_mapistry_take_home_challenge_shared__WEBPACK_IMPORTED_MODULE_0__.HttpStatusCode.INVALID_DATA);
            res.send(e.toString());
        }
        else {
            res.status(_mapistry_take_home_challenge_shared__WEBPACK_IMPORTED_MODULE_0__.HttpStatusCode.SERVER_ERROR);
            res.send();
        }
        res.json();
    }
});


/***/ }),

/***/ "./src/shared/database.ts":
/*!********************************!*\
  !*** ./src/shared/database.ts ***!
  \********************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Database: () => (/* binding */ Database)
/* harmony export */ });
/* harmony import */ var _mapistry_take_home_challenge_shared__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @mapistry/take-home-challenge-shared */ "../shared/src/index.ts");
/* harmony import */ var crypto__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! crypto */ "crypto");
/* harmony import */ var crypto__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(crypto__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var fs__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! fs */ "fs");
/* harmony import */ var fs__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(fs__WEBPACK_IMPORTED_MODULE_2__);



const LOG_ENTRIES_TABLE_SEED = [
    {
        id: crypto__WEBPACK_IMPORTED_MODULE_1___default().randomUUID().toString(),
        logId: _mapistry_take_home_challenge_shared__WEBPACK_IMPORTED_MODULE_0__.LOG_1_ID,
        logDate: new Date('2024-01-01'),
        logValue: 5,
    },
    {
        id: crypto__WEBPACK_IMPORTED_MODULE_1___default().randomUUID().toString(),
        logId: _mapistry_take_home_challenge_shared__WEBPACK_IMPORTED_MODULE_0__.LOG_1_ID,
        logDate: new Date('2024-01-02'),
        logValue: 15,
    },
    {
        id: crypto__WEBPACK_IMPORTED_MODULE_1___default().randomUUID().toString(),
        logId: _mapistry_take_home_challenge_shared__WEBPACK_IMPORTED_MODULE_0__.LOG_1_ID,
        logDate: new Date('2024-01-03'),
        logValue: 23,
    },
    {
        id: crypto__WEBPACK_IMPORTED_MODULE_1___default().randomUUID().toString(),
        logId: _mapistry_take_home_challenge_shared__WEBPACK_IMPORTED_MODULE_0__.LOG_2_ID,
        logDate: new Date('2024-01-01'),
        logValue: 15,
    },
];
const FILE_NAME = 'database';
class Database {
    static async getAllLogEntries(logId) {
        let allEntries;
        try {
            await this.simulateDbSlowness();
            const db = await fs__WEBPACK_IMPORTED_MODULE_2___default().readFileSync(FILE_NAME, 'utf8');
            allEntries = JSON.parse(db);
        }
        catch (e) {
            await fs__WEBPACK_IMPORTED_MODULE_2___default().writeFileSync(FILE_NAME, JSON.stringify(LOG_ENTRIES_TABLE_SEED));
            allEntries = LOG_ENTRIES_TABLE_SEED;
        }
        return allEntries.filter((le) => le.logId === logId);
    }
    static async createLogEntry(entry) {
        await this.simulateDbSlowness();
        const db = await fs__WEBPACK_IMPORTED_MODULE_2___default().readFileSync(FILE_NAME, 'utf8');
        const allEntries = JSON.parse(db);
        allEntries.push(entry);
        await fs__WEBPACK_IMPORTED_MODULE_2___default().writeFileSync(FILE_NAME, JSON.stringify(allEntries));
        return entry;
    }
    static async findById(logEntryId) {
        await this.simulateDbSlowness();
        const db = await fs__WEBPACK_IMPORTED_MODULE_2___default().readFileSync(FILE_NAME, 'utf8');
        const allEntries = JSON.parse(db);
        return allEntries.find((le) => le.id === logEntryId) || null;
    }
    static async deleteLogEntry(logEntryId) {
        await this.simulateDbSlowness();
        const db = await fs__WEBPACK_IMPORTED_MODULE_2___default().readFileSync(FILE_NAME, 'utf8');
        const allEntries = JSON.parse(db);
        const index = allEntries.findIndex((le) => le.id === logEntryId);
        allEntries.splice(index, 1);
        await fs__WEBPACK_IMPORTED_MODULE_2___default().writeFileSync(FILE_NAME, JSON.stringify(allEntries));
        return logEntryId;
    }
    static simulateDbSlowness(ms = 1000) {
        return new Promise((resolve) => {
            setTimeout(resolve, ms);
        });
    }
}


/***/ }),

/***/ "./src/shared/errors.ts":
/*!******************************!*\
  !*** ./src/shared/errors.ts ***!
  \******************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   RecordNotFoundError: () => (/* binding */ RecordNotFoundError),
/* harmony export */   ValidationError: () => (/* binding */ ValidationError)
/* harmony export */ });
/* eslint-disable max-classes-per-file */
class RecordNotFoundError extends Error {
}
class ValidationError extends Error {
}


/***/ }),

/***/ "crypto":
/*!*************************!*\
  !*** external "crypto" ***!
  \*************************/
/***/ ((module) => {

"use strict";
module.exports = require("crypto");

/***/ }),

/***/ "express":
/*!**************************!*\
  !*** external "express" ***!
  \**************************/
/***/ ((module) => {

"use strict";
module.exports = require("express");

/***/ }),

/***/ "fs":
/*!*********************!*\
  !*** external "fs" ***!
  \*********************/
/***/ ((module) => {

"use strict";
module.exports = require("fs");

/***/ }),

/***/ "http":
/*!***********************!*\
  !*** external "http" ***!
  \***********************/
/***/ ((module) => {

"use strict";
module.exports = require("http");

/***/ }),

/***/ "morgan":
/*!*************************!*\
  !*** external "morgan" ***!
  \*************************/
/***/ ((module) => {

"use strict";
module.exports = require("morgan");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat get default export */
/******/ 	(() => {
/******/ 		// getDefaultExport function for compatibility with non-harmony modules
/******/ 		__webpack_require__.n = (module) => {
/******/ 			var getter = module && module.__esModule ?
/******/ 				() => (module['default']) :
/******/ 				() => (module);
/******/ 			__webpack_require__.d(getter, { a: getter });
/******/ 			return getter;
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/define property getters */
/******/ 	(() => {
/******/ 		// define getter functions for harmony exports
/******/ 		__webpack_require__.d = (exports, definition) => {
/******/ 			for(var key in definition) {
/******/ 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/make namespace object */
/******/ 	(() => {
/******/ 		// define __esModule on exports
/******/ 		__webpack_require__.r = (exports) => {
/******/ 			if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 				Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 			}
/******/ 			Object.defineProperty(exports, '__esModule', { value: true });
/******/ 		};
/******/ 	})();
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry needs to be wrapped in an IIFE because it needs to be in strict mode.
(() => {
"use strict";
/*!********************!*\
  !*** ./src/app.ts ***!
  \********************/
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   app: () => (/* binding */ app)
/* harmony export */ });
/* harmony import */ var cookie_parser__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! cookie-parser */ "../../node_modules/cookie-parser/index.js");
/* harmony import */ var cookie_parser__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(cookie_parser__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var cors__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! cors */ "../../node_modules/cors/lib/index.js");
/* harmony import */ var cors__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(cors__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var express__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! express */ "express");
/* harmony import */ var express__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(express__WEBPACK_IMPORTED_MODULE_2__);
/* harmony import */ var http__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! http */ "http");
/* harmony import */ var http__WEBPACK_IMPORTED_MODULE_3___default = /*#__PURE__*/__webpack_require__.n(http__WEBPACK_IMPORTED_MODULE_3__);
/* harmony import */ var morgan__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! morgan */ "morgan");
/* harmony import */ var morgan__WEBPACK_IMPORTED_MODULE_4___default = /*#__PURE__*/__webpack_require__.n(morgan__WEBPACK_IMPORTED_MODULE_4__);
/* harmony import */ var _presentation_controllers_logEntriesController__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./presentation/controllers/logEntriesController */ "./src/presentation/controllers/logEntriesController.ts");






const app = express__WEBPACK_IMPORTED_MODULE_2___default()();
app.use(morgan__WEBPACK_IMPORTED_MODULE_4___default()('dev'));
app.use(express__WEBPACK_IMPORTED_MODULE_2___default().json());
app.use(express__WEBPACK_IMPORTED_MODULE_2___default().urlencoded({ extended: false }));
app.use(cookie_parser__WEBPACK_IMPORTED_MODULE_0___default()());
app.use(cors__WEBPACK_IMPORTED_MODULE_1___default()({ origin: 'http://localhost:3001' }));
app.use('/api', _presentation_controllers_logEntriesController__WEBPACK_IMPORTED_MODULE_5__.logEntriesController);
/**
 * Normalize a port into a number, string, or false.
 */
function normalizePort(val) {
    const port = parseInt(val, 10);
    if (Number.isNaN(port)) {
        // named pipe
        return val;
    }
    if (port >= 0) {
        // port number
        return port;
    }
    return false;
}
/**
 * Get port from environment and store in Express.
 */
const port = normalizePort(process.env.PORT || '3000');
app.set('port', port);
/**
 * Create HTTP server.
 */
const server = http__WEBPACK_IMPORTED_MODULE_3___default().createServer(app);
/**
 * Event listener for HTTP server "error" event.
 */
function onError(error) {
    if (error.syscall !== 'listen') {
        throw error;
    }
    const bind = typeof port === 'string' ? `Pipe ${port}` : `Port ${port}`;
    // handle specific listen errors with friendly messages
    switch (error.code) {
        case 'EACCES':
            // eslint-disable-next-line no-console
            console.error(`${bind} requires elevated privileges`);
            process.exit(1);
            break;
        case 'EADDRINUSE':
            // eslint-disable-next-line no-console
            console.error(`${bind} is already in use`);
            process.exit(1);
            break;
        default:
            throw error;
    }
}
/**
 * Event listener for HTTP server "listening" event.
 */
function onListening() {
    const addr = server.address();
    const bind = typeof addr === 'string' ? `pipe ${addr}` : `port ${addr?.port}`;
    // eslint-disable-next-line no-console
    console.log(`Listening on ${bind}`);
}
/**
 * Listen on provided port, on all network interfaces.
 */
server.listen(port);
server.on('error', onError);
server.on('listening', onListening);

})();

/******/ })()
;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,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LElBQUksR0FBRyxPQUFPLElBQUksS0FBSyxRQUFRLENBQUMsQ0FBQyxDQUFDLFFBQVEsSUFBSSxFQUFFLENBQUMsQ0FBQyxDQUFDLFFBQVEsSUFBSSxFQUFFLElBQUksRUFBRSxDQUFDO0lBQzlFLHNDQUFzQztJQUN0QyxPQUFPLENBQUMsR0FBRyxDQUFDLGdCQUFnQixJQUFJLEVBQUUsQ0FBQyxDQUFDO0FBQ3RDLENBQUM7QUFFRDs7R0FFRztBQUVILE1BQU0sQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLENBQUM7QUFDcEIsTUFBTSxDQUFDLEVBQUUsQ0FBQyxPQUFPLEVBQUUsT0FBTyxDQUFDLENBQUM7QUFDNUIsTUFBTSxDQUFDLEVBQUUsQ0FBQyxXQUFXLEVBQUUsV0FBVyxDQUFDLENBQUMiLCJzb3VyY2VzIjpbIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi4vLi4vbm9kZV9tb2R1bGVzL2Nvb2tpZS1wYXJzZXIvaW5kZXguanMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4uLy4uL25vZGVfbW9kdWxlcy9jb29raWUtc2lnbmF0dXJlL2luZGV4LmpzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uLi8uLi9ub2RlX21vZHVsZXMvY29va2llL2luZGV4LmpzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uLi8uLi9ub2RlX21vZHVsZXMvY29ycy9saWIvaW5kZXguanMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4uLy4uL25vZGVfbW9kdWxlcy9vYmplY3QtYXNzaWduL2luZGV4LmpzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uLi8uLi9ub2RlX21vZHVsZXMvdmFyeS9pbmRleC5qcyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi4vc2hhcmVkL3NyYy9jb25zdGFudHMudHMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4uL3NoYXJlZC9zcmMvaW5kZXgudHMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4uL3NoYXJlZC9zcmMvdHlwZXMudHMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4vc3JjL2FwcGxpY2F0aW9uL21hcHBlcnMvTG9nRW50cmllc0FwaU1hcHBlci50cyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi9zcmMvYXBwbGljYXRpb24vc2VydmljZXMvTG9nRW50cmllc1NlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4vc3JjL2RvbWFpbi9lbnRpdGllcy9FbnRpdHkudHMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4vc3JjL2RvbWFpbi9lbnRpdGllcy9Mb2dFbnRyeS50cyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi9zcmMvZG9tYWluL2VudGl0aWVzL1V1aWQudHMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4vc3JjL3BlcnNpc3RlbmNlL21hcHBlcnMvTG9nRW50cmllc1BlcnNpc3RlbmNlTWFwcGVyLnRzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uL3NyYy9wZXJzaXN0ZW5jZS9yZXBvc2l0b3JpZXMvTG9nRW50cmllc1F1ZXJ5UmVwb3NpdG9yeS50cyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi9zcmMvcGVyc2lzdGVuY2UvcmVwb3NpdG9yaWVzL0xvZ0VudHJpZXNSZXBvc2l0b3J5LnRzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uL3NyYy9wcmVzZW50YXRpb24vY29udHJvbGxlcnMvbG9nRW50cmllc0NvbnRyb2xsZXIudHMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4vc3JjL3NoYXJlZC9kYXRhYmFzZS50cyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi9zcmMvc2hhcmVkL2Vycm9ycy50cyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvZXh0ZXJuYWwgbm9kZS1jb21tb25qcyBcImNyeXB0b1wiIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci9leHRlcm5hbCBjb21tb25qcyBcImV4cHJlc3NcIiIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvZXh0ZXJuYWwgbm9kZS1jb21tb25qcyBcImZzXCIiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyL2V4dGVybmFsIG5vZGUtY29tbW9uanMgXCJodHRwXCIiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyL2V4dGVybmFsIGNvbW1vbmpzIFwibW9yZ2FuXCIiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyL3dlYnBhY2svYm9vdHN0cmFwIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci93ZWJwYWNrL3J1bnRpbWUvY29tcGF0IGdldCBkZWZhdWx0IGV4cG9ydCIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvd2VicGFjay9ydW50aW1lL2RlZmluZSBwcm9wZXJ0eSBnZXR0ZXJzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci93ZWJwYWNrL3J1bnRpbWUvaGFzT3duUHJvcGVydHkgc2hvcnRoYW5kIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci93ZWJwYWNrL3J1bnRpbWUvbWFrZSBuYW1lc3BhY2Ugb2JqZWN0Iiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uL3NyYy9hcHAudHMiXSwic291cmNlc0NvbnRlbnQiOlsiLyohXG4gKiBjb29raWUtcGFyc2VyXG4gKiBDb3B5cmlnaHQoYykgMjAxNCBUSiBIb2xvd2F5Y2h1a1xuICogQ29weXJpZ2h0KGMpIDIwMTUgRG91Z2xhcyBDaHJpc3RvcGhlciBXaWxzb25cbiAqIE1JVCBMaWNlbnNlZFxuICovXG5cbid1c2Ugc3RyaWN0J1xuXG4vKipcbiAqIE1vZHVsZSBkZXBlbmRlbmNpZXMuXG4gKiBAcHJpdmF0ZVxuICovXG5cbnZhciBjb29raWUgPSByZXF1aXJlKCdjb29raWUnKVxudmFyIHNpZ25hdHVyZSA9IHJlcXVpcmUoJ2Nvb2tpZS1zaWduYXR1cmUnKVxuXG4vKipcbiAqIE1vZHVsZSBleHBvcnRzLlxuICogQHB1YmxpY1xuICovXG5cbm1vZHVsZS5leHBvcnRzID0gY29va2llUGFyc2VyXG5tb2R1bGUuZXhwb3J0cy5KU09OQ29va2llID0gSlNPTkNvb2tpZVxubW9kdWxlLmV4cG9ydHMuSlNPTkNvb2tpZXMgPSBKU09OQ29va2llc1xubW9kdWxlLmV4cG9ydHMuc2lnbmVkQ29va2llID0gc2lnbmVkQ29va2llXG5tb2R1bGUuZXhwb3J0cy5zaWduZWRDb29raWVzID0gc2lnbmVkQ29va2llc1xuXG4vKipcbiAqIFBhcnNlIENvb2tpZSBoZWFkZXIgYW5kIHBvcHVsYXRlIGByZXEuY29va2llc2BcbiAqIHdpdGggYW4gb2JqZWN0IGtleWVkIGJ5IHRoZSBjb29raWUgbmFtZXMuXG4gKlxuICogQHBhcmFtIHtzdHJpbmd8YXJyYXl9IFtzZWNyZXRdIEEgc3RyaW5nIChvciBhcnJheSBvZiBzdHJpbmdzKSByZXByZXNlbnRpbmcgY29va2llIHNpZ25pbmcgc2VjcmV0KHMpLlxuICogQHBhcmFtIHtPYmplY3R9IFtvcHRpb25zXVxuICogQHJldHVybiB7RnVuY3Rpb259XG4gKiBAcHVibGljXG4gKi9cblxuZnVuY3Rpb24gY29va2llUGFyc2VyIChzZWNyZXQsIG9wdGlvbnMpIHtcbiAgdmFyIHNlY3JldHMgPSAhc2VjcmV0IHx8IEFycmF5LmlzQXJyYXkoc2VjcmV0KVxuICAgID8gKHNlY3JldCB8fCBbXSlcbiAgICA6IFtzZWNyZXRdXG5cbiAgcmV0dXJuIGZ1bmN0aW9uIGNvb2tpZVBhcnNlciAocmVxLCByZXMsIG5leHQpIHtcbiAgICBpZiAocmVxLmNvb2tpZXMpIHtcbiAgICAgIHJldHVybiBuZXh0KClcbiAgICB9XG5cbiAgICB2YXIgY29va2llcyA9IHJlcS5oZWFkZXJzLmNvb2tpZVxuXG4gICAgcmVxLnNlY3JldCA9IHNlY3JldHNbMF1cbiAgICByZXEuY29va2llcyA9IE9iamVjdC5jcmVhdGUobnVsbClcbiAgICByZXEuc2lnbmVkQ29va2llcyA9IE9iamVjdC5jcmVhdGUobnVsbClcblxuICAgIC8vIG5vIGNvb2tpZXNcbiAgICBpZiAoIWNvb2tpZXMpIHtcbiAgICAgIHJldHVybiBuZXh0KClcbiAgICB9XG5cbiAgICByZXEuY29va2llcyA9IGNvb2tpZS5wYXJzZShjb29raWVzLCBvcHRpb25zKVxuXG4gICAgLy8gcGFyc2Ugc2lnbmVkIGNvb2tpZXNcbiAgICBpZiAoc2VjcmV0cy5sZW5ndGggIT09IDApIHtcbiAgICAgIHJlcS5zaWduZWRDb29raWVzID0gc2lnbmVkQ29va2llcyhyZXEuY29va2llcywgc2VjcmV0cylcbiAgICAgIHJlcS5zaWduZWRDb29raWVzID0gSlNPTkNvb2tpZXMocmVxLnNpZ25lZENvb2tpZXMpXG4gICAgfVxuXG4gICAgLy8gcGFyc2UgSlNPTiBjb29raWVzXG4gICAgcmVxLmNvb2tpZXMgPSBKU09OQ29va2llcyhyZXEuY29va2llcylcblxuICAgIG5leHQoKVxuICB9XG59XG5cbi8qKlxuICogUGFyc2UgSlNPTiBjb29raWUgc3RyaW5nLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSBzdHJcbiAqIEByZXR1cm4ge09iamVjdH0gUGFyc2VkIG9iamVjdCBvciB1bmRlZmluZWQgaWYgbm90IGpzb24gY29va2llXG4gKiBAcHVibGljXG4gKi9cblxuZnVuY3Rpb24gSlNPTkNvb2tpZSAoc3RyKSB7XG4gIGlmICh0eXBlb2Ygc3RyICE9PSAnc3RyaW5nJyB8fCBzdHIuc3Vic3RyKDAsIDIpICE9PSAnajonKSB7XG4gICAgcmV0dXJuIHVuZGVmaW5lZFxuICB9XG5cbiAgdHJ5IHtcbiAgICByZXR1cm4gSlNPTi5wYXJzZShzdHIuc2xpY2UoMikpXG4gIH0gY2F0Y2ggKGVycikge1xuICAgIHJldHVybiB1bmRlZmluZWRcbiAgfVxufVxuXG4vKipcbiAqIFBhcnNlIEpTT04gY29va2llcy5cbiAqXG4gKiBAcGFyYW0ge09iamVjdH0gb2JqXG4gKiBAcmV0dXJuIHtPYmplY3R9XG4gKiBAcHVibGljXG4gKi9cblxuZnVuY3Rpb24gSlNPTkNvb2tpZXMgKG9iaikge1xuICB2YXIgY29va2llcyA9IE9iamVjdC5rZXlzKG9iailcbiAgdmFyIGtleVxuICB2YXIgdmFsXG5cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBjb29raWVzLmxlbmd0aDsgaSsrKSB7XG4gICAga2V5ID0gY29va2llc1tpXVxuICAgIHZhbCA9IEpTT05Db29raWUob2JqW2tleV0pXG5cbiAgICBpZiAodmFsKSB7XG4gICAgICBvYmpba2V5XSA9IHZhbFxuICAgIH1cbiAgfVxuXG4gIHJldHVybiBvYmpcbn1cblxuLyoqXG4gKiBQYXJzZSBhIHNpZ25lZCBjb29raWUgc3RyaW5nLCByZXR1cm4gdGhlIGRlY29kZWQgdmFsdWUuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHN0ciBzaWduZWQgY29va2llIHN0cmluZ1xuICogQHBhcmFtIHtzdHJpbmd8YXJyYXl9IHNlY3JldFxuICogQHJldHVybiB7U3RyaW5nfSBkZWNvZGVkIHZhbHVlXG4gKiBAcHVibGljXG4gKi9cblxuZnVuY3Rpb24gc2lnbmVkQ29va2llIChzdHIsIHNlY3JldCkge1xuICBpZiAodHlwZW9mIHN0ciAhPT0gJ3N0cmluZycpIHtcbiAgICByZXR1cm4gdW5kZWZpbmVkXG4gIH1cblxuICBpZiAoc3RyLnN1YnN0cigwLCAyKSAhPT0gJ3M6Jykge1xuICAgIHJldHVybiBzdHJcbiAgfVxuXG4gIHZhciBzZWNyZXRzID0gIXNlY3JldCB8fCBBcnJheS5pc0FycmF5KHNlY3JldClcbiAgICA/IChzZWNyZXQgfHwgW10pXG4gICAgOiBbc2VjcmV0XVxuXG4gIGZvciAodmFyIGkgPSAwOyBpIDwgc2VjcmV0cy5sZW5ndGg7IGkrKykge1xuICAgIHZhciB2YWwgPSBzaWduYXR1cmUudW5zaWduKHN0ci5zbGljZSgyKSwgc2VjcmV0c1tpXSlcblxuICAgIGlmICh2YWwgIT09IGZhbHNlKSB7XG4gICAgICByZXR1cm4gdmFsXG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIGZhbHNlXG59XG5cbi8qKlxuICogUGFyc2Ugc2lnbmVkIGNvb2tpZXMsIHJldHVybmluZyBhbiBvYmplY3QgY29udGFpbmluZyB0aGUgZGVjb2RlZCBrZXkvdmFsdWVcbiAqIHBhaXJzLCB3aGlsZSByZW1vdmluZyB0aGUgc2lnbmVkIGtleSBmcm9tIG9iai5cbiAqXG4gKiBAcGFyYW0ge09iamVjdH0gb2JqXG4gKiBAcGFyYW0ge3N0cmluZ3xhcnJheX0gc2VjcmV0XG4gKiBAcmV0dXJuIHtPYmplY3R9XG4gKiBAcHVibGljXG4gKi9cblxuZnVuY3Rpb24gc2lnbmVkQ29va2llcyAob2JqLCBzZWNyZXQpIHtcbiAgdmFyIGNvb2tpZXMgPSBPYmplY3Qua2V5cyhvYmopXG4gIHZhciBkZWNcbiAgdmFyIGtleVxuICB2YXIgcmV0ID0gT2JqZWN0LmNyZWF0ZShudWxsKVxuICB2YXIgdmFsXG5cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBjb29raWVzLmxlbmd0aDsgaSsrKSB7XG4gICAga2V5ID0gY29va2llc1tpXVxuICAgIHZhbCA9IG9ialtrZXldXG4gICAgZGVjID0gc2lnbmVkQ29va2llKHZhbCwgc2VjcmV0KVxuXG4gICAgaWYgKHZhbCAhPT0gZGVjKSB7XG4gICAgICByZXRba2V5XSA9IGRlY1xuICAgICAgZGVsZXRlIG9ialtrZXldXG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIHJldFxufVxuIiwiLyoqXG4gKiBNb2R1bGUgZGVwZW5kZW5jaWVzLlxuICovXG5cbnZhciBjcnlwdG8gPSByZXF1aXJlKCdjcnlwdG8nKTtcblxuLyoqXG4gKiBTaWduIHRoZSBnaXZlbiBgdmFsYCB3aXRoIGBzZWNyZXRgLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSB2YWxcbiAqIEBwYXJhbSB7U3RyaW5nfSBzZWNyZXRcbiAqIEByZXR1cm4ge1N0cmluZ31cbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cbmV4cG9ydHMuc2lnbiA9IGZ1bmN0aW9uKHZhbCwgc2VjcmV0KXtcbiAgaWYgKCdzdHJpbmcnICE9IHR5cGVvZiB2YWwpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJDb29raWUgdmFsdWUgbXVzdCBiZSBwcm92aWRlZCBhcyBhIHN0cmluZy5cIik7XG4gIGlmICgnc3RyaW5nJyAhPSB0eXBlb2Ygc2VjcmV0KSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiU2VjcmV0IHN0cmluZyBtdXN0IGJlIHByb3ZpZGVkLlwiKTtcbiAgcmV0dXJuIHZhbCArICcuJyArIGNyeXB0b1xuICAgIC5jcmVhdGVIbWFjKCdzaGEyNTYnLCBzZWNyZXQpXG4gICAgLnVwZGF0ZSh2YWwpXG4gICAgLmRpZ2VzdCgnYmFzZTY0JylcbiAgICAucmVwbGFjZSgvXFw9KyQvLCAnJyk7XG59O1xuXG4vKipcbiAqIFVuc2lnbiBhbmQgZGVjb2RlIHRoZSBnaXZlbiBgdmFsYCB3aXRoIGBzZWNyZXRgLFxuICogcmV0dXJuaW5nIGBmYWxzZWAgaWYgdGhlIHNpZ25hdHVyZSBpcyBpbnZhbGlkLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSB2YWxcbiAqIEBwYXJhbSB7U3RyaW5nfSBzZWNyZXRcbiAqIEByZXR1cm4ge1N0cmluZ3xCb29sZWFufVxuICogQGFwaSBwcml2YXRlXG4gKi9cblxuZXhwb3J0cy51bnNpZ24gPSBmdW5jdGlvbih2YWwsIHNlY3JldCl7XG4gIGlmICgnc3RyaW5nJyAhPSB0eXBlb2YgdmFsKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiU2lnbmVkIGNvb2tpZSBzdHJpbmcgbXVzdCBiZSBwcm92aWRlZC5cIik7XG4gIGlmICgnc3RyaW5nJyAhPSB0eXBlb2Ygc2VjcmV0KSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiU2VjcmV0IHN0cmluZyBtdXN0IGJlIHByb3ZpZGVkLlwiKTtcbiAgdmFyIHN0ciA9IHZhbC5zbGljZSgwLCB2YWwubGFzdEluZGV4T2YoJy4nKSlcbiAgICAsIG1hYyA9IGV4cG9ydHMuc2lnbihzdHIsIHNlY3JldCk7XG4gIFxuICByZXR1cm4gc2hhMShtYWMpID09IHNoYTEodmFsKSA/IHN0ciA6IGZhbHNlO1xufTtcblxuLyoqXG4gKiBQcml2YXRlXG4gKi9cblxuZnVuY3Rpb24gc2hhMShzdHIpe1xuICByZXR1cm4gY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTEnKS51cGRhdGUoc3RyKS5kaWdlc3QoJ2hleCcpO1xufVxuIiwiLyohXG4gKiBjb29raWVcbiAqIENvcHlyaWdodChjKSAyMDEyLTIwMTQgUm9tYW4gU2h0eWxtYW5cbiAqIENvcHlyaWdodChjKSAyMDE1IERvdWdsYXMgQ2hyaXN0b3BoZXIgV2lsc29uXG4gKiBNSVQgTGljZW5zZWRcbiAqL1xuXG4ndXNlIHN0cmljdCc7XG5cbi8qKlxuICogTW9kdWxlIGV4cG9ydHMuXG4gKiBAcHVibGljXG4gKi9cblxuZXhwb3J0cy5wYXJzZSA9IHBhcnNlO1xuZXhwb3J0cy5zZXJpYWxpemUgPSBzZXJpYWxpemU7XG5cbi8qKlxuICogTW9kdWxlIHZhcmlhYmxlcy5cbiAqIEBwcml2YXRlXG4gKi9cblxudmFyIF9fdG9TdHJpbmcgPSBPYmplY3QucHJvdG90eXBlLnRvU3RyaW5nXG52YXIgX19oYXNPd25Qcm9wZXJ0eSA9IE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHlcblxuLyoqXG4gKiBSZWdFeHAgdG8gbWF0Y2ggY29va2llLW5hbWUgaW4gUkZDIDYyNjUgc2VjIDQuMS4xXG4gKiBUaGlzIHJlZmVycyBvdXQgdG8gdGhlIG9ic29sZXRlZCBkZWZpbml0aW9uIG9mIHRva2VuIGluIFJGQyAyNjE2IHNlYyAyLjJcbiAqIHdoaWNoIGhhcyBiZWVuIHJlcGxhY2VkIGJ5IHRoZSB0b2tlbiBkZWZpbml0aW9uIGluIFJGQyA3MjMwIGFwcGVuZGl4IEIuXG4gKlxuICogY29va2llLW5hbWUgICAgICAgPSB0b2tlblxuICogdG9rZW4gICAgICAgICAgICAgPSAxKnRjaGFyXG4gKiB0Y2hhciAgICAgICAgICAgICA9IFwiIVwiIC8gXCIjXCIgLyBcIiRcIiAvIFwiJVwiIC8gXCImXCIgLyBcIidcIiAvXG4gKiAgICAgICAgICAgICAgICAgICAgIFwiKlwiIC8gXCIrXCIgLyBcIi1cIiAvIFwiLlwiIC8gXCJeXCIgLyBcIl9cIiAvXG4gKiAgICAgICAgICAgICAgICAgICAgIFwiYFwiIC8gXCJ8XCIgLyBcIn5cIiAvIERJR0lUIC8gQUxQSEFcbiAqL1xuXG52YXIgY29va2llTmFtZVJlZ0V4cCA9IC9eWyEjJCUmJyorXFwtLl5fYHx+MC05QS1aYS16XSskLztcblxuLyoqXG4gKiBSZWdFeHAgdG8gbWF0Y2ggY29va2llLXZhbHVlIGluIFJGQyA2MjY1IHNlYyA0LjEuMVxuICpcbiAqIGNvb2tpZS12YWx1ZSAgICAgID0gKmNvb2tpZS1vY3RldCAvICggRFFVT1RFICpjb29raWUtb2N0ZXQgRFFVT1RFIClcbiAqIGNvb2tpZS1vY3RldCAgICAgID0gJXgyMSAvICV4MjMtMkIgLyAleDJELTNBIC8gJXgzQy01QiAvICV4NUQtN0VcbiAqICAgICAgICAgICAgICAgICAgICAgOyBVUy1BU0NJSSBjaGFyYWN0ZXJzIGV4Y2x1ZGluZyBDVExzLFxuICogICAgICAgICAgICAgICAgICAgICA7IHdoaXRlc3BhY2UgRFFVT1RFLCBjb21tYSwgc2VtaWNvbG9uLFxuICogICAgICAgICAgICAgICAgICAgICA7IGFuZCBiYWNrc2xhc2hcbiAqL1xuXG52YXIgY29va2llVmFsdWVSZWdFeHAgPSAvXihcIj8pW1xcdTAwMjFcXHUwMDIzLVxcdTAwMkJcXHUwMDJELVxcdTAwM0FcXHUwMDNDLVxcdTAwNUJcXHUwMDVELVxcdTAwN0VdKlxcMSQvO1xuXG4vKipcbiAqIFJlZ0V4cCB0byBtYXRjaCBkb21haW4tdmFsdWUgaW4gUkZDIDYyNjUgc2VjIDQuMS4xXG4gKlxuICogZG9tYWluLXZhbHVlICAgICAgPSA8c3ViZG9tYWluPlxuICogICAgICAgICAgICAgICAgICAgICA7IGRlZmluZWQgaW4gW1JGQzEwMzRdLCBTZWN0aW9uIDMuNSwgYXNcbiAqICAgICAgICAgICAgICAgICAgICAgOyBlbmhhbmNlZCBieSBbUkZDMTEyM10sIFNlY3Rpb24gMi4xXG4gKiA8c3ViZG9tYWluPiAgICAgICA9IDxsYWJlbD4gfCA8c3ViZG9tYWluPiBcIi5cIiA8bGFiZWw+XG4gKiA8bGFiZWw+ICAgICAgICAgICA9IDxsZXQtZGlnPiBbIFsgPGxkaC1zdHI+IF0gPGxldC1kaWc+IF1cbiAqICAgICAgICAgICAgICAgICAgICAgTGFiZWxzIG11c3QgYmUgNjMgY2hhcmFjdGVycyBvciBsZXNzLlxuICogICAgICAgICAgICAgICAgICAgICAnbGV0LWRpZycgbm90ICdsZXR0ZXInIGluIHRoZSBmaXJzdCBjaGFyLCBwZXIgUkZDMTEyM1xuICogPGxkaC1zdHI+ICAgICAgICAgPSA8bGV0LWRpZy1oeXA+IHwgPGxldC1kaWctaHlwPiA8bGRoLXN0cj5cbiAqIDxsZXQtZGlnLWh5cD4gICAgID0gPGxldC1kaWc+IHwgXCItXCJcbiAqIDxsZXQtZGlnPiAgICAgICAgID0gPGxldHRlcj4gfCA8ZGlnaXQ+XG4gKiA8bGV0dGVyPiAgICAgICAgICA9IGFueSBvbmUgb2YgdGhlIDUyIGFscGhhYmV0aWMgY2hhcmFjdGVycyBBIHRocm91Z2ggWiBpblxuICogICAgICAgICAgICAgICAgICAgICB1cHBlciBjYXNlIGFuZCBhIHRocm91Z2ggeiBpbiBsb3dlciBjYXNlXG4gKiA8ZGlnaXQ+ICAgICAgICAgICA9IGFueSBvbmUgb2YgdGhlIHRlbiBkaWdpdHMgMCB0aHJvdWdoIDlcbiAqXG4gKiBLZWVwIHN1cHBvcnQgZm9yIGxlYWRpbmcgZG90OiBodHRwczovL2dpdGh1Yi5jb20vanNodHRwL2Nvb2tpZS9pc3N1ZXMvMTczXG4gKlxuICogPiAoTm90ZSB0aGF0IGEgbGVhZGluZyAleDJFIChcIi5cIiksIGlmIHByZXNlbnQsIGlzIGlnbm9yZWQgZXZlbiB0aG91Z2ggdGhhdFxuICogY2hhcmFjdGVyIGlzIG5vdCBwZXJtaXR0ZWQsIGJ1dCBhIHRyYWlsaW5nICV4MkUgKFwiLlwiKSwgaWYgcHJlc2VudCwgd2lsbFxuICogY2F1c2UgdGhlIHVzZXIgYWdlbnQgdG8gaWdub3JlIHRoZSBhdHRyaWJ1dGUuKVxuICovXG5cbnZhciBkb21haW5WYWx1ZVJlZ0V4cCA9IC9eKFsuXT9bYS16MC05XShbYS16MC05LV17MCw2MX1bYS16MC05XSk/KShbLl1bYS16MC05XShbYS16MC05LV17MCw2MX1bYS16MC05XSk/KSokL2k7XG5cbi8qKlxuICogUmVnRXhwIHRvIG1hdGNoIHBhdGgtdmFsdWUgaW4gUkZDIDYyNjUgc2VjIDQuMS4xXG4gKlxuICogcGF0aC12YWx1ZSAgICAgICAgPSA8YW55IENIQVIgZXhjZXB0IENUTHMgb3IgXCI7XCI+XG4gKiBDSEFSICAgICAgICAgICAgICA9ICV4MDEtN0ZcbiAqICAgICAgICAgICAgICAgICAgICAgOyBkZWZpbmVkIGluIFJGQyA1MjM0IGFwcGVuZGl4IEIuMVxuICovXG5cbnZhciBwYXRoVmFsdWVSZWdFeHAgPSAvXltcXHUwMDIwLVxcdTAwM0FcXHUwMDNELVxcdTAwN0VdKiQvO1xuXG4vKipcbiAqIFBhcnNlIGEgY29va2llIGhlYWRlci5cbiAqXG4gKiBQYXJzZSB0aGUgZ2l2ZW4gY29va2llIGhlYWRlciBzdHJpbmcgaW50byBhbiBvYmplY3RcbiAqIFRoZSBvYmplY3QgaGFzIHRoZSB2YXJpb3VzIGNvb2tpZXMgYXMga2V5cyhuYW1lcykgPT4gdmFsdWVzXG4gKlxuICogQHBhcmFtIHtzdHJpbmd9IHN0clxuICogQHBhcmFtIHtvYmplY3R9IFtvcHRdXG4gKiBAcmV0dXJuIHtvYmplY3R9XG4gKiBAcHVibGljXG4gKi9cblxuZnVuY3Rpb24gcGFyc2Uoc3RyLCBvcHQpIHtcbiAgaWYgKHR5cGVvZiBzdHIgIT09ICdzdHJpbmcnKSB7XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcignYXJndW1lbnQgc3RyIG11c3QgYmUgYSBzdHJpbmcnKTtcbiAgfVxuXG4gIHZhciBvYmogPSB7fTtcbiAgdmFyIGxlbiA9IHN0ci5sZW5ndGg7XG4gIC8vIFJGQyA2MjY1IHNlYyA0LjEuMSwgUkZDIDI2MTYgMi4yIGRlZmluZXMgYSBjb29raWUgbmFtZSBjb25zaXN0cyBvZiBvbmUgY2hhciBtaW5pbXVtLCBwbHVzICc9Jy5cbiAgaWYgKGxlbiA8IDIpIHJldHVybiBvYmo7XG5cbiAgdmFyIGRlYyA9IChvcHQgJiYgb3B0LmRlY29kZSkgfHwgZGVjb2RlO1xuICB2YXIgaW5kZXggPSAwO1xuICB2YXIgZXFJZHggPSAwO1xuICB2YXIgZW5kSWR4ID0gMDtcblxuICBkbyB7XG4gICAgZXFJZHggPSBzdHIuaW5kZXhPZignPScsIGluZGV4KTtcbiAgICBpZiAoZXFJZHggPT09IC0xKSBicmVhazsgLy8gTm8gbW9yZSBjb29raWUgcGFpcnMuXG5cbiAgICBlbmRJZHggPSBzdHIuaW5kZXhPZignOycsIGluZGV4KTtcblxuICAgIGlmIChlbmRJZHggPT09IC0xKSB7XG4gICAgICBlbmRJZHggPSBsZW47XG4gICAgfSBlbHNlIGlmIChlcUlkeCA+IGVuZElkeCkge1xuICAgICAgLy8gYmFja3RyYWNrIG9uIHByaW9yIHNlbWljb2xvblxuICAgICAgaW5kZXggPSBzdHIubGFzdEluZGV4T2YoJzsnLCBlcUlkeCAtIDEpICsgMTtcbiAgICAgIGNvbnRpbnVlO1xuICAgIH1cblxuICAgIHZhciBrZXlTdGFydElkeCA9IHN0YXJ0SW5kZXgoc3RyLCBpbmRleCwgZXFJZHgpO1xuICAgIHZhciBrZXlFbmRJZHggPSBlbmRJbmRleChzdHIsIGVxSWR4LCBrZXlTdGFydElkeCk7XG4gICAgdmFyIGtleSA9IHN0ci5zbGljZShrZXlTdGFydElkeCwga2V5RW5kSWR4KTtcblxuICAgIC8vIG9ubHkgYXNzaWduIG9uY2VcbiAgICBpZiAoIV9faGFzT3duUHJvcGVydHkuY2FsbChvYmosIGtleSkpIHtcbiAgICAgIHZhciB2YWxTdGFydElkeCA9IHN0YXJ0SW5kZXgoc3RyLCBlcUlkeCArIDEsIGVuZElkeCk7XG4gICAgICB2YXIgdmFsRW5kSWR4ID0gZW5kSW5kZXgoc3RyLCBlbmRJZHgsIHZhbFN0YXJ0SWR4KTtcblxuICAgICAgaWYgKHN0ci5jaGFyQ29kZUF0KHZhbFN0YXJ0SWR4KSA9PT0gMHgyMiAvKiBcIiAqLyAmJiBzdHIuY2hhckNvZGVBdCh2YWxFbmRJZHggLSAxKSA9PT0gMHgyMiAvKiBcIiAqLykge1xuICAgICAgICB2YWxTdGFydElkeCsrO1xuICAgICAgICB2YWxFbmRJZHgtLTtcbiAgICAgIH1cblxuICAgICAgdmFyIHZhbCA9IHN0ci5zbGljZSh2YWxTdGFydElkeCwgdmFsRW5kSWR4KTtcbiAgICAgIG9ialtrZXldID0gdHJ5RGVjb2RlKHZhbCwgZGVjKTtcbiAgICB9XG5cbiAgICBpbmRleCA9IGVuZElkeCArIDFcbiAgfSB3aGlsZSAoaW5kZXggPCBsZW4pO1xuXG4gIHJldHVybiBvYmo7XG59XG5cbmZ1bmN0aW9uIHN0YXJ0SW5kZXgoc3RyLCBpbmRleCwgbWF4KSB7XG4gIGRvIHtcbiAgICB2YXIgY29kZSA9IHN0ci5jaGFyQ29kZUF0KGluZGV4KTtcbiAgICBpZiAoY29kZSAhPT0gMHgyMCAvKiAgICovICYmIGNvZGUgIT09IDB4MDkgLyogXFx0ICovKSByZXR1cm4gaW5kZXg7XG4gIH0gd2hpbGUgKCsraW5kZXggPCBtYXgpO1xuICByZXR1cm4gbWF4O1xufVxuXG5mdW5jdGlvbiBlbmRJbmRleChzdHIsIGluZGV4LCBtaW4pIHtcbiAgd2hpbGUgKGluZGV4ID4gbWluKSB7XG4gICAgdmFyIGNvZGUgPSBzdHIuY2hhckNvZGVBdCgtLWluZGV4KTtcbiAgICBpZiAoY29kZSAhPT0gMHgyMCAvKiAgICovICYmIGNvZGUgIT09IDB4MDkgLyogXFx0ICovKSByZXR1cm4gaW5kZXggKyAxO1xuICB9XG4gIHJldHVybiBtaW47XG59XG5cbi8qKlxuICogU2VyaWFsaXplIGRhdGEgaW50byBhIGNvb2tpZSBoZWFkZXIuXG4gKlxuICogU2VyaWFsaXplIGEgbmFtZSB2YWx1ZSBwYWlyIGludG8gYSBjb29raWUgc3RyaW5nIHN1aXRhYmxlIGZvclxuICogaHR0cCBoZWFkZXJzLiBBbiBvcHRpb25hbCBvcHRpb25zIG9iamVjdCBzcGVjaWZpZXMgY29va2llIHBhcmFtZXRlcnMuXG4gKlxuICogc2VyaWFsaXplKCdmb28nLCAnYmFyJywgeyBodHRwT25seTogdHJ1ZSB9KVxuICogICA9PiBcImZvbz1iYXI7IGh0dHBPbmx5XCJcbiAqXG4gKiBAcGFyYW0ge3N0cmluZ30gbmFtZVxuICogQHBhcmFtIHtzdHJpbmd9IHZhbFxuICogQHBhcmFtIHtvYmplY3R9IFtvcHRdXG4gKiBAcmV0dXJuIHtzdHJpbmd9XG4gKiBAcHVibGljXG4gKi9cblxuZnVuY3Rpb24gc2VyaWFsaXplKG5hbWUsIHZhbCwgb3B0KSB7XG4gIHZhciBlbmMgPSAob3B0ICYmIG9wdC5lbmNvZGUpIHx8IGVuY29kZVVSSUNvbXBvbmVudDtcblxuICBpZiAodHlwZW9mIGVuYyAhPT0gJ2Z1bmN0aW9uJykge1xuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ29wdGlvbiBlbmNvZGUgaXMgaW52YWxpZCcpO1xuICB9XG5cbiAgaWYgKCFjb29raWVOYW1lUmVnRXhwLnRlc3QobmFtZSkpIHtcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdhcmd1bWVudCBuYW1lIGlzIGludmFsaWQnKTtcbiAgfVxuXG4gIHZhciB2YWx1ZSA9IGVuYyh2YWwpO1xuXG4gIGlmICghY29va2llVmFsdWVSZWdFeHAudGVzdCh2YWx1ZSkpIHtcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdhcmd1bWVudCB2YWwgaXMgaW52YWxpZCcpO1xuICB9XG5cbiAgdmFyIHN0ciA9IG5hbWUgKyAnPScgKyB2YWx1ZTtcbiAgaWYgKCFvcHQpIHJldHVybiBzdHI7XG5cbiAgaWYgKG51bGwgIT0gb3B0Lm1heEFnZSkge1xuICAgIHZhciBtYXhBZ2UgPSBNYXRoLmZsb29yKG9wdC5tYXhBZ2UpO1xuXG4gICAgaWYgKCFpc0Zpbml0ZShtYXhBZ2UpKSB7XG4gICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdvcHRpb24gbWF4QWdlIGlzIGludmFsaWQnKVxuICAgIH1cblxuICAgIHN0ciArPSAnOyBNYXgtQWdlPScgKyBtYXhBZ2U7XG4gIH1cblxuICBpZiAob3B0LmRvbWFpbikge1xuICAgIGlmICghZG9tYWluVmFsdWVSZWdFeHAudGVzdChvcHQuZG9tYWluKSkge1xuICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignb3B0aW9uIGRvbWFpbiBpcyBpbnZhbGlkJyk7XG4gICAgfVxuXG4gICAgc3RyICs9ICc7IERvbWFpbj0nICsgb3B0LmRvbWFpbjtcbiAgfVxuXG4gIGlmIChvcHQucGF0aCkge1xuICAgIGlmICghcGF0aFZhbHVlUmVnRXhwLnRlc3Qob3B0LnBhdGgpKSB7XG4gICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdvcHRpb24gcGF0aCBpcyBpbnZhbGlkJyk7XG4gICAgfVxuXG4gICAgc3RyICs9ICc7IFBhdGg9JyArIG9wdC5wYXRoO1xuICB9XG5cbiAgaWYgKG9wdC5leHBpcmVzKSB7XG4gICAgdmFyIGV4cGlyZXMgPSBvcHQuZXhwaXJlc1xuXG4gICAgaWYgKCFpc0RhdGUoZXhwaXJlcykgfHwgaXNOYU4oZXhwaXJlcy52YWx1ZU9mKCkpKSB7XG4gICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdvcHRpb24gZXhwaXJlcyBpcyBpbnZhbGlkJyk7XG4gICAgfVxuXG4gICAgc3RyICs9ICc7IEV4cGlyZXM9JyArIGV4cGlyZXMudG9VVENTdHJpbmcoKVxuICB9XG5cbiAgaWYgKG9wdC5odHRwT25seSkge1xuICAgIHN0ciArPSAnOyBIdHRwT25seSc7XG4gIH1cblxuICBpZiAob3B0LnNlY3VyZSkge1xuICAgIHN0ciArPSAnOyBTZWN1cmUnO1xuICB9XG5cbiAgaWYgKG9wdC5wYXJ0aXRpb25lZCkge1xuICAgIHN0ciArPSAnOyBQYXJ0aXRpb25lZCdcbiAgfVxuXG4gIGlmIChvcHQucHJpb3JpdHkpIHtcbiAgICB2YXIgcHJpb3JpdHkgPSB0eXBlb2Ygb3B0LnByaW9yaXR5ID09PSAnc3RyaW5nJ1xuICAgICAgPyBvcHQucHJpb3JpdHkudG9Mb3dlckNhc2UoKSA6IG9wdC5wcmlvcml0eTtcblxuICAgIHN3aXRjaCAocHJpb3JpdHkpIHtcbiAgICAgIGNhc2UgJ2xvdyc6XG4gICAgICAgIHN0ciArPSAnOyBQcmlvcml0eT1Mb3cnXG4gICAgICAgIGJyZWFrXG4gICAgICBjYXNlICdtZWRpdW0nOlxuICAgICAgICBzdHIgKz0gJzsgUHJpb3JpdHk9TWVkaXVtJ1xuICAgICAgICBicmVha1xuICAgICAgY2FzZSAnaGlnaCc6XG4gICAgICAgIHN0ciArPSAnOyBQcmlvcml0eT1IaWdoJ1xuICAgICAgICBicmVha1xuICAgICAgZGVmYXVsdDpcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignb3B0aW9uIHByaW9yaXR5IGlzIGludmFsaWQnKVxuICAgIH1cbiAgfVxuXG4gIGlmIChvcHQuc2FtZVNpdGUpIHtcbiAgICB2YXIgc2FtZVNpdGUgPSB0eXBlb2Ygb3B0LnNhbWVTaXRlID09PSAnc3RyaW5nJ1xuICAgICAgPyBvcHQuc2FtZVNpdGUudG9Mb3dlckNhc2UoKSA6IG9wdC5zYW1lU2l0ZTtcblxuICAgIHN3aXRjaCAoc2FtZVNpdGUpIHtcbiAgICAgIGNhc2UgdHJ1ZTpcbiAgICAgICAgc3RyICs9ICc7IFNhbWVTaXRlPVN0cmljdCc7XG4gICAgICAgIGJyZWFrO1xuICAgICAgY2FzZSAnbGF4JzpcbiAgICAgICAgc3RyICs9ICc7IFNhbWVTaXRlPUxheCc7XG4gICAgICAgIGJyZWFrO1xuICAgICAgY2FzZSAnc3RyaWN0JzpcbiAgICAgICAgc3RyICs9ICc7IFNhbWVTaXRlPVN0cmljdCc7XG4gICAgICAgIGJyZWFrO1xuICAgICAgY2FzZSAnbm9uZSc6XG4gICAgICAgIHN0ciArPSAnOyBTYW1lU2l0ZT1Ob25lJztcbiAgICAgICAgYnJlYWs7XG4gICAgICBkZWZhdWx0OlxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdvcHRpb24gc2FtZVNpdGUgaXMgaW52YWxpZCcpO1xuICAgIH1cbiAgfVxuXG4gIHJldHVybiBzdHI7XG59XG5cbi8qKlxuICogVVJMLWRlY29kZSBzdHJpbmcgdmFsdWUuIE9wdGltaXplZCB0byBza2lwIG5hdGl2ZSBjYWxsIHdoZW4gbm8gJS5cbiAqXG4gKiBAcGFyYW0ge3N0cmluZ30gc3RyXG4gKiBAcmV0dXJucyB7c3RyaW5nfVxuICovXG5cbmZ1bmN0aW9uIGRlY29kZSAoc3RyKSB7XG4gIHJldHVybiBzdHIuaW5kZXhPZignJScpICE9PSAtMVxuICAgID8gZGVjb2RlVVJJQ29tcG9uZW50KHN0cilcbiAgICA6IHN0clxufVxuXG4vKipcbiAqIERldGVybWluZSBpZiB2YWx1ZSBpcyBhIERhdGUuXG4gKlxuICogQHBhcmFtIHsqfSB2YWxcbiAqIEBwcml2YXRlXG4gKi9cblxuZnVuY3Rpb24gaXNEYXRlICh2YWwpIHtcbiAgcmV0dXJuIF9fdG9TdHJpbmcuY2FsbCh2YWwpID09PSAnW29iamVjdCBEYXRlXSc7XG59XG5cbi8qKlxuICogVHJ5IGRlY29kaW5nIGEgc3RyaW5nIHVzaW5nIGEgZGVjb2RpbmcgZnVuY3Rpb24uXG4gKlxuICogQHBhcmFtIHtzdHJpbmd9IHN0clxuICogQHBhcmFtIHtmdW5jdGlvbn0gZGVjb2RlXG4gKiBAcHJpdmF0ZVxuICovXG5cbmZ1bmN0aW9uIHRyeURlY29kZShzdHIsIGRlY29kZSkge1xuICB0cnkge1xuICAgIHJldHVybiBkZWNvZGUoc3RyKTtcbiAgfSBjYXRjaCAoZSkge1xuICAgIHJldHVybiBzdHI7XG4gIH1cbn1cbiIsIihmdW5jdGlvbiAoKSB7XG5cbiAgJ3VzZSBzdHJpY3QnO1xuXG4gIHZhciBhc3NpZ24gPSByZXF1aXJlKCdvYmplY3QtYXNzaWduJyk7XG4gIHZhciB2YXJ5ID0gcmVxdWlyZSgndmFyeScpO1xuXG4gIHZhciBkZWZhdWx0cyA9IHtcbiAgICBvcmlnaW46ICcqJyxcbiAgICBtZXRob2RzOiAnR0VULEhFQUQsUFVULFBBVENILFBPU1QsREVMRVRFJyxcbiAgICBwcmVmbGlnaHRDb250aW51ZTogZmFsc2UsXG4gICAgb3B0aW9uc1N1Y2Nlc3NTdGF0dXM6IDIwNFxuICB9O1xuXG4gIGZ1bmN0aW9uIGlzU3RyaW5nKHMpIHtcbiAgICByZXR1cm4gdHlwZW9mIHMgPT09ICdzdHJpbmcnIHx8IHMgaW5zdGFuY2VvZiBTdHJpbmc7XG4gIH1cblxuICBmdW5jdGlvbiBpc09yaWdpbkFsbG93ZWQob3JpZ2luLCBhbGxvd2VkT3JpZ2luKSB7XG4gICAgaWYgKEFycmF5LmlzQXJyYXkoYWxsb3dlZE9yaWdpbikpIHtcbiAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYWxsb3dlZE9yaWdpbi5sZW5ndGg7ICsraSkge1xuICAgICAgICBpZiAoaXNPcmlnaW5BbGxvd2VkKG9yaWdpbiwgYWxsb3dlZE9yaWdpbltpXSkpIHtcbiAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH0gZWxzZSBpZiAoaXNTdHJpbmcoYWxsb3dlZE9yaWdpbikpIHtcbiAgICAgIHJldHVybiBvcmlnaW4gPT09IGFsbG93ZWRPcmlnaW47XG4gICAgfSBlbHNlIGlmIChhbGxvd2VkT3JpZ2luIGluc3RhbmNlb2YgUmVnRXhwKSB7XG4gICAgICByZXR1cm4gYWxsb3dlZE9yaWdpbi50ZXN0KG9yaWdpbik7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJldHVybiAhIWFsbG93ZWRPcmlnaW47XG4gICAgfVxuICB9XG5cbiAgZnVuY3Rpb24gY29uZmlndXJlT3JpZ2luKG9wdGlvbnMsIHJlcSkge1xuICAgIHZhciByZXF1ZXN0T3JpZ2luID0gcmVxLmhlYWRlcnMub3JpZ2luLFxuICAgICAgaGVhZGVycyA9IFtdLFxuICAgICAgaXNBbGxvd2VkO1xuXG4gICAgaWYgKCFvcHRpb25zLm9yaWdpbiB8fCBvcHRpb25zLm9yaWdpbiA9PT0gJyonKSB7XG4gICAgICAvLyBhbGxvdyBhbnkgb3JpZ2luXG4gICAgICBoZWFkZXJzLnB1c2goW3tcbiAgICAgICAga2V5OiAnQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luJyxcbiAgICAgICAgdmFsdWU6ICcqJ1xuICAgICAgfV0pO1xuICAgIH0gZWxzZSBpZiAoaXNTdHJpbmcob3B0aW9ucy5vcmlnaW4pKSB7XG4gICAgICAvLyBmaXhlZCBvcmlnaW5cbiAgICAgIGhlYWRlcnMucHVzaChbe1xuICAgICAgICBrZXk6ICdBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4nLFxuICAgICAgICB2YWx1ZTogb3B0aW9ucy5vcmlnaW5cbiAgICAgIH1dKTtcbiAgICAgIGhlYWRlcnMucHVzaChbe1xuICAgICAgICBrZXk6ICdWYXJ5JyxcbiAgICAgICAgdmFsdWU6ICdPcmlnaW4nXG4gICAgICB9XSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGlzQWxsb3dlZCA9IGlzT3JpZ2luQWxsb3dlZChyZXF1ZXN0T3JpZ2luLCBvcHRpb25zLm9yaWdpbik7XG4gICAgICAvLyByZWZsZWN0IG9yaWdpblxuICAgICAgaGVhZGVycy5wdXNoKFt7XG4gICAgICAgIGtleTogJ0FjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbicsXG4gICAgICAgIHZhbHVlOiBpc0FsbG93ZWQgPyByZXF1ZXN0T3JpZ2luIDogZmFsc2VcbiAgICAgIH1dKTtcbiAgICAgIGhlYWRlcnMucHVzaChbe1xuICAgICAgICBrZXk6ICdWYXJ5JyxcbiAgICAgICAgdmFsdWU6ICdPcmlnaW4nXG4gICAgICB9XSk7XG4gICAgfVxuXG4gICAgcmV0dXJuIGhlYWRlcnM7XG4gIH1cblxuICBmdW5jdGlvbiBjb25maWd1cmVNZXRob2RzKG9wdGlvbnMpIHtcbiAgICB2YXIgbWV0aG9kcyA9IG9wdGlvbnMubWV0aG9kcztcbiAgICBpZiAobWV0aG9kcy5qb2luKSB7XG4gICAgICBtZXRob2RzID0gb3B0aW9ucy5tZXRob2RzLmpvaW4oJywnKTsgLy8gLm1ldGhvZHMgaXMgYW4gYXJyYXksIHNvIHR1cm4gaXQgaW50byBhIHN0cmluZ1xuICAgIH1cbiAgICByZXR1cm4ge1xuICAgICAga2V5OiAnQWNjZXNzLUNvbnRyb2wtQWxsb3ctTWV0aG9kcycsXG4gICAgICB2YWx1ZTogbWV0aG9kc1xuICAgIH07XG4gIH1cblxuICBmdW5jdGlvbiBjb25maWd1cmVDcmVkZW50aWFscyhvcHRpb25zKSB7XG4gICAgaWYgKG9wdGlvbnMuY3JlZGVudGlhbHMgPT09IHRydWUpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIGtleTogJ0FjY2Vzcy1Db250cm9sLUFsbG93LUNyZWRlbnRpYWxzJyxcbiAgICAgICAgdmFsdWU6ICd0cnVlJ1xuICAgICAgfTtcbiAgICB9XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cblxuICBmdW5jdGlvbiBjb25maWd1cmVBbGxvd2VkSGVhZGVycyhvcHRpb25zLCByZXEpIHtcbiAgICB2YXIgYWxsb3dlZEhlYWRlcnMgPSBvcHRpb25zLmFsbG93ZWRIZWFkZXJzIHx8IG9wdGlvbnMuaGVhZGVycztcbiAgICB2YXIgaGVhZGVycyA9IFtdO1xuXG4gICAgaWYgKCFhbGxvd2VkSGVhZGVycykge1xuICAgICAgYWxsb3dlZEhlYWRlcnMgPSByZXEuaGVhZGVyc1snYWNjZXNzLWNvbnRyb2wtcmVxdWVzdC1oZWFkZXJzJ107IC8vIC5oZWFkZXJzIHdhc24ndCBzcGVjaWZpZWQsIHNvIHJlZmxlY3QgdGhlIHJlcXVlc3QgaGVhZGVyc1xuICAgICAgaGVhZGVycy5wdXNoKFt7XG4gICAgICAgIGtleTogJ1ZhcnknLFxuICAgICAgICB2YWx1ZTogJ0FjY2Vzcy1Db250cm9sLVJlcXVlc3QtSGVhZGVycydcbiAgICAgIH1dKTtcbiAgICB9IGVsc2UgaWYgKGFsbG93ZWRIZWFkZXJzLmpvaW4pIHtcbiAgICAgIGFsbG93ZWRIZWFkZXJzID0gYWxsb3dlZEhlYWRlcnMuam9pbignLCcpOyAvLyAuaGVhZGVycyBpcyBhbiBhcnJheSwgc28gdHVybiBpdCBpbnRvIGEgc3RyaW5nXG4gICAgfVxuICAgIGlmIChhbGxvd2VkSGVhZGVycyAmJiBhbGxvd2VkSGVhZGVycy5sZW5ndGgpIHtcbiAgICAgIGhlYWRlcnMucHVzaChbe1xuICAgICAgICBrZXk6ICdBY2Nlc3MtQ29udHJvbC1BbGxvdy1IZWFkZXJzJyxcbiAgICAgICAgdmFsdWU6IGFsbG93ZWRIZWFkZXJzXG4gICAgICB9XSk7XG4gICAgfVxuXG4gICAgcmV0dXJuIGhlYWRlcnM7XG4gIH1cblxuICBmdW5jdGlvbiBjb25maWd1cmVFeHBvc2VkSGVhZGVycyhvcHRpb25zKSB7XG4gICAgdmFyIGhlYWRlcnMgPSBvcHRpb25zLmV4cG9zZWRIZWFkZXJzO1xuICAgIGlmICghaGVhZGVycykge1xuICAgICAgcmV0dXJuIG51bGw7XG4gICAgfSBlbHNlIGlmIChoZWFkZXJzLmpvaW4pIHtcbiAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLmpvaW4oJywnKTsgLy8gLmhlYWRlcnMgaXMgYW4gYXJyYXksIHNvIHR1cm4gaXQgaW50byBhIHN0cmluZ1xuICAgIH1cbiAgICBpZiAoaGVhZGVycyAmJiBoZWFkZXJzLmxlbmd0aCkge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAga2V5OiAnQWNjZXNzLUNvbnRyb2wtRXhwb3NlLUhlYWRlcnMnLFxuICAgICAgICB2YWx1ZTogaGVhZGVyc1xuICAgICAgfTtcbiAgICB9XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cblxuICBmdW5jdGlvbiBjb25maWd1cmVNYXhBZ2Uob3B0aW9ucykge1xuICAgIHZhciBtYXhBZ2UgPSAodHlwZW9mIG9wdGlvbnMubWF4QWdlID09PSAnbnVtYmVyJyB8fCBvcHRpb25zLm1heEFnZSkgJiYgb3B0aW9ucy5tYXhBZ2UudG9TdHJpbmcoKVxuICAgIGlmIChtYXhBZ2UgJiYgbWF4QWdlLmxlbmd0aCkge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAga2V5OiAnQWNjZXNzLUNvbnRyb2wtTWF4LUFnZScsXG4gICAgICAgIHZhbHVlOiBtYXhBZ2VcbiAgICAgIH07XG4gICAgfVxuICAgIHJldHVybiBudWxsO1xuICB9XG5cbiAgZnVuY3Rpb24gYXBwbHlIZWFkZXJzKGhlYWRlcnMsIHJlcykge1xuICAgIGZvciAodmFyIGkgPSAwLCBuID0gaGVhZGVycy5sZW5ndGg7IGkgPCBuOyBpKyspIHtcbiAgICAgIHZhciBoZWFkZXIgPSBoZWFkZXJzW2ldO1xuICAgICAgaWYgKGhlYWRlcikge1xuICAgICAgICBpZiAoQXJyYXkuaXNBcnJheShoZWFkZXIpKSB7XG4gICAgICAgICAgYXBwbHlIZWFkZXJzKGhlYWRlciwgcmVzKTtcbiAgICAgICAgfSBlbHNlIGlmIChoZWFkZXIua2V5ID09PSAnVmFyeScgJiYgaGVhZGVyLnZhbHVlKSB7XG4gICAgICAgICAgdmFyeShyZXMsIGhlYWRlci52YWx1ZSk7XG4gICAgICAgIH0gZWxzZSBpZiAoaGVhZGVyLnZhbHVlKSB7XG4gICAgICAgICAgcmVzLnNldEhlYWRlcihoZWFkZXIua2V5LCBoZWFkZXIudmFsdWUpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgZnVuY3Rpb24gY29ycyhvcHRpb25zLCByZXEsIHJlcywgbmV4dCkge1xuICAgIHZhciBoZWFkZXJzID0gW10sXG4gICAgICBtZXRob2QgPSByZXEubWV0aG9kICYmIHJlcS5tZXRob2QudG9VcHBlckNhc2UgJiYgcmVxLm1ldGhvZC50b1VwcGVyQ2FzZSgpO1xuXG4gICAgaWYgKG1ldGhvZCA9PT0gJ09QVElPTlMnKSB7XG4gICAgICAvLyBwcmVmbGlnaHRcbiAgICAgIGhlYWRlcnMucHVzaChjb25maWd1cmVPcmlnaW4ob3B0aW9ucywgcmVxKSk7XG4gICAgICBoZWFkZXJzLnB1c2goY29uZmlndXJlQ3JlZGVudGlhbHMob3B0aW9ucywgcmVxKSk7XG4gICAgICBoZWFkZXJzLnB1c2goY29uZmlndXJlTWV0aG9kcyhvcHRpb25zLCByZXEpKTtcbiAgICAgIGhlYWRlcnMucHVzaChjb25maWd1cmVBbGxvd2VkSGVhZGVycyhvcHRpb25zLCByZXEpKTtcbiAgICAgIGhlYWRlcnMucHVzaChjb25maWd1cmVNYXhBZ2Uob3B0aW9ucywgcmVxKSk7XG4gICAgICBoZWFkZXJzLnB1c2goY29uZmlndXJlRXhwb3NlZEhlYWRlcnMob3B0aW9ucywgcmVxKSk7XG4gICAgICBhcHBseUhlYWRlcnMoaGVhZGVycywgcmVzKTtcblxuICAgICAgaWYgKG9wdGlvbnMucHJlZmxpZ2h0Q29udGludWUpIHtcbiAgICAgICAgbmV4dCgpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy8gU2FmYXJpIChhbmQgcG90ZW50aWFsbHkgb3RoZXIgYnJvd3NlcnMpIG5lZWQgY29udGVudC1sZW5ndGggMCxcbiAgICAgICAgLy8gICBmb3IgMjA0IG9yIHRoZXkganVzdCBoYW5nIHdhaXRpbmcgZm9yIGEgYm9keVxuICAgICAgICByZXMuc3RhdHVzQ29kZSA9IG9wdGlvbnMub3B0aW9uc1N1Y2Nlc3NTdGF0dXM7XG4gICAgICAgIHJlcy5zZXRIZWFkZXIoJ0NvbnRlbnQtTGVuZ3RoJywgJzAnKTtcbiAgICAgICAgcmVzLmVuZCgpO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICAvLyBhY3R1YWwgcmVzcG9uc2VcbiAgICAgIGhlYWRlcnMucHVzaChjb25maWd1cmVPcmlnaW4ob3B0aW9ucywgcmVxKSk7XG4gICAgICBoZWFkZXJzLnB1c2goY29uZmlndXJlQ3JlZGVudGlhbHMob3B0aW9ucywgcmVxKSk7XG4gICAgICBoZWFkZXJzLnB1c2goY29uZmlndXJlRXhwb3NlZEhlYWRlcnMob3B0aW9ucywgcmVxKSk7XG4gICAgICBhcHBseUhlYWRlcnMoaGVhZGVycywgcmVzKTtcbiAgICAgIG5leHQoKTtcbiAgICB9XG4gIH1cblxuICBmdW5jdGlvbiBtaWRkbGV3YXJlV3JhcHBlcihvKSB7XG4gICAgLy8gaWYgb3B0aW9ucyBhcmUgc3RhdGljIChlaXRoZXIgdmlhIGRlZmF1bHRzIG9yIGN1c3RvbSBvcHRpb25zIHBhc3NlZCBpbiksIHdyYXAgaW4gYSBmdW5jdGlvblxuICAgIHZhciBvcHRpb25zQ2FsbGJhY2sgPSBudWxsO1xuICAgIGlmICh0eXBlb2YgbyA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgb3B0aW9uc0NhbGxiYWNrID0gbztcbiAgICB9IGVsc2Uge1xuICAgICAgb3B0aW9uc0NhbGxiYWNrID0gZnVuY3Rpb24gKHJlcSwgY2IpIHtcbiAgICAgICAgY2IobnVsbCwgbyk7XG4gICAgICB9O1xuICAgIH1cblxuICAgIHJldHVybiBmdW5jdGlvbiBjb3JzTWlkZGxld2FyZShyZXEsIHJlcywgbmV4dCkge1xuICAgICAgb3B0aW9uc0NhbGxiYWNrKHJlcSwgZnVuY3Rpb24gKGVyciwgb3B0aW9ucykge1xuICAgICAgICBpZiAoZXJyKSB7XG4gICAgICAgICAgbmV4dChlcnIpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHZhciBjb3JzT3B0aW9ucyA9IGFzc2lnbih7fSwgZGVmYXVsdHMsIG9wdGlvbnMpO1xuICAgICAgICAgIHZhciBvcmlnaW5DYWxsYmFjayA9IG51bGw7XG4gICAgICAgICAgaWYgKGNvcnNPcHRpb25zLm9yaWdpbiAmJiB0eXBlb2YgY29yc09wdGlvbnMub3JpZ2luID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgICAgICBvcmlnaW5DYWxsYmFjayA9IGNvcnNPcHRpb25zLm9yaWdpbjtcbiAgICAgICAgICB9IGVsc2UgaWYgKGNvcnNPcHRpb25zLm9yaWdpbikge1xuICAgICAgICAgICAgb3JpZ2luQ2FsbGJhY2sgPSBmdW5jdGlvbiAob3JpZ2luLCBjYikge1xuICAgICAgICAgICAgICBjYihudWxsLCBjb3JzT3B0aW9ucy5vcmlnaW4pO1xuICAgICAgICAgICAgfTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAob3JpZ2luQ2FsbGJhY2spIHtcbiAgICAgICAgICAgIG9yaWdpbkNhbGxiYWNrKHJlcS5oZWFkZXJzLm9yaWdpbiwgZnVuY3Rpb24gKGVycjIsIG9yaWdpbikge1xuICAgICAgICAgICAgICBpZiAoZXJyMiB8fCAhb3JpZ2luKSB7XG4gICAgICAgICAgICAgICAgbmV4dChlcnIyKTtcbiAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICBjb3JzT3B0aW9ucy5vcmlnaW4gPSBvcmlnaW47XG4gICAgICAgICAgICAgICAgY29ycyhjb3JzT3B0aW9ucywgcmVxLCByZXMsIG5leHQpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgbmV4dCgpO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfTtcbiAgfVxuXG4gIC8vIGNhbiBwYXNzIGVpdGhlciBhbiBvcHRpb25zIGhhc2gsIGFuIG9wdGlvbnMgZGVsZWdhdGUsIG9yIG5vdGhpbmdcbiAgbW9kdWxlLmV4cG9ydHMgPSBtaWRkbGV3YXJlV3JhcHBlcjtcblxufSgpKTtcbiIsIi8qXG5vYmplY3QtYXNzaWduXG4oYykgU2luZHJlIFNvcmh1c1xuQGxpY2Vuc2UgTUlUXG4qL1xuXG4ndXNlIHN0cmljdCc7XG4vKiBlc2xpbnQtZGlzYWJsZSBuby11bnVzZWQtdmFycyAqL1xudmFyIGdldE93blByb3BlcnR5U3ltYm9scyA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eVN5bWJvbHM7XG52YXIgaGFzT3duUHJvcGVydHkgPSBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5O1xudmFyIHByb3BJc0VudW1lcmFibGUgPSBPYmplY3QucHJvdG90eXBlLnByb3BlcnR5SXNFbnVtZXJhYmxlO1xuXG5mdW5jdGlvbiB0b09iamVjdCh2YWwpIHtcblx0aWYgKHZhbCA9PT0gbnVsbCB8fCB2YWwgPT09IHVuZGVmaW5lZCkge1xuXHRcdHRocm93IG5ldyBUeXBlRXJyb3IoJ09iamVjdC5hc3NpZ24gY2Fubm90IGJlIGNhbGxlZCB3aXRoIG51bGwgb3IgdW5kZWZpbmVkJyk7XG5cdH1cblxuXHRyZXR1cm4gT2JqZWN0KHZhbCk7XG59XG5cbmZ1bmN0aW9uIHNob3VsZFVzZU5hdGl2ZSgpIHtcblx0dHJ5IHtcblx0XHRpZiAoIU9iamVjdC5hc3NpZ24pIHtcblx0XHRcdHJldHVybiBmYWxzZTtcblx0XHR9XG5cblx0XHQvLyBEZXRlY3QgYnVnZ3kgcHJvcGVydHkgZW51bWVyYXRpb24gb3JkZXIgaW4gb2xkZXIgVjggdmVyc2lvbnMuXG5cblx0XHQvLyBodHRwczovL2J1Z3MuY2hyb21pdW0ub3JnL3AvdjgvaXNzdWVzL2RldGFpbD9pZD00MTE4XG5cdFx0dmFyIHRlc3QxID0gbmV3IFN0cmluZygnYWJjJyk7ICAvLyBlc2xpbnQtZGlzYWJsZS1saW5lIG5vLW5ldy13cmFwcGVyc1xuXHRcdHRlc3QxWzVdID0gJ2RlJztcblx0XHRpZiAoT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGVzdDEpWzBdID09PSAnNScpIHtcblx0XHRcdHJldHVybiBmYWxzZTtcblx0XHR9XG5cblx0XHQvLyBodHRwczovL2J1Z3MuY2hyb21pdW0ub3JnL3AvdjgvaXNzdWVzL2RldGFpbD9pZD0zMDU2XG5cdFx0dmFyIHRlc3QyID0ge307XG5cdFx0Zm9yICh2YXIgaSA9IDA7IGkgPCAxMDsgaSsrKSB7XG5cdFx0XHR0ZXN0MlsnXycgKyBTdHJpbmcuZnJvbUNoYXJDb2RlKGkpXSA9IGk7XG5cdFx0fVxuXHRcdHZhciBvcmRlcjIgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0ZXN0MikubWFwKGZ1bmN0aW9uIChuKSB7XG5cdFx0XHRyZXR1cm4gdGVzdDJbbl07XG5cdFx0fSk7XG5cdFx0aWYgKG9yZGVyMi5qb2luKCcnKSAhPT0gJzAxMjM0NTY3ODknKSB7XG5cdFx0XHRyZXR1cm4gZmFsc2U7XG5cdFx0fVxuXG5cdFx0Ly8gaHR0cHM6Ly9idWdzLmNocm9taXVtLm9yZy9wL3Y4L2lzc3Vlcy9kZXRhaWw/aWQ9MzA1NlxuXHRcdHZhciB0ZXN0MyA9IHt9O1xuXHRcdCdhYmNkZWZnaGlqa2xtbm9wcXJzdCcuc3BsaXQoJycpLmZvckVhY2goZnVuY3Rpb24gKGxldHRlcikge1xuXHRcdFx0dGVzdDNbbGV0dGVyXSA9IGxldHRlcjtcblx0XHR9KTtcblx0XHRpZiAoT2JqZWN0LmtleXMoT2JqZWN0LmFzc2lnbih7fSwgdGVzdDMpKS5qb2luKCcnKSAhPT1cblx0XHRcdFx0J2FiY2RlZmdoaWprbG1ub3BxcnN0Jykge1xuXHRcdFx0cmV0dXJuIGZhbHNlO1xuXHRcdH1cblxuXHRcdHJldHVybiB0cnVlO1xuXHR9IGNhdGNoIChlcnIpIHtcblx0XHQvLyBXZSBkb24ndCBleHBlY3QgYW55IG9mIHRoZSBhYm92ZSB0byB0aHJvdywgYnV0IGJldHRlciB0byBiZSBzYWZlLlxuXHRcdHJldHVybiBmYWxzZTtcblx0fVxufVxuXG5tb2R1bGUuZXhwb3J0cyA9IHNob3VsZFVzZU5hdGl2ZSgpID8gT2JqZWN0LmFzc2lnbiA6IGZ1bmN0aW9uICh0YXJnZXQsIHNvdXJjZSkge1xuXHR2YXIgZnJvbTtcblx0dmFyIHRvID0gdG9PYmplY3QodGFyZ2V0KTtcblx0dmFyIHN5bWJvbHM7XG5cblx0Zm9yICh2YXIgcyA9IDE7IHMgPCBhcmd1bWVudHMubGVuZ3RoOyBzKyspIHtcblx0XHRmcm9tID0gT2JqZWN0KGFyZ3VtZW50c1tzXSk7XG5cblx0XHRmb3IgKHZhciBrZXkgaW4gZnJvbSkge1xuXHRcdFx0aWYgKGhhc093blByb3BlcnR5LmNhbGwoZnJvbSwga2V5KSkge1xuXHRcdFx0XHR0b1trZXldID0gZnJvbVtrZXldO1xuXHRcdFx0fVxuXHRcdH1cblxuXHRcdGlmIChnZXRPd25Qcm9wZXJ0eVN5bWJvbHMpIHtcblx0XHRcdHN5bWJvbHMgPSBnZXRPd25Qcm9wZXJ0eVN5bWJvbHMoZnJvbSk7XG5cdFx0XHRmb3IgKHZhciBpID0gMDsgaSA8IHN5bWJvbHMubGVuZ3RoOyBpKyspIHtcblx0XHRcdFx0aWYgKHByb3BJc0VudW1lcmFibGUuY2FsbChmcm9tLCBzeW1ib2xzW2ldKSkge1xuXHRcdFx0XHRcdHRvW3N5bWJvbHNbaV1dID0gZnJvbVtzeW1ib2xzW2ldXTtcblx0XHRcdFx0fVxuXHRcdFx0fVxuXHRcdH1cblx0fVxuXG5cdHJldHVybiB0bztcbn07XG4iLCIvKiFcbiAqIHZhcnlcbiAqIENvcHlyaWdodChjKSAyMDE0LTIwMTcgRG91Z2xhcyBDaHJpc3RvcGhlciBXaWxzb25cbiAqIE1JVCBMaWNlbnNlZFxuICovXG5cbid1c2Ugc3RyaWN0J1xuXG4vKipcbiAqIE1vZHVsZSBleHBvcnRzLlxuICovXG5cbm1vZHVsZS5leHBvcnRzID0gdmFyeVxubW9kdWxlLmV4cG9ydHMuYXBwZW5kID0gYXBwZW5kXG5cbi8qKlxuICogUmVnRXhwIHRvIG1hdGNoIGZpZWxkLW5hbWUgaW4gUkZDIDcyMzAgc2VjIDMuMlxuICpcbiAqIGZpZWxkLW5hbWUgICAgPSB0b2tlblxuICogdG9rZW4gICAgICAgICA9IDEqdGNoYXJcbiAqIHRjaGFyICAgICAgICAgPSBcIiFcIiAvIFwiI1wiIC8gXCIkXCIgLyBcIiVcIiAvIFwiJlwiIC8gXCInXCIgLyBcIipcIlxuICogICAgICAgICAgICAgICAvIFwiK1wiIC8gXCItXCIgLyBcIi5cIiAvIFwiXlwiIC8gXCJfXCIgLyBcImBcIiAvIFwifFwiIC8gXCJ+XCJcbiAqICAgICAgICAgICAgICAgLyBESUdJVCAvIEFMUEhBXG4gKiAgICAgICAgICAgICAgIDsgYW55IFZDSEFSLCBleGNlcHQgZGVsaW1pdGVyc1xuICovXG5cbnZhciBGSUVMRF9OQU1FX1JFR0VYUCA9IC9eWyEjJCUmJyorXFwtLl5fYHx+MC05QS1aYS16XSskL1xuXG4vKipcbiAqIEFwcGVuZCBhIGZpZWxkIHRvIGEgdmFyeSBoZWFkZXIuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IGhlYWRlclxuICogQHBhcmFtIHtTdHJpbmd8QXJyYXl9IGZpZWxkXG4gKiBAcmV0dXJuIHtTdHJpbmd9XG4gKiBAcHVibGljXG4gKi9cblxuZnVuY3Rpb24gYXBwZW5kIChoZWFkZXIsIGZpZWxkKSB7XG4gIGlmICh0eXBlb2YgaGVhZGVyICE9PSAnc3RyaW5nJykge1xuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ2hlYWRlciBhcmd1bWVudCBpcyByZXF1aXJlZCcpXG4gIH1cblxuICBpZiAoIWZpZWxkKSB7XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcignZmllbGQgYXJndW1lbnQgaXMgcmVxdWlyZWQnKVxuICB9XG5cbiAgLy8gZ2V0IGZpZWxkcyBhcnJheVxuICB2YXIgZmllbGRzID0gIUFycmF5LmlzQXJyYXkoZmllbGQpXG4gICAgPyBwYXJzZShTdHJpbmcoZmllbGQpKVxuICAgIDogZmllbGRcblxuICAvLyBhc3NlcnQgb24gaW52YWxpZCBmaWVsZCBuYW1lc1xuICBmb3IgKHZhciBqID0gMDsgaiA8IGZpZWxkcy5sZW5ndGg7IGorKykge1xuICAgIGlmICghRklFTERfTkFNRV9SRUdFWFAudGVzdChmaWVsZHNbal0pKSB7XG4gICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdmaWVsZCBhcmd1bWVudCBjb250YWlucyBhbiBpbnZhbGlkIGhlYWRlciBuYW1lJylcbiAgICB9XG4gIH1cblxuICAvLyBleGlzdGluZywgdW5zcGVjaWZpZWQgdmFyeVxuICBpZiAoaGVhZGVyID09PSAnKicpIHtcbiAgICByZXR1cm4gaGVhZGVyXG4gIH1cblxuICAvLyBlbnVtZXJhdGUgY3VycmVudCB2YWx1ZXNcbiAgdmFyIHZhbCA9IGhlYWRlclxuICB2YXIgdmFscyA9IHBhcnNlKGhlYWRlci50b0xvd2VyQ2FzZSgpKVxuXG4gIC8vIHVuc3BlY2lmaWVkIHZhcnlcbiAgaWYgKGZpZWxkcy5pbmRleE9mKCcqJykgIT09IC0xIHx8IHZhbHMuaW5kZXhPZignKicpICE9PSAtMSkge1xuICAgIHJldHVybiAnKidcbiAgfVxuXG4gIGZvciAodmFyIGkgPSAwOyBpIDwgZmllbGRzLmxlbmd0aDsgaSsrKSB7XG4gICAgdmFyIGZsZCA9IGZpZWxkc1tpXS50b0xvd2VyQ2FzZSgpXG5cbiAgICAvLyBhcHBlbmQgdmFsdWUgKGNhc2UtcHJlc2VydmluZylcbiAgICBpZiAodmFscy5pbmRleE9mKGZsZCkgPT09IC0xKSB7XG4gICAgICB2YWxzLnB1c2goZmxkKVxuICAgICAgdmFsID0gdmFsXG4gICAgICAgID8gdmFsICsgJywgJyArIGZpZWxkc1tpXVxuICAgICAgICA6IGZpZWxkc1tpXVxuICAgIH1cbiAgfVxuXG4gIHJldHVybiB2YWxcbn1cblxuLyoqXG4gKiBQYXJzZSBhIHZhcnkgaGVhZGVyIGludG8gYW4gYXJyYXkuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IGhlYWRlclxuICogQHJldHVybiB7QXJyYXl9XG4gKiBAcHJpdmF0ZVxuICovXG5cbmZ1bmN0aW9uIHBhcnNlIChoZWFkZXIpIHtcbiAgdmFyIGVuZCA9IDBcbiAgdmFyIGxpc3QgPSBbXVxuICB2YXIgc3RhcnQgPSAwXG5cbiAgLy8gZ2F0aGVyIHRva2Vuc1xuICBmb3IgKHZhciBpID0gMCwgbGVuID0gaGVhZGVyLmxlbmd0aDsgaSA8IGxlbjsgaSsrKSB7XG4gICAgc3dpdGNoIChoZWFkZXIuY2hhckNvZGVBdChpKSkge1xuICAgICAgY2FzZSAweDIwOiAvKiAgICovXG4gICAgICAgIGlmIChzdGFydCA9PT0gZW5kKSB7XG4gICAgICAgICAgc3RhcnQgPSBlbmQgPSBpICsgMVxuICAgICAgICB9XG4gICAgICAgIGJyZWFrXG4gICAgICBjYXNlIDB4MmM6IC8qICwgKi9cbiAgICAgICAgbGlzdC5wdXNoKGhlYWRlci5zdWJzdHJpbmcoc3RhcnQsIGVuZCkpXG4gICAgICAgIHN0YXJ0ID0gZW5kID0gaSArIDFcbiAgICAgICAgYnJlYWtcbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIGVuZCA9IGkgKyAxXG4gICAgICAgIGJyZWFrXG4gICAgfVxuICB9XG5cbiAgLy8gZmluYWwgdG9rZW5cbiAgbGlzdC5wdXNoKGhlYWRlci5zdWJzdHJpbmcoc3RhcnQsIGVuZCkpXG5cbiAgcmV0dXJuIGxpc3Rcbn1cblxuLyoqXG4gKiBNYXJrIHRoYXQgYSByZXF1ZXN0IGlzIHZhcmllZCBvbiBhIGhlYWRlciBmaWVsZC5cbiAqXG4gKiBAcGFyYW0ge09iamVjdH0gcmVzXG4gKiBAcGFyYW0ge1N0cmluZ3xBcnJheX0gZmllbGRcbiAqIEBwdWJsaWNcbiAqL1xuXG5mdW5jdGlvbiB2YXJ5IChyZXMsIGZpZWxkKSB7XG4gIGlmICghcmVzIHx8ICFyZXMuZ2V0SGVhZGVyIHx8ICFyZXMuc2V0SGVhZGVyKSB7XG4gICAgLy8gcXVhY2sgcXVhY2tcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdyZXMgYXJndW1lbnQgaXMgcmVxdWlyZWQnKVxuICB9XG5cbiAgLy8gZ2V0IGV4aXN0aW5nIGhlYWRlclxuICB2YXIgdmFsID0gcmVzLmdldEhlYWRlcignVmFyeScpIHx8ICcnXG4gIHZhciBoZWFkZXIgPSBBcnJheS5pc0FycmF5KHZhbClcbiAgICA/IHZhbC5qb2luKCcsICcpXG4gICAgOiBTdHJpbmcodmFsKVxuXG4gIC8vIHNldCBuZXcgaGVhZGVyXG4gIGlmICgodmFsID0gYXBwZW5kKGhlYWRlciwgZmllbGQpKSkge1xuICAgIHJlcy5zZXRIZWFkZXIoJ1ZhcnknLCB2YWwpXG4gIH1cbn1cbiIsImV4cG9ydCBjb25zdCBQUk9KRUNUX0lEID0gJzk4N3p5eCc7XG5leHBvcnQgY29uc3QgTE9HXzFfSUQgPSAnYWJjMTIzJztcbmV4cG9ydCBjb25zdCBMT0dfMl9JRCA9ICdkZWY0NTYnO1xuIiwiZXhwb3J0ICogZnJvbSAnLi9jb25zdGFudHMnO1xuZXhwb3J0ICogZnJvbSAnLi90eXBlcyc7XG4iLCJleHBvcnQgdHlwZSBEYXRlTGlrZSA9IERhdGUgfCBzdHJpbmc7XG5cbmV4cG9ydCB0eXBlIExvZ0VudHJ5UmVzcG9uc2UgPSB7XG5cdGlkOiBzdHJpbmc7XG5cdGxvZ0lkOiBzdHJpbmc7XG5cdGxvZ0RhdGU6IERhdGVMaWtlO1xuXHRsb2dWYWx1ZTogbnVtYmVyO1xufTtcblxuZXhwb3J0IHR5cGUgTG9nRW50cnlSZXF1ZXN0ID0ge1xuXHRsb2dEYXRlOiBEYXRlTGlrZTtcblx0bG9nVmFsdWU6IG51bWJlcjtcbn07XG5cbmV4cG9ydCBlbnVtIEh0dHBTdGF0dXNDb2RlIHtcblx0T0sgPSAyMDAsXG5cdENSRUFURUQgPSAyMDEsXG5cdFRFTVBPUkFSWV9SRURJUkVDVCA9IDMwMixcblx0SU5WQUxJRF9SRVFVRVNUID0gNDAwLFxuXHRJTlZBTElEX0NSRURFTlRJQUxTID0gNDAxLFxuXHRVTkFVVEhPUklaRURfUkVRVUVTVCA9IDQwMyxcblx0Tk9UX0ZPVU5EID0gNDA0LFxuXHRDT05GTElDVCA9IDQwOSxcblx0TUlTU0lOR19RVUVSWV9QQVJBTSA9IDQyMixcblx0TUlTU0lOR19EQVRBID0gNDIyLFxuXHRJTlZBTElEX0RBVEEgPSA0MjIsXG5cdFNFUlZFUl9FUlJPUiA9IDUwMCxcblx0VU5JTVBMRU1FTlRFRF9FUlJPUiA9IDUwMSxcbn1cbiIsImltcG9ydCB7XG5cdExvZ0VudHJ5UmVxdWVzdCxcblx0TG9nRW50cnlSZXNwb25zZSxcbn0gZnJvbSAnQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2hhcmVkJztcbmltcG9ydCB7IExvZ0VudHJ5IH0gZnJvbSAnLi4vLi4vZG9tYWluL2VudGl0aWVzL0xvZ0VudHJ5JztcblxuZXhwb3J0IGNsYXNzIExvZ0VudHJpZXNBcGlNYXBwZXIge1xuXHRwdWJsaWMgdG9SZXNwb25zZShsb2dFbnRyeTogTG9nRW50cnkpOiBMb2dFbnRyeVJlc3BvbnNlIHtcblx0XHRyZXR1cm4ge1xuXHRcdFx0aWQ6IGxvZ0VudHJ5LmlkLnRvU3RyaW5nKCksXG5cdFx0XHRsb2dJZDogbG9nRW50cnkubG9nSWQsXG5cdFx0XHRsb2dEYXRlOiBsb2dFbnRyeS5sb2dEYXRlLFxuXHRcdFx0bG9nVmFsdWU6IGxvZ0VudHJ5LmxvZ1ZhbHVlLFxuXHRcdH07XG5cdH1cblxuXHRwdWJsaWMgZnJvbVJlcXVlc3QoXG5cdFx0bG9nSWQ6IHN0cmluZyxcblx0XHRjcmVhdGVMb2dFbnRyeTogTG9nRW50cnlSZXF1ZXN0XG5cdCk6IExvZ0VudHJ5IHtcblx0XHRyZXR1cm4gTG9nRW50cnkuY3JlYXRlKHtcblx0XHRcdGxvZ0lkLFxuXHRcdFx0bG9nRGF0ZTogbmV3IERhdGUoY3JlYXRlTG9nRW50cnkubG9nRGF0ZSksXG5cdFx0XHRsb2dWYWx1ZTogY3JlYXRlTG9nRW50cnkubG9nVmFsdWUsXG5cdFx0fSk7XG5cdH1cbn1cbiIsImltcG9ydCB7XG5cdExvZ0VudHJ5UmVxdWVzdCxcblx0TG9nRW50cnlSZXNwb25zZSxcbn0gZnJvbSAnQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2hhcmVkJztcbmltcG9ydCB7IExvZ0VudHJpZXNRdWVyeVJlcG9zaXRvcnkgfSBmcm9tICcuLi8uLi9wZXJzaXN0ZW5jZS9yZXBvc2l0b3JpZXMvTG9nRW50cmllc1F1ZXJ5UmVwb3NpdG9yeSc7XG5pbXBvcnQgeyBMb2dFbnRyaWVzUmVwb3NpdG9yeSB9IGZyb20gJy4uLy4uL3BlcnNpc3RlbmNlL3JlcG9zaXRvcmllcy9Mb2dFbnRyaWVzUmVwb3NpdG9yeSc7XG5pbXBvcnQgeyBMb2dFbnRyaWVzQXBpTWFwcGVyIH0gZnJvbSAnLi4vbWFwcGVycy9Mb2dFbnRyaWVzQXBpTWFwcGVyJztcblxuZXhwb3J0IGNsYXNzIExvZ0VudHJpZXNTZXJ2aWNlIHtcblx0Z2V0TG9nRW50cmllcyhsb2dJZDogc3RyaW5nKTogUHJvbWlzZTxMb2dFbnRyeVJlc3BvbnNlW10+IHtcblx0XHRjb25zdCBsb2dFbnRyeVJlcG9zaXRvcnkgPSBuZXcgTG9nRW50cmllc1F1ZXJ5UmVwb3NpdG9yeSgpO1xuXHRcdHJldHVybiBsb2dFbnRyeVJlcG9zaXRvcnkuZmluZExvZ0VudHJpZXMobG9nSWQpO1xuXHR9XG5cblx0YXN5bmMgY3JlYXRlTG9nRW50cnkoXG5cdFx0bG9nSWQ6IHN0cmluZyxcblx0XHRjcmVhdGVMb2dFbnRyeTogTG9nRW50cnlSZXF1ZXN0XG5cdCk6IFByb21pc2U8TG9nRW50cnlSZXNwb25zZT4ge1xuXHRcdGNvbnN0IG1hcHBlciA9IG5ldyBMb2dFbnRyaWVzQXBpTWFwcGVyKCk7XG5cdFx0Y29uc3QgbG9nRW50cnkgPSBtYXBwZXIuZnJvbVJlcXVlc3QobG9nSWQsIGNyZWF0ZUxvZ0VudHJ5KTtcblx0XHRjb25zdCByZXBvc2l0b3J5ID0gbmV3IExvZ0VudHJpZXNSZXBvc2l0b3J5KGxvZ0lkKTtcblx0XHRjb25zdCBuZXdFbnRyeSA9IGF3YWl0IHJlcG9zaXRvcnkuY3JlYXRlTG9nRW50cnkobG9nRW50cnkpO1xuXHRcdHJldHVybiBtYXBwZXIudG9SZXNwb25zZShuZXdFbnRyeSk7XG5cdH1cblxuXHRhc3luYyBkZWxldGVMb2dFbnRyeShsb2dJZDogc3RyaW5nLCBsb2dFbnRyeUlkOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuXHRcdGNvbnN0IGxvZ0VudHJ5UmVwb3NpdG9yeSA9IG5ldyBMb2dFbnRyaWVzUmVwb3NpdG9yeShsb2dJZCk7XG5cdFx0Y29uc3QgbG9nRW50cnkgPSBhd2FpdCBsb2dFbnRyeVJlcG9zaXRvcnkuZmluZEJ5SWQobG9nRW50cnlJZCk7XG5cdFx0cmV0dXJuIGxvZ0VudHJ5UmVwb3NpdG9yeS5kZXN0cm95TG9nRW50cnkobG9nRW50cnkpO1xuXHR9XG59XG4iLCJpbXBvcnQgeyBVdWlkIH0gZnJvbSAnLi9VdWlkJztcblxuZXhwb3J0IGNsYXNzIEVudGl0eTxUPiB7XG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuby11bmRlcnNjb3JlLWRhbmdsZVxuICBwcm90ZWN0ZWQgcmVhZG9ubHkgX2lkOiBVdWlkO1xuXG4gIHByb3RlY3RlZCBjb25zdHJ1Y3Rvcihwcm90ZWN0ZWQgcHJvcHM6IFQsIGlkPzogVXVpZCkge1xuICAgIHRoaXMuX2lkID0gaWQgfHwgVXVpZC5jcmVhdGUoKTtcbiAgfVxuXG4gIGdldCBpZCgpOiBVdWlkIHtcbiAgICByZXR1cm4gdGhpcy5faWQ7XG4gIH1cbn1cbiIsImltcG9ydCB7IFZhbGlkYXRpb25FcnJvciB9IGZyb20gJy4uLy4uL3NoYXJlZC9lcnJvcnMnO1xuaW1wb3J0IHsgRW50aXR5IH0gZnJvbSAnLi9FbnRpdHknO1xuaW1wb3J0IHsgVXVpZCB9IGZyb20gJy4vVXVpZCc7XG5cbmludGVyZmFjZSBMb2dFbnRyeVByb3BzIHtcbiAgbG9nRGF0ZTogRGF0ZTtcbiAgbG9nVmFsdWU6IG51bWJlcjtcbiAgbG9nSWQ6IHN0cmluZztcbn1cblxudHlwZSBDcmVhdGVMb2dFbnRyeVByb3BzID0gTG9nRW50cnlQcm9wcztcblxuZXhwb3J0IGNsYXNzIExvZ0VudHJ5IGV4dGVuZHMgRW50aXR5PExvZ0VudHJ5UHJvcHM+IHtcbiAgc3RhdGljIGNyZWF0ZUZyb21QZXJzaXN0ZW5jZShwcm9wczogTG9nRW50cnlQcm9wcywgaWQ6IHN0cmluZykge1xuICAgIHJldHVybiBuZXcgTG9nRW50cnkocHJvcHMsIFV1aWQuY3JlYXRlKGlkKSk7XG4gIH1cblxuICBzdGF0aWMgY3JlYXRlKGNyZWF0ZUxvZ0VudHJ5UHJvcHM6IENyZWF0ZUxvZ0VudHJ5UHJvcHMpIHtcbiAgICBpZiAoIXRoaXMuaXNWYWxpZChjcmVhdGVMb2dFbnRyeVByb3BzKSkge1xuICAgICAgdGhyb3cgbmV3IFZhbGlkYXRpb25FcnJvcihcbiAgICAgICAgJ0Nhbm5vdCBjcmVhdGUgbG9nIGVudHJ5LiBQcm9wcyBhcmUgbm90IHZhbGlkLicsXG4gICAgICApO1xuICAgIH1cbiAgICByZXR1cm4gbmV3IExvZ0VudHJ5KGNyZWF0ZUxvZ0VudHJ5UHJvcHMpO1xuICB9XG5cbiAgcHJpdmF0ZSBzdGF0aWMgaXNWYWxpZChjcmVhdGVMb2dFbnRyeVByb3BzOiBDcmVhdGVMb2dFbnRyeVByb3BzKTogYm9vbGVhbiB7XG4gICAgcmV0dXJuIHR5cGVvZiBjcmVhdGVMb2dFbnRyeVByb3BzLmxvZ1ZhbHVlID09PSAnbnVtYmVyJztcbiAgfVxuXG4gIGdldCBsb2dEYXRlKCkge1xuICAgIHJldHVybiB0aGlzLnByb3BzLmxvZ0RhdGU7XG4gIH1cblxuICBnZXQgbG9nVmFsdWUoKSB7XG4gICAgcmV0dXJuIHRoaXMucHJvcHMubG9nVmFsdWU7XG4gIH1cblxuICBnZXQgbG9nSWQoKSB7XG4gICAgcmV0dXJuIHRoaXMucHJvcHMubG9nSWQ7XG4gIH1cbn1cbiIsImltcG9ydCBjcnlwdG8gZnJvbSAnY3J5cHRvJztcblxuZXhwb3J0IGNsYXNzIFV1aWQge1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbm8tdW5kZXJzY29yZS1kYW5nbGVcbiAgcHJpdmF0ZSByZWFkb25seSBfaWQ6IHN0cmluZztcblxuICBwcm90ZWN0ZWQgY29uc3RydWN0b3IoaWQ6IHN0cmluZykge1xuICAgIHRoaXMuX2lkID0gaWQ7XG4gIH1cblxuICBwdWJsaWMgZ2V0IHZhbHVlKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIHRoaXMuX2lkO1xuICB9XG5cbiAgcHVibGljIHRvU3RyaW5nKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIHRoaXMudmFsdWU7XG4gIH1cblxuICBwdWJsaWMgZXF1YWxzKGlkPzogVXVpZCB8IHN0cmluZyk6IGJvb2xlYW4ge1xuICAgIGlmIChpZCBpbnN0YW5jZW9mIFV1aWQpIHtcbiAgICAgIHJldHVybiBpZC52YWx1ZSA9PT0gdGhpcy52YWx1ZTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBpZCA9PT0gJ3N0cmluZycpIHtcbiAgICAgIHJldHVybiBpZCA9PT0gdGhpcy5faWQ7XG4gICAgfVxuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuXG4gIHB1YmxpYyBzdGF0aWMgY3JlYXRlKGdpdmVuSWQ/OiBzdHJpbmcgfCBudWxsKTogVXVpZCB7XG4gICAgaWYgKCFnaXZlbklkKSByZXR1cm4gbmV3IFV1aWQoY3J5cHRvLnJhbmRvbVVVSUQoKSk7XG4gICAgLy8gd2UgZG9uJ3QgdmFsaWRhdGUgdGhhdCBpdCdzIGEgcHJvcGVyIHV1aWQgc28gd2UgY2FuIHN1cHBvcnQgY29tcG9zaXRlIElEc1xuICAgIHJldHVybiBuZXcgVXVpZChnaXZlbklkKTtcbiAgfVxuXG4gIHB1YmxpYyBzdGF0aWMgaXNWYWxpZChnaXZlbklkOiBzdHJpbmcpOiBib29sZWFuIHtcbiAgICByZXR1cm4gL15bMC05YS1mXXs4fS1bMC05YS1mXXs0fS1bMS01XVswLTlhLWZdezN9LVs4OWFiXVswLTlhLWZdezN9LVswLTlhLWZdezEyfSQvaS50ZXN0KFxuICAgICAgZ2l2ZW5JZCxcbiAgICApO1xuICB9XG59XG4iLCJpbXBvcnQgeyBMb2dFbnRyeSB9IGZyb20gJy4uLy4uL2RvbWFpbi9lbnRpdGllcy9Mb2dFbnRyeSc7XG5pbXBvcnQgeyBMb2dFbnRyaWVzUmVjb3JkIH0gZnJvbSAnLi4vLi4vc2hhcmVkL2RhdGFiYXNlJztcblxuZXhwb3J0IGNsYXNzIExvZ0VudHJpZXNQZXJzaXN0ZW5jZU1hcHBlciB7XG4gIHN0YXRpYyB0b1BlcnNpc3RlbmNlKGxvZ0VudHJ5OiBMb2dFbnRyeSk6IExvZ0VudHJpZXNSZWNvcmQge1xuICAgIHJldHVybiB7XG4gICAgICBpZDogbG9nRW50cnkuaWQudG9TdHJpbmcoKSxcbiAgICAgIGxvZ0lkOiBsb2dFbnRyeS5sb2dJZCxcbiAgICAgIGxvZ0RhdGU6IGxvZ0VudHJ5LmxvZ0RhdGUsXG4gICAgICBsb2dWYWx1ZTogbG9nRW50cnkubG9nVmFsdWUsXG4gICAgfTtcbiAgfVxuXG4gIHN0YXRpYyBmcm9tUGVyc2lzdGVuY2UobG9nRW50cmllc1JlY29yZDogTG9nRW50cmllc1JlY29yZCk6IExvZ0VudHJ5IHtcbiAgICByZXR1cm4gTG9nRW50cnkuY3JlYXRlRnJvbVBlcnNpc3RlbmNlKFxuICAgICAgbG9nRW50cmllc1JlY29yZCxcbiAgICAgIGxvZ0VudHJpZXNSZWNvcmQuaWQsXG4gICAgKTtcbiAgfVxufVxuIiwiaW1wb3J0IHsgRGF0YWJhc2UsIExvZ0VudHJpZXNSZWNvcmQgfSBmcm9tICcuLi8uLi9zaGFyZWQvZGF0YWJhc2UnO1xuXG5leHBvcnQgY2xhc3MgTG9nRW50cmllc1F1ZXJ5UmVwb3NpdG9yeSB7XG4gIGFzeW5jIGZpbmRMb2dFbnRyaWVzKGxvZ0lkOiBzdHJpbmcpOiBQcm9taXNlPExvZ0VudHJpZXNSZWNvcmRbXT4ge1xuICAgIHJldHVybiBEYXRhYmFzZS5nZXRBbGxMb2dFbnRyaWVzKGxvZ0lkKTtcbiAgfVxufVxuIiwiaW1wb3J0IHsgTG9nRW50cnkgfSBmcm9tICcuLi8uLi9kb21haW4vZW50aXRpZXMvTG9nRW50cnknO1xuaW1wb3J0IHsgRGF0YWJhc2UgfSBmcm9tICcuLi8uLi9zaGFyZWQvZGF0YWJhc2UnO1xuaW1wb3J0IHsgUmVjb3JkTm90Rm91bmRFcnJvciB9IGZyb20gJy4uLy4uL3NoYXJlZC9lcnJvcnMnO1xuaW1wb3J0IHsgTG9nRW50cmllc1BlcnNpc3RlbmNlTWFwcGVyIH0gZnJvbSAnLi4vbWFwcGVycy9Mb2dFbnRyaWVzUGVyc2lzdGVuY2VNYXBwZXInO1xuXG5leHBvcnQgY2xhc3MgTG9nRW50cmllc1JlcG9zaXRvcnkge1xuICBjb25zdHJ1Y3Rvcihwcm90ZWN0ZWQgbG9nSWQ6IHN0cmluZykge31cblxuICBhc3luYyBjcmVhdGVMb2dFbnRyeShsb2dFbnRyeTogTG9nRW50cnkpOiBQcm9taXNlPExvZ0VudHJ5PiB7XG4gICAgY29uc3QgZHRvID0gTG9nRW50cmllc1BlcnNpc3RlbmNlTWFwcGVyLnRvUGVyc2lzdGVuY2UobG9nRW50cnkpO1xuICAgIGF3YWl0IERhdGFiYXNlLmNyZWF0ZUxvZ0VudHJ5KGR0byk7XG4gICAgcmV0dXJuIGxvZ0VudHJ5O1xuICB9XG5cbiAgYXN5bmMgZmluZEJ5SWQobG9nRW50cnlJZDogc3RyaW5nKTogUHJvbWlzZTxMb2dFbnRyeT4ge1xuICAgIGNvbnN0IHJlY29yZCA9IGF3YWl0IERhdGFiYXNlLmZpbmRCeUlkKGxvZ0VudHJ5SWQpO1xuICAgIGlmICghcmVjb3JkKSB7XG4gICAgICB0aHJvdyBuZXcgUmVjb3JkTm90Rm91bmRFcnJvcihcbiAgICAgICAgYGxvZyBlbnRyeSBub3QgZm91bmQgZm9yIGlkOiAke2xvZ0VudHJ5SWR9YCxcbiAgICAgICk7XG4gICAgfVxuICAgIHJldHVybiBMb2dFbnRyaWVzUGVyc2lzdGVuY2VNYXBwZXIuZnJvbVBlcnNpc3RlbmNlKHJlY29yZCk7XG4gIH1cblxuICBhc3luYyBkZXN0cm95TG9nRW50cnkobG9nRW50cnk6IExvZ0VudHJ5KTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICBhd2FpdCBEYXRhYmFzZS5kZWxldGVMb2dFbnRyeShsb2dFbnRyeS5pZC52YWx1ZSk7XG4gICAgcmV0dXJuIGxvZ0VudHJ5LmlkLnZhbHVlO1xuICB9XG59XG4iLCJpbXBvcnQgeyBIdHRwU3RhdHVzQ29kZSB9IGZyb20gJ0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNoYXJlZCc7XG5pbXBvcnQgeyBSb3V0ZXIgfSBmcm9tICdleHByZXNzJztcbmltcG9ydCB7IExvZ0VudHJpZXNTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vYXBwbGljYXRpb24vc2VydmljZXMvTG9nRW50cmllc1NlcnZpY2UnO1xuaW1wb3J0IHsgUmVjb3JkTm90Rm91bmRFcnJvciwgVmFsaWRhdGlvbkVycm9yIH0gZnJvbSAnLi4vLi4vc2hhcmVkL2Vycm9ycyc7XG5cbmV4cG9ydCBjb25zdCBsb2dFbnRyaWVzQ29udHJvbGxlciA9IFJvdXRlcigpO1xuXG5sb2dFbnRyaWVzQ29udHJvbGxlci5nZXQoJy9sb2dzLzpsb2dJZC9sb2ctZW50cmllcycsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuXHRjb25zdCB7IGxvZ0lkIH0gPSByZXEucGFyYW1zO1xuXHRjb25zdCBsb2dFbnRyeVNlcnZpY2UgPSBuZXcgTG9nRW50cmllc1NlcnZpY2UoKTtcblx0Y29uc3QgbG9nRW50cmllcyA9IGF3YWl0IGxvZ0VudHJ5U2VydmljZS5nZXRMb2dFbnRyaWVzKGxvZ0lkKTtcblx0cmVzLmpzb24obG9nRW50cmllcyk7XG59KTtcblxubG9nRW50cmllc0NvbnRyb2xsZXIucG9zdCgnL2xvZ3MvOmxvZ0lkL2xvZy1lbnRyaWVzJywgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG5cdGNvbnN0IHsgbG9nSWQgfSA9IHJlcS5wYXJhbXM7XG5cdGNvbnN0IHsgbG9nRW50cnkgfSA9IHJlcS5ib2R5O1xuXHRjb25zdCBsb2dFbnRyeVNlcnZpY2UgPSBuZXcgTG9nRW50cmllc1NlcnZpY2UoKTtcblx0dHJ5IHtcblx0XHRjb25zdCBsb2dFbnRyaWVzID0gYXdhaXQgbG9nRW50cnlTZXJ2aWNlLmNyZWF0ZUxvZ0VudHJ5KFxuXHRcdFx0bG9nSWQsXG5cdFx0XHRsb2dFbnRyeVxuXHRcdCk7XG5cdFx0cmVzLmpzb24obG9nRW50cmllcyk7XG5cdH0gY2F0Y2ggKGU6IHVua25vd24pIHtcblx0XHRpZiAoZSBpbnN0YW5jZW9mIFZhbGlkYXRpb25FcnJvcikge1xuXHRcdFx0cmVzLnN0YXR1cyhIdHRwU3RhdHVzQ29kZS5JTlZBTElEX0RBVEEpO1xuXHRcdFx0cmVzLnNlbmQoZS50b1N0cmluZygpKTtcblx0XHR9IGVsc2Uge1xuXHRcdFx0cmVzLnN0YXR1cyhIdHRwU3RhdHVzQ29kZS5TRVJWRVJfRVJST1IpO1xuXHRcdFx0cmVzLnNlbmQoKTtcblx0XHR9XG5cdH1cbn0pO1xuXG5sb2dFbnRyaWVzQ29udHJvbGxlci5kZWxldGUoXG5cdCcvbG9ncy86bG9nSWQvbG9nLWVudHJpZXMvOmxvZ0VudHJ5SWQnLFxuXHRhc3luYyAocmVxLCByZXMpID0+IHtcblx0XHRjb25zdCB7IGxvZ0lkLCBsb2dFbnRyeUlkIH0gPSByZXEucGFyYW1zO1xuXHRcdGNvbnN0IGxvZ0VudHJ5U2VydmljZSA9IG5ldyBMb2dFbnRyaWVzU2VydmljZSgpO1xuXHRcdHRyeSB7XG5cdFx0XHRjb25zdCBsb2dFbnRyaWVzID0gYXdhaXQgbG9nRW50cnlTZXJ2aWNlLmRlbGV0ZUxvZ0VudHJ5KFxuXHRcdFx0XHRsb2dJZCxcblx0XHRcdFx0bG9nRW50cnlJZFxuXHRcdFx0KTtcblx0XHRcdHJlcy5qc29uKGxvZ0VudHJpZXMpO1xuXHRcdH0gY2F0Y2ggKGU6IHVua25vd24pIHtcblx0XHRcdGlmIChlIGluc3RhbmNlb2YgUmVjb3JkTm90Rm91bmRFcnJvcikge1xuXHRcdFx0XHRyZXMuc3RhdHVzKEh0dHBTdGF0dXNDb2RlLklOVkFMSURfREFUQSk7XG5cdFx0XHRcdHJlcy5zZW5kKGUudG9TdHJpbmcoKSk7XG5cdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHRyZXMuc3RhdHVzKEh0dHBTdGF0dXNDb2RlLlNFUlZFUl9FUlJPUik7XG5cdFx0XHRcdHJlcy5zZW5kKCk7XG5cdFx0XHR9XG5cdFx0XHRyZXMuanNvbigpO1xuXHRcdH1cblx0fVxuKTtcbiIsImltcG9ydCB7IExPR18xX0lELCBMT0dfMl9JRCB9IGZyb20gJ0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNoYXJlZCc7XG5pbXBvcnQgY3J5cHRvIGZyb20gJ2NyeXB0byc7XG5pbXBvcnQgZnMgZnJvbSAnZnMnO1xuXG5leHBvcnQgdHlwZSBMb2dFbnRyaWVzUmVjb3JkID0ge1xuICBpZDogc3RyaW5nO1xuICBsb2dJZDogc3RyaW5nO1xuICBsb2dEYXRlOiBEYXRlO1xuICBsb2dWYWx1ZTogbnVtYmVyO1xufTtcblxuY29uc3QgTE9HX0VOVFJJRVNfVEFCTEVfU0VFRDogTG9nRW50cmllc1JlY29yZFtdID0gW1xuICB7XG4gICAgaWQ6IGNyeXB0by5yYW5kb21VVUlEKCkudG9TdHJpbmcoKSxcbiAgICBsb2dJZDogTE9HXzFfSUQsXG4gICAgbG9nRGF0ZTogbmV3IERhdGUoJzIwMjQtMDEtMDEnKSxcbiAgICBsb2dWYWx1ZTogNSxcbiAgfSxcbiAge1xuICAgIGlkOiBjcnlwdG8ucmFuZG9tVVVJRCgpLnRvU3RyaW5nKCksXG4gICAgbG9nSWQ6IExPR18xX0lELFxuICAgIGxvZ0RhdGU6IG5ldyBEYXRlKCcyMDI0LTAxLTAyJyksXG4gICAgbG9nVmFsdWU6IDE1LFxuICB9LFxuICB7XG4gICAgaWQ6IGNyeXB0by5yYW5kb21VVUlEKCkudG9TdHJpbmcoKSxcbiAgICBsb2dJZDogTE9HXzFfSUQsXG4gICAgbG9nRGF0ZTogbmV3IERhdGUoJzIwMjQtMDEtMDMnKSxcbiAgICBsb2dWYWx1ZTogMjMsXG4gIH0sXG4gIHtcbiAgICBpZDogY3J5cHRvLnJhbmRvbVVVSUQoKS50b1N0cmluZygpLFxuICAgIGxvZ0lkOiBMT0dfMl9JRCxcbiAgICBsb2dEYXRlOiBuZXcgRGF0ZSgnMjAyNC0wMS0wMScpLFxuICAgIGxvZ1ZhbHVlOiAxNSxcbiAgfSxcbl07XG5cbmNvbnN0IEZJTEVfTkFNRSA9ICdkYXRhYmFzZSc7XG5cbmV4cG9ydCBjbGFzcyBEYXRhYmFzZSB7XG4gIHB1YmxpYyBzdGF0aWMgYXN5bmMgZ2V0QWxsTG9nRW50cmllcyhsb2dJZDogc3RyaW5nKSB7XG4gICAgbGV0IGFsbEVudHJpZXM7XG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IHRoaXMuc2ltdWxhdGVEYlNsb3duZXNzKCk7XG4gICAgICBjb25zdCBkYiA9IGF3YWl0IGZzLnJlYWRGaWxlU3luYyhGSUxFX05BTUUsICd1dGY4Jyk7XG4gICAgICBhbGxFbnRyaWVzID0gSlNPTi5wYXJzZShkYikgYXMgTG9nRW50cmllc1JlY29yZFtdO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGF3YWl0IGZzLndyaXRlRmlsZVN5bmMoRklMRV9OQU1FLCBKU09OLnN0cmluZ2lmeShMT0dfRU5UUklFU19UQUJMRV9TRUVEKSk7XG4gICAgICBhbGxFbnRyaWVzID0gTE9HX0VOVFJJRVNfVEFCTEVfU0VFRDtcbiAgICB9XG4gICAgcmV0dXJuIGFsbEVudHJpZXMuZmlsdGVyKChsZSkgPT4gbGUubG9nSWQgPT09IGxvZ0lkKTtcbiAgfVxuXG4gIHB1YmxpYyBzdGF0aWMgYXN5bmMgY3JlYXRlTG9nRW50cnkoZW50cnk6IExvZ0VudHJpZXNSZWNvcmQpIHtcbiAgICBhd2FpdCB0aGlzLnNpbXVsYXRlRGJTbG93bmVzcygpO1xuICAgIGNvbnN0IGRiID0gYXdhaXQgZnMucmVhZEZpbGVTeW5jKEZJTEVfTkFNRSwgJ3V0ZjgnKTtcbiAgICBjb25zdCBhbGxFbnRyaWVzID0gSlNPTi5wYXJzZShkYik7XG4gICAgYWxsRW50cmllcy5wdXNoKGVudHJ5KTtcbiAgICBhd2FpdCBmcy53cml0ZUZpbGVTeW5jKEZJTEVfTkFNRSwgSlNPTi5zdHJpbmdpZnkoYWxsRW50cmllcykpO1xuICAgIHJldHVybiBlbnRyeTtcbiAgfVxuXG4gIHB1YmxpYyBzdGF0aWMgYXN5bmMgZmluZEJ5SWQoXG4gICAgbG9nRW50cnlJZDogc3RyaW5nLFxuICApOiBQcm9taXNlPExvZ0VudHJpZXNSZWNvcmQgfCBudWxsPiB7XG4gICAgYXdhaXQgdGhpcy5zaW11bGF0ZURiU2xvd25lc3MoKTtcbiAgICBjb25zdCBkYiA9IGF3YWl0IGZzLnJlYWRGaWxlU3luYyhGSUxFX05BTUUsICd1dGY4Jyk7XG4gICAgY29uc3QgYWxsRW50cmllcyA9IEpTT04ucGFyc2UoZGIpIGFzIExvZ0VudHJpZXNSZWNvcmRbXTtcbiAgICByZXR1cm4gYWxsRW50cmllcy5maW5kKChsZSkgPT4gbGUuaWQgPT09IGxvZ0VudHJ5SWQpIHx8IG51bGw7XG4gIH1cblxuICBwdWJsaWMgc3RhdGljIGFzeW5jIGRlbGV0ZUxvZ0VudHJ5KGxvZ0VudHJ5SWQ6IHN0cmluZykge1xuICAgIGF3YWl0IHRoaXMuc2ltdWxhdGVEYlNsb3duZXNzKCk7XG4gICAgY29uc3QgZGIgPSBhd2FpdCBmcy5yZWFkRmlsZVN5bmMoRklMRV9OQU1FLCAndXRmOCcpO1xuICAgIGNvbnN0IGFsbEVudHJpZXMgPSBKU09OLnBhcnNlKGRiKSBhcyBMb2dFbnRyaWVzUmVjb3JkW107XG4gICAgY29uc3QgaW5kZXggPSBhbGxFbnRyaWVzLmZpbmRJbmRleCgobGUpID0+IGxlLmlkID09PSBsb2dFbnRyeUlkKTtcbiAgICBhbGxFbnRyaWVzLnNwbGljZShpbmRleCwgMSk7XG4gICAgYXdhaXQgZnMud3JpdGVGaWxlU3luYyhGSUxFX05BTUUsIEpTT04uc3RyaW5naWZ5KGFsbEVudHJpZXMpKTtcbiAgICByZXR1cm4gbG9nRW50cnlJZDtcbiAgfVxuXG4gIHByaXZhdGUgc3RhdGljIHNpbXVsYXRlRGJTbG93bmVzcyhtcyA9IDEwMDApIHtcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUpID0+IHtcbiAgICAgIHNldFRpbWVvdXQocmVzb2x2ZSwgbXMpO1xuICAgIH0pO1xuICB9XG59XG4iLCIvKiBlc2xpbnQtZGlzYWJsZSBtYXgtY2xhc3Nlcy1wZXItZmlsZSAqL1xuXG5leHBvcnQgY2xhc3MgUmVjb3JkTm90Rm91bmRFcnJvciBleHRlbmRzIEVycm9yIHt9XG5cbmV4cG9ydCBjbGFzcyBWYWxpZGF0aW9uRXJyb3IgZXh0ZW5kcyBFcnJvciB7fVxuIiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiY3J5cHRvXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcImV4cHJlc3NcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiZnNcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiaHR0cFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJtb3JnYW5cIik7IiwiLy8gVGhlIG1vZHVsZSBjYWNoZVxudmFyIF9fd2VicGFja19tb2R1bGVfY2FjaGVfXyA9IHt9O1xuXG4vLyBUaGUgcmVxdWlyZSBmdW5jdGlvblxuZnVuY3Rpb24gX193ZWJwYWNrX3JlcXVpcmVfXyhtb2R1bGVJZCkge1xuXHQvLyBDaGVjayBpZiBtb2R1bGUgaXMgaW4gY2FjaGVcblx0dmFyIGNhY2hlZE1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF07XG5cdGlmIChjYWNoZWRNb2R1bGUgIT09IHVuZGVmaW5lZCkge1xuXHRcdHJldHVybiBjYWNoZWRNb2R1bGUuZXhwb3J0cztcblx0fVxuXHQvLyBDcmVhdGUgYSBuZXcgbW9kdWxlIChhbmQgcHV0IGl0IGludG8gdGhlIGNhY2hlKVxuXHR2YXIgbW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXSA9IHtcblx0XHQvLyBubyBtb2R1bGUuaWQgbmVlZGVkXG5cdFx0Ly8gbm8gbW9kdWxlLmxvYWRlZCBuZWVkZWRcblx0XHRleHBvcnRzOiB7fVxuXHR9O1xuXG5cdC8vIEV4ZWN1dGUgdGhlIG1vZHVsZSBmdW5jdGlvblxuXHRfX3dlYnBhY2tfbW9kdWxlc19fW21vZHVsZUlkXShtb2R1bGUsIG1vZHVsZS5leHBvcnRzLCBfX3dlYnBhY2tfcmVxdWlyZV9fKTtcblxuXHQvLyBSZXR1cm4gdGhlIGV4cG9ydHMgb2YgdGhlIG1vZHVsZVxuXHRyZXR1cm4gbW9kdWxlLmV4cG9ydHM7XG59XG5cbiIsIi8vIGdldERlZmF1bHRFeHBvcnQgZnVuY3Rpb24gZm9yIGNvbXBhdGliaWxpdHkgd2l0aCBub24taGFybW9ueSBtb2R1bGVzXG5fX3dlYnBhY2tfcmVxdWlyZV9fLm4gPSAobW9kdWxlKSA9PiB7XG5cdHZhciBnZXR0ZXIgPSBtb2R1bGUgJiYgbW9kdWxlLl9fZXNNb2R1bGUgP1xuXHRcdCgpID0+IChtb2R1bGVbJ2RlZmF1bHQnXSkgOlxuXHRcdCgpID0+IChtb2R1bGUpO1xuXHRfX3dlYnBhY2tfcmVxdWlyZV9fLmQoZ2V0dGVyLCB7IGE6IGdldHRlciB9KTtcblx0cmV0dXJuIGdldHRlcjtcbn07IiwiLy8gZGVmaW5lIGdldHRlciBmdW5jdGlvbnMgZm9yIGhhcm1vbnkgZXhwb3J0c1xuX193ZWJwYWNrX3JlcXVpcmVfXy5kID0gKGV4cG9ydHMsIGRlZmluaXRpb24pID0+IHtcblx0Zm9yKHZhciBrZXkgaW4gZGVmaW5pdGlvbikge1xuXHRcdGlmKF9fd2VicGFja19yZXF1aXJlX18ubyhkZWZpbml0aW9uLCBrZXkpICYmICFfX3dlYnBhY2tfcmVxdWlyZV9fLm8oZXhwb3J0cywga2V5KSkge1xuXHRcdFx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIGtleSwgeyBlbnVtZXJhYmxlOiB0cnVlLCBnZXQ6IGRlZmluaXRpb25ba2V5XSB9KTtcblx0XHR9XG5cdH1cbn07IiwiX193ZWJwYWNrX3JlcXVpcmVfXy5vID0gKG9iaiwgcHJvcCkgPT4gKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChvYmosIHByb3ApKSIsIi8vIGRlZmluZSBfX2VzTW9kdWxlIG9uIGV4cG9ydHNcbl9fd2VicGFja19yZXF1aXJlX18uciA9IChleHBvcnRzKSA9PiB7XG5cdGlmKHR5cGVvZiBTeW1ib2wgIT09ICd1bmRlZmluZWQnICYmIFN5bWJvbC50b1N0cmluZ1RhZykge1xuXHRcdE9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBTeW1ib2wudG9TdHJpbmdUYWcsIHsgdmFsdWU6ICdNb2R1bGUnIH0pO1xuXHR9XG5cdE9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCAnX19lc01vZHVsZScsIHsgdmFsdWU6IHRydWUgfSk7XG59OyIsImltcG9ydCBjb29raWVQYXJzZXIgZnJvbSAnY29va2llLXBhcnNlcic7XG5pbXBvcnQgY29ycyBmcm9tICdjb3JzJztcbmltcG9ydCBleHByZXNzIGZyb20gJ2V4cHJlc3MnO1xuaW1wb3J0IGh0dHAgZnJvbSAnaHR0cCc7XG5pbXBvcnQgbG9nZ2VyIGZyb20gJ21vcmdhbic7XG5pbXBvcnQgeyBsb2dFbnRyaWVzQ29udHJvbGxlciB9IGZyb20gJy4vcHJlc2VudGF0aW9uL2NvbnRyb2xsZXJzL2xvZ0VudHJpZXNDb250cm9sbGVyJztcblxuZXhwb3J0IGNvbnN0IGFwcCA9IGV4cHJlc3MoKTtcblxuYXBwLnVzZShsb2dnZXIoJ2RldicpKTtcbmFwcC51c2UoZXhwcmVzcy5qc29uKCkpO1xuYXBwLnVzZShleHByZXNzLnVybGVuY29kZWQoeyBleHRlbmRlZDogZmFsc2UgfSkpO1xuYXBwLnVzZShjb29raWVQYXJzZXIoKSk7XG5hcHAudXNlKGNvcnMoeyBvcmlnaW46ICdodHRwOi8vbG9jYWxob3N0OjMwMDEnIH0pKTtcbmFwcC51c2UoJy9hcGknLCBsb2dFbnRyaWVzQ29udHJvbGxlcik7XG5cbi8qKlxuICogTm9ybWFsaXplIGEgcG9ydCBpbnRvIGEgbnVtYmVyLCBzdHJpbmcsIG9yIGZhbHNlLlxuICovXG5cbmZ1bmN0aW9uIG5vcm1hbGl6ZVBvcnQodmFsOiBzdHJpbmcpIHtcbiAgY29uc3QgcG9ydCA9IHBhcnNlSW50KHZhbCwgMTApO1xuXG4gIGlmIChOdW1iZXIuaXNOYU4ocG9ydCkpIHtcbiAgICAvLyBuYW1lZCBwaXBlXG4gICAgcmV0dXJuIHZhbDtcbiAgfVxuXG4gIGlmIChwb3J0ID49IDApIHtcbiAgICAvLyBwb3J0IG51bWJlclxuICAgIHJldHVybiBwb3J0O1xuICB9XG5cbiAgcmV0dXJuIGZhbHNlO1xufVxuXG4vKipcbiAqIEdldCBwb3J0IGZyb20gZW52aXJvbm1lbnQgYW5kIHN0b3JlIGluIEV4cHJlc3MuXG4gKi9cblxuY29uc3QgcG9ydCA9IG5vcm1hbGl6ZVBvcnQocHJvY2Vzcy5lbnYuUE9SVCB8fCAnMzAwMCcpO1xuYXBwLnNldCgncG9ydCcsIHBvcnQpO1xuXG4vKipcbiAqIENyZWF0ZSBIVFRQIHNlcnZlci5cbiAqL1xuXG5jb25zdCBzZXJ2ZXIgPSBodHRwLmNyZWF0ZVNlcnZlcihhcHApO1xuXG4vKipcbiAqIEV2ZW50IGxpc3RlbmVyIGZvciBIVFRQIHNlcnZlciBcImVycm9yXCIgZXZlbnQuXG4gKi9cblxuZnVuY3Rpb24gb25FcnJvcihlcnJvcjogTm9kZUpTLkVycm5vRXhjZXB0aW9uKSB7XG4gIGlmIChlcnJvci5zeXNjYWxsICE9PSAnbGlzdGVuJykge1xuICAgIHRocm93IGVycm9yO1xuICB9XG5cbiAgY29uc3QgYmluZCA9IHR5cGVvZiBwb3J0ID09PSAnc3RyaW5nJyA/IGBQaXBlICR7cG9ydH1gIDogYFBvcnQgJHtwb3J0fWA7XG5cbiAgLy8gaGFuZGxlIHNwZWNpZmljIGxpc3RlbiBlcnJvcnMgd2l0aCBmcmllbmRseSBtZXNzYWdlc1xuICBzd2l0Y2ggKGVycm9yLmNvZGUpIHtcbiAgICBjYXNlICdFQUNDRVMnOlxuICAgICAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG5vLWNvbnNvbGVcbiAgICAgIGNvbnNvbGUuZXJyb3IoYCR7YmluZH0gcmVxdWlyZXMgZWxldmF0ZWQgcHJpdmlsZWdlc2ApO1xuICAgICAgcHJvY2Vzcy5leGl0KDEpO1xuICAgICAgYnJlYWs7XG4gICAgY2FzZSAnRUFERFJJTlVTRSc6XG4gICAgICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbm8tY29uc29sZVxuICAgICAgY29uc29sZS5lcnJvcihgJHtiaW5kfSBpcyBhbHJlYWR5IGluIHVzZWApO1xuICAgICAgcHJvY2Vzcy5leGl0KDEpO1xuICAgICAgYnJlYWs7XG4gICAgZGVmYXVsdDpcbiAgICAgIHRocm93IGVycm9yO1xuICB9XG59XG5cbi8qKlxuICogRXZlbnQgbGlzdGVuZXIgZm9yIEhUVFAgc2VydmVyIFwibGlzdGVuaW5nXCIgZXZlbnQuXG4gKi9cblxuZnVuY3Rpb24gb25MaXN0ZW5pbmcoKSB7XG4gIGNvbnN0IGFkZHIgPSBzZXJ2ZXIuYWRkcmVzcygpO1xuICBjb25zdCBiaW5kID0gdHlwZW9mIGFkZHIgPT09ICdzdHJpbmcnID8gYHBpcGUgJHthZGRyfWAgOiBgcG9ydCAke2FkZHI/LnBvcnR9YDtcbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG5vLWNvbnNvbGVcbiAgY29uc29sZS5sb2coYExpc3RlbmluZyBvbiAke2JpbmR9YCk7XG59XG5cbi8qKlxuICogTGlzdGVuIG9uIHByb3ZpZGVkIHBvcnQsIG9uIGFsbCBuZXR3b3JrIGludGVyZmFjZXMuXG4gKi9cblxuc2VydmVyLmxpc3Rlbihwb3J0KTtcbnNlcnZlci5vbignZXJyb3InLCBvbkVycm9yKTtcbnNlcnZlci5vbignbGlzdGVuaW5nJywgb25MaXN0ZW5pbmcpO1xuIl0sIm5hbWVzIjpbXSwic291cmNlUm9vdCI6IiJ9