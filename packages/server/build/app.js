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
    fromCreateRequest(logId, createLogEntry) {
        return _domain_entities_LogEntry__WEBPACK_IMPORTED_MODULE_0__.LogEntry.create({
            logId,
            logDate: new Date(createLogEntry.logDate),
            logValue: createLogEntry.logValue,
        });
    }
    fromUpdateRequest(updateLogEntry) {
        return _domain_entities_LogEntry__WEBPACK_IMPORTED_MODULE_0__.LogEntry.update({
            id: updateLogEntry.id,
            logId: updateLogEntry.logId,
            logDate: new Date(updateLogEntry.logDate),
            logValue: updateLogEntry.logValue,
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
        const logEntry = mapper.fromCreateRequest(logId, createLogEntry);
        const repository = new _persistence_repositories_LogEntriesRepository__WEBPACK_IMPORTED_MODULE_1__.LogEntriesRepository(logId);
        const newEntry = await repository.createLogEntry(logEntry);
        return mapper.toResponse(newEntry);
    }
    async deleteLogEntry(logId, logEntryId) {
        const logEntryRepository = new _persistence_repositories_LogEntriesRepository__WEBPACK_IMPORTED_MODULE_1__.LogEntriesRepository(logId);
        const logEntry = await logEntryRepository.findById(logEntryId);
        return logEntryRepository.destroyLogEntry(logEntry);
    }
    async updateLogEntry(updateLogEntry) {
        const mapper = new _mappers_LogEntriesApiMapper__WEBPACK_IMPORTED_MODULE_2__.LogEntriesApiMapper();
        const logEntry = mapper.fromUpdateRequest(updateLogEntry);
        const repository = new _persistence_repositories_LogEntriesRepository__WEBPACK_IMPORTED_MODULE_1__.LogEntriesRepository(updateLogEntry.logId);
        const updatedEntry = await repository.updateLogEntry(logEntry);
        return mapper.toResponse(updatedEntry);
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
    static update(updateLogEntryProps) {
        if (!this.isValid(updateLogEntryProps)) {
            throw new _shared_errors__WEBPACK_IMPORTED_MODULE_0__.ValidationError('Cannot update log entry. Props are not valid.');
        }
        return new LogEntry(updateLogEntryProps, updateLogEntryProps.id);
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
    static fromUpdatePersistence(logEntriesRecord) {
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
    async updateLogEntry(logEntry) {
        const dto = _mappers_LogEntriesPersistenceMapper__WEBPACK_IMPORTED_MODULE_2__.LogEntriesPersistenceMapper.toPersistence(logEntry);
        const updatedEntry = await _shared_database__WEBPACK_IMPORTED_MODULE_0__.Database.updateLogEntry(dto);
        return _mappers_LogEntriesPersistenceMapper__WEBPACK_IMPORTED_MODULE_2__.LogEntriesPersistenceMapper.fromPersistence(updatedEntry);
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
logEntriesController.put('/logs/log-entries', async (req, res) => {
    const { logEntry } = req.body;
    const logEntryService = new _application_services_LogEntriesService__WEBPACK_IMPORTED_MODULE_2__.LogEntriesService();
    try {
        const logEntries = await logEntryService.updateLogEntry(logEntry);
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
    static async updateLogEntry(entry) {
        await this.simulateDbSlowness();
        const db = await fs__WEBPACK_IMPORTED_MODULE_2___default().readFileSync(FILE_NAME, 'utf8');
        const allEntries = JSON.parse(db);
        const index = allEntries.findIndex((le) => le.id === entry.id);
        if (index !== -1) {
            allEntries[index] = entry;
            await fs__WEBPACK_IMPORTED_MODULE_2___default().writeFileSync(FILE_NAME, JSON.stringify(allEntries));
            return entry;
        }
        throw new Error(`Log entry with id ${entry.id} not found`);
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,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LFFBQVEsS0FBSyxDQUFDLElBQUksRUFBRTtRQUNsQixLQUFLLFFBQVE7WUFDWCxzQ0FBc0M7WUFDdEMsT0FBTyxDQUFDLEtBQUssQ0FBQyxHQUFHLElBQUksK0JBQStCLENBQUMsQ0FBQztZQUN0RCxPQUFPLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDO1lBQ2hCLE1BQU07UUFDUixLQUFLLFlBQVk7WUFDZixzQ0FBc0M7WUFDdEMsT0FBTyxDQUFDLEtBQUssQ0FBQyxHQUFHLElBQUksb0JBQW9CLENBQUMsQ0FBQztZQUMzQyxPQUFPLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDO1lBQ2hCLE1BQU07UUFDUjtZQUNFLE1BQU0sS0FBSyxDQUFDO0tBQ2Y7QUFDSCxDQUFDO0FBRUQ7O0dBRUc7QUFFSCxTQUFTLFdBQVc7SUFDbEIsTUFBTSxJQUFJLEdBQUcsTUFBTSxDQUFDLE9BQU8sRUFBRSxDQUFDO0lBQzlCLE1BQU0sSUFBSSxHQUFHLE9BQU8sSUFBSSxLQUFLLFFBQVEsQ0FBQyxDQUFDLENBQUMsUUFBUSxJQUFJLEVBQUUsQ0FBQyxDQUFDLENBQUMsUUFBUSxJQUFJLEVBQUUsSUFBSSxFQUFFLENBQUM7SUFDOUUsc0NBQXNDO0lBQ3RDLE9BQU8sQ0FBQyxHQUFHLENBQUMsZ0JBQWdCLElBQUksRUFBRSxDQUFDLENBQUM7QUFDdEMsQ0FBQztBQUVEOztHQUVHO0FBRUgsTUFBTSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsQ0FBQztBQUNwQixNQUFNLENBQUMsRUFBRSxDQUFDLE9BQU8sRUFBRSxPQUFPLENBQUMsQ0FBQztBQUM1QixNQUFNLENBQUMsRUFBRSxDQUFDLFdBQVcsRUFBRSxXQUFXLENBQUMsQ0FBQyIsInNvdXJjZXMiOlsid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uLi8uLi9ub2RlX21vZHVsZXMvY29va2llLXBhcnNlci9pbmRleC5qcyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi4vLi4vbm9kZV9tb2R1bGVzL2Nvb2tpZS1zaWduYXR1cmUvaW5kZXguanMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4uLy4uL25vZGVfbW9kdWxlcy9jb29raWUvaW5kZXguanMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JzL2xpYi9pbmRleC5qcyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi4vLi4vbm9kZV9tb2R1bGVzL29iamVjdC1hc3NpZ24vaW5kZXguanMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4uLy4uL25vZGVfbW9kdWxlcy92YXJ5L2luZGV4LmpzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uLi9zaGFyZWQvc3JjL2NvbnN0YW50cy50cyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi4vc2hhcmVkL3NyYy9pbmRleC50cyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi4vc2hhcmVkL3NyYy90eXBlcy50cyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi9zcmMvYXBwbGljYXRpb24vbWFwcGVycy9Mb2dFbnRyaWVzQXBpTWFwcGVyLnRzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uL3NyYy9hcHBsaWNhdGlvbi9zZXJ2aWNlcy9Mb2dFbnRyaWVzU2VydmljZS50cyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi9zcmMvZG9tYWluL2VudGl0aWVzL0VudGl0eS50cyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi9zcmMvZG9tYWluL2VudGl0aWVzL0xvZ0VudHJ5LnRzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uL3NyYy9kb21haW4vZW50aXRpZXMvVXVpZC50cyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi9zcmMvcGVyc2lzdGVuY2UvbWFwcGVycy9Mb2dFbnRyaWVzUGVyc2lzdGVuY2VNYXBwZXIudHMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4vc3JjL3BlcnNpc3RlbmNlL3JlcG9zaXRvcmllcy9Mb2dFbnRyaWVzUXVlcnlSZXBvc2l0b3J5LnRzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uL3NyYy9wZXJzaXN0ZW5jZS9yZXBvc2l0b3JpZXMvTG9nRW50cmllc1JlcG9zaXRvcnkudHMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4vc3JjL3ByZXNlbnRhdGlvbi9jb250cm9sbGVycy9sb2dFbnRyaWVzQ29udHJvbGxlci50cyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi9zcmMvc2hhcmVkL2RhdGFiYXNlLnRzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uL3NyYy9zaGFyZWQvZXJyb3JzLnRzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci9leHRlcm5hbCBub2RlLWNvbW1vbmpzIFwiY3J5cHRvXCIiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyL2V4dGVybmFsIGNvbW1vbmpzIFwiZXhwcmVzc1wiIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci9leHRlcm5hbCBub2RlLWNvbW1vbmpzIFwiZnNcIiIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvZXh0ZXJuYWwgbm9kZS1jb21tb25qcyBcImh0dHBcIiIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvZXh0ZXJuYWwgY29tbW9uanMgXCJtb3JnYW5cIiIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvd2VicGFjay9ib290c3RyYXAiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyL3dlYnBhY2svcnVudGltZS9jb21wYXQgZ2V0IGRlZmF1bHQgZXhwb3J0Iiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci93ZWJwYWNrL3J1bnRpbWUvZGVmaW5lIHByb3BlcnR5IGdldHRlcnMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyL3dlYnBhY2svcnVudGltZS9oYXNPd25Qcm9wZXJ0eSBzaG9ydGhhbmQiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyL3dlYnBhY2svcnVudGltZS9tYWtlIG5hbWVzcGFjZSBvYmplY3QiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4vc3JjL2FwcC50cyJdLCJzb3VyY2VzQ29udGVudCI6WyIvKiFcbiAqIGNvb2tpZS1wYXJzZXJcbiAqIENvcHlyaWdodChjKSAyMDE0IFRKIEhvbG93YXljaHVrXG4gKiBDb3B5cmlnaHQoYykgMjAxNSBEb3VnbGFzIENocmlzdG9waGVyIFdpbHNvblxuICogTUlUIExpY2Vuc2VkXG4gKi9cblxuJ3VzZSBzdHJpY3QnXG5cbi8qKlxuICogTW9kdWxlIGRlcGVuZGVuY2llcy5cbiAqIEBwcml2YXRlXG4gKi9cblxudmFyIGNvb2tpZSA9IHJlcXVpcmUoJ2Nvb2tpZScpXG52YXIgc2lnbmF0dXJlID0gcmVxdWlyZSgnY29va2llLXNpZ25hdHVyZScpXG5cbi8qKlxuICogTW9kdWxlIGV4cG9ydHMuXG4gKiBAcHVibGljXG4gKi9cblxubW9kdWxlLmV4cG9ydHMgPSBjb29raWVQYXJzZXJcbm1vZHVsZS5leHBvcnRzLkpTT05Db29raWUgPSBKU09OQ29va2llXG5tb2R1bGUuZXhwb3J0cy5KU09OQ29va2llcyA9IEpTT05Db29raWVzXG5tb2R1bGUuZXhwb3J0cy5zaWduZWRDb29raWUgPSBzaWduZWRDb29raWVcbm1vZHVsZS5leHBvcnRzLnNpZ25lZENvb2tpZXMgPSBzaWduZWRDb29raWVzXG5cbi8qKlxuICogUGFyc2UgQ29va2llIGhlYWRlciBhbmQgcG9wdWxhdGUgYHJlcS5jb29raWVzYFxuICogd2l0aCBhbiBvYmplY3Qga2V5ZWQgYnkgdGhlIGNvb2tpZSBuYW1lcy5cbiAqXG4gKiBAcGFyYW0ge3N0cmluZ3xhcnJheX0gW3NlY3JldF0gQSBzdHJpbmcgKG9yIGFycmF5IG9mIHN0cmluZ3MpIHJlcHJlc2VudGluZyBjb29raWUgc2lnbmluZyBzZWNyZXQocykuXG4gKiBAcGFyYW0ge09iamVjdH0gW29wdGlvbnNdXG4gKiBAcmV0dXJuIHtGdW5jdGlvbn1cbiAqIEBwdWJsaWNcbiAqL1xuXG5mdW5jdGlvbiBjb29raWVQYXJzZXIgKHNlY3JldCwgb3B0aW9ucykge1xuICB2YXIgc2VjcmV0cyA9ICFzZWNyZXQgfHwgQXJyYXkuaXNBcnJheShzZWNyZXQpXG4gICAgPyAoc2VjcmV0IHx8IFtdKVxuICAgIDogW3NlY3JldF1cblxuICByZXR1cm4gZnVuY3Rpb24gY29va2llUGFyc2VyIChyZXEsIHJlcywgbmV4dCkge1xuICAgIGlmIChyZXEuY29va2llcykge1xuICAgICAgcmV0dXJuIG5leHQoKVxuICAgIH1cblxuICAgIHZhciBjb29raWVzID0gcmVxLmhlYWRlcnMuY29va2llXG5cbiAgICByZXEuc2VjcmV0ID0gc2VjcmV0c1swXVxuICAgIHJlcS5jb29raWVzID0gT2JqZWN0LmNyZWF0ZShudWxsKVxuICAgIHJlcS5zaWduZWRDb29raWVzID0gT2JqZWN0LmNyZWF0ZShudWxsKVxuXG4gICAgLy8gbm8gY29va2llc1xuICAgIGlmICghY29va2llcykge1xuICAgICAgcmV0dXJuIG5leHQoKVxuICAgIH1cblxuICAgIHJlcS5jb29raWVzID0gY29va2llLnBhcnNlKGNvb2tpZXMsIG9wdGlvbnMpXG5cbiAgICAvLyBwYXJzZSBzaWduZWQgY29va2llc1xuICAgIGlmIChzZWNyZXRzLmxlbmd0aCAhPT0gMCkge1xuICAgICAgcmVxLnNpZ25lZENvb2tpZXMgPSBzaWduZWRDb29raWVzKHJlcS5jb29raWVzLCBzZWNyZXRzKVxuICAgICAgcmVxLnNpZ25lZENvb2tpZXMgPSBKU09OQ29va2llcyhyZXEuc2lnbmVkQ29va2llcylcbiAgICB9XG5cbiAgICAvLyBwYXJzZSBKU09OIGNvb2tpZXNcbiAgICByZXEuY29va2llcyA9IEpTT05Db29raWVzKHJlcS5jb29raWVzKVxuXG4gICAgbmV4dCgpXG4gIH1cbn1cblxuLyoqXG4gKiBQYXJzZSBKU09OIGNvb2tpZSBzdHJpbmcuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHN0clxuICogQHJldHVybiB7T2JqZWN0fSBQYXJzZWQgb2JqZWN0IG9yIHVuZGVmaW5lZCBpZiBub3QganNvbiBjb29raWVcbiAqIEBwdWJsaWNcbiAqL1xuXG5mdW5jdGlvbiBKU09OQ29va2llIChzdHIpIHtcbiAgaWYgKHR5cGVvZiBzdHIgIT09ICdzdHJpbmcnIHx8IHN0ci5zdWJzdHIoMCwgMikgIT09ICdqOicpIHtcbiAgICByZXR1cm4gdW5kZWZpbmVkXG4gIH1cblxuICB0cnkge1xuICAgIHJldHVybiBKU09OLnBhcnNlKHN0ci5zbGljZSgyKSlcbiAgfSBjYXRjaCAoZXJyKSB7XG4gICAgcmV0dXJuIHVuZGVmaW5lZFxuICB9XG59XG5cbi8qKlxuICogUGFyc2UgSlNPTiBjb29raWVzLlxuICpcbiAqIEBwYXJhbSB7T2JqZWN0fSBvYmpcbiAqIEByZXR1cm4ge09iamVjdH1cbiAqIEBwdWJsaWNcbiAqL1xuXG5mdW5jdGlvbiBKU09OQ29va2llcyAob2JqKSB7XG4gIHZhciBjb29raWVzID0gT2JqZWN0LmtleXMob2JqKVxuICB2YXIga2V5XG4gIHZhciB2YWxcblxuICBmb3IgKHZhciBpID0gMDsgaSA8IGNvb2tpZXMubGVuZ3RoOyBpKyspIHtcbiAgICBrZXkgPSBjb29raWVzW2ldXG4gICAgdmFsID0gSlNPTkNvb2tpZShvYmpba2V5XSlcblxuICAgIGlmICh2YWwpIHtcbiAgICAgIG9ialtrZXldID0gdmFsXG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIG9ialxufVxuXG4vKipcbiAqIFBhcnNlIGEgc2lnbmVkIGNvb2tpZSBzdHJpbmcsIHJldHVybiB0aGUgZGVjb2RlZCB2YWx1ZS5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gc3RyIHNpZ25lZCBjb29raWUgc3RyaW5nXG4gKiBAcGFyYW0ge3N0cmluZ3xhcnJheX0gc2VjcmV0XG4gKiBAcmV0dXJuIHtTdHJpbmd9IGRlY29kZWQgdmFsdWVcbiAqIEBwdWJsaWNcbiAqL1xuXG5mdW5jdGlvbiBzaWduZWRDb29raWUgKHN0ciwgc2VjcmV0KSB7XG4gIGlmICh0eXBlb2Ygc3RyICE9PSAnc3RyaW5nJykge1xuICAgIHJldHVybiB1bmRlZmluZWRcbiAgfVxuXG4gIGlmIChzdHIuc3Vic3RyKDAsIDIpICE9PSAnczonKSB7XG4gICAgcmV0dXJuIHN0clxuICB9XG5cbiAgdmFyIHNlY3JldHMgPSAhc2VjcmV0IHx8IEFycmF5LmlzQXJyYXkoc2VjcmV0KVxuICAgID8gKHNlY3JldCB8fCBbXSlcbiAgICA6IFtzZWNyZXRdXG5cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBzZWNyZXRzLmxlbmd0aDsgaSsrKSB7XG4gICAgdmFyIHZhbCA9IHNpZ25hdHVyZS51bnNpZ24oc3RyLnNsaWNlKDIpLCBzZWNyZXRzW2ldKVxuXG4gICAgaWYgKHZhbCAhPT0gZmFsc2UpIHtcbiAgICAgIHJldHVybiB2YWxcbiAgICB9XG4gIH1cblxuICByZXR1cm4gZmFsc2Vcbn1cblxuLyoqXG4gKiBQYXJzZSBzaWduZWQgY29va2llcywgcmV0dXJuaW5nIGFuIG9iamVjdCBjb250YWluaW5nIHRoZSBkZWNvZGVkIGtleS92YWx1ZVxuICogcGFpcnMsIHdoaWxlIHJlbW92aW5nIHRoZSBzaWduZWQga2V5IGZyb20gb2JqLlxuICpcbiAqIEBwYXJhbSB7T2JqZWN0fSBvYmpcbiAqIEBwYXJhbSB7c3RyaW5nfGFycmF5fSBzZWNyZXRcbiAqIEByZXR1cm4ge09iamVjdH1cbiAqIEBwdWJsaWNcbiAqL1xuXG5mdW5jdGlvbiBzaWduZWRDb29raWVzIChvYmosIHNlY3JldCkge1xuICB2YXIgY29va2llcyA9IE9iamVjdC5rZXlzKG9iailcbiAgdmFyIGRlY1xuICB2YXIga2V5XG4gIHZhciByZXQgPSBPYmplY3QuY3JlYXRlKG51bGwpXG4gIHZhciB2YWxcblxuICBmb3IgKHZhciBpID0gMDsgaSA8IGNvb2tpZXMubGVuZ3RoOyBpKyspIHtcbiAgICBrZXkgPSBjb29raWVzW2ldXG4gICAgdmFsID0gb2JqW2tleV1cbiAgICBkZWMgPSBzaWduZWRDb29raWUodmFsLCBzZWNyZXQpXG5cbiAgICBpZiAodmFsICE9PSBkZWMpIHtcbiAgICAgIHJldFtrZXldID0gZGVjXG4gICAgICBkZWxldGUgb2JqW2tleV1cbiAgICB9XG4gIH1cblxuICByZXR1cm4gcmV0XG59XG4iLCIvKipcbiAqIE1vZHVsZSBkZXBlbmRlbmNpZXMuXG4gKi9cblxudmFyIGNyeXB0byA9IHJlcXVpcmUoJ2NyeXB0bycpO1xuXG4vKipcbiAqIFNpZ24gdGhlIGdpdmVuIGB2YWxgIHdpdGggYHNlY3JldGAuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHZhbFxuICogQHBhcmFtIHtTdHJpbmd9IHNlY3JldFxuICogQHJldHVybiB7U3RyaW5nfVxuICogQGFwaSBwcml2YXRlXG4gKi9cblxuZXhwb3J0cy5zaWduID0gZnVuY3Rpb24odmFsLCBzZWNyZXQpe1xuICBpZiAoJ3N0cmluZycgIT0gdHlwZW9mIHZhbCkgdGhyb3cgbmV3IFR5cGVFcnJvcihcIkNvb2tpZSB2YWx1ZSBtdXN0IGJlIHByb3ZpZGVkIGFzIGEgc3RyaW5nLlwiKTtcbiAgaWYgKCdzdHJpbmcnICE9IHR5cGVvZiBzZWNyZXQpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJTZWNyZXQgc3RyaW5nIG11c3QgYmUgcHJvdmlkZWQuXCIpO1xuICByZXR1cm4gdmFsICsgJy4nICsgY3J5cHRvXG4gICAgLmNyZWF0ZUhtYWMoJ3NoYTI1NicsIHNlY3JldClcbiAgICAudXBkYXRlKHZhbClcbiAgICAuZGlnZXN0KCdiYXNlNjQnKVxuICAgIC5yZXBsYWNlKC9cXD0rJC8sICcnKTtcbn07XG5cbi8qKlxuICogVW5zaWduIGFuZCBkZWNvZGUgdGhlIGdpdmVuIGB2YWxgIHdpdGggYHNlY3JldGAsXG4gKiByZXR1cm5pbmcgYGZhbHNlYCBpZiB0aGUgc2lnbmF0dXJlIGlzIGludmFsaWQuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHZhbFxuICogQHBhcmFtIHtTdHJpbmd9IHNlY3JldFxuICogQHJldHVybiB7U3RyaW5nfEJvb2xlYW59XG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5leHBvcnRzLnVuc2lnbiA9IGZ1bmN0aW9uKHZhbCwgc2VjcmV0KXtcbiAgaWYgKCdzdHJpbmcnICE9IHR5cGVvZiB2YWwpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJTaWduZWQgY29va2llIHN0cmluZyBtdXN0IGJlIHByb3ZpZGVkLlwiKTtcbiAgaWYgKCdzdHJpbmcnICE9IHR5cGVvZiBzZWNyZXQpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJTZWNyZXQgc3RyaW5nIG11c3QgYmUgcHJvdmlkZWQuXCIpO1xuICB2YXIgc3RyID0gdmFsLnNsaWNlKDAsIHZhbC5sYXN0SW5kZXhPZignLicpKVxuICAgICwgbWFjID0gZXhwb3J0cy5zaWduKHN0ciwgc2VjcmV0KTtcbiAgXG4gIHJldHVybiBzaGExKG1hYykgPT0gc2hhMSh2YWwpID8gc3RyIDogZmFsc2U7XG59O1xuXG4vKipcbiAqIFByaXZhdGVcbiAqL1xuXG5mdW5jdGlvbiBzaGExKHN0cil7XG4gIHJldHVybiBjcnlwdG8uY3JlYXRlSGFzaCgnc2hhMScpLnVwZGF0ZShzdHIpLmRpZ2VzdCgnaGV4Jyk7XG59XG4iLCIvKiFcbiAqIGNvb2tpZVxuICogQ29weXJpZ2h0KGMpIDIwMTItMjAxNCBSb21hbiBTaHR5bG1hblxuICogQ29weXJpZ2h0KGMpIDIwMTUgRG91Z2xhcyBDaHJpc3RvcGhlciBXaWxzb25cbiAqIE1JVCBMaWNlbnNlZFxuICovXG5cbid1c2Ugc3RyaWN0JztcblxuLyoqXG4gKiBNb2R1bGUgZXhwb3J0cy5cbiAqIEBwdWJsaWNcbiAqL1xuXG5leHBvcnRzLnBhcnNlID0gcGFyc2U7XG5leHBvcnRzLnNlcmlhbGl6ZSA9IHNlcmlhbGl6ZTtcblxuLyoqXG4gKiBNb2R1bGUgdmFyaWFibGVzLlxuICogQHByaXZhdGVcbiAqL1xuXG52YXIgX190b1N0cmluZyA9IE9iamVjdC5wcm90b3R5cGUudG9TdHJpbmdcbnZhciBfX2hhc093blByb3BlcnR5ID0gT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eVxuXG4vKipcbiAqIFJlZ0V4cCB0byBtYXRjaCBjb29raWUtbmFtZSBpbiBSRkMgNjI2NSBzZWMgNC4xLjFcbiAqIFRoaXMgcmVmZXJzIG91dCB0byB0aGUgb2Jzb2xldGVkIGRlZmluaXRpb24gb2YgdG9rZW4gaW4gUkZDIDI2MTYgc2VjIDIuMlxuICogd2hpY2ggaGFzIGJlZW4gcmVwbGFjZWQgYnkgdGhlIHRva2VuIGRlZmluaXRpb24gaW4gUkZDIDcyMzAgYXBwZW5kaXggQi5cbiAqXG4gKiBjb29raWUtbmFtZSAgICAgICA9IHRva2VuXG4gKiB0b2tlbiAgICAgICAgICAgICA9IDEqdGNoYXJcbiAqIHRjaGFyICAgICAgICAgICAgID0gXCIhXCIgLyBcIiNcIiAvIFwiJFwiIC8gXCIlXCIgLyBcIiZcIiAvIFwiJ1wiIC9cbiAqICAgICAgICAgICAgICAgICAgICAgXCIqXCIgLyBcIitcIiAvIFwiLVwiIC8gXCIuXCIgLyBcIl5cIiAvIFwiX1wiIC9cbiAqICAgICAgICAgICAgICAgICAgICAgXCJgXCIgLyBcInxcIiAvIFwiflwiIC8gRElHSVQgLyBBTFBIQVxuICovXG5cbnZhciBjb29raWVOYW1lUmVnRXhwID0gL15bISMkJSYnKitcXC0uXl9gfH4wLTlBLVphLXpdKyQvO1xuXG4vKipcbiAqIFJlZ0V4cCB0byBtYXRjaCBjb29raWUtdmFsdWUgaW4gUkZDIDYyNjUgc2VjIDQuMS4xXG4gKlxuICogY29va2llLXZhbHVlICAgICAgPSAqY29va2llLW9jdGV0IC8gKCBEUVVPVEUgKmNvb2tpZS1vY3RldCBEUVVPVEUgKVxuICogY29va2llLW9jdGV0ICAgICAgPSAleDIxIC8gJXgyMy0yQiAvICV4MkQtM0EgLyAleDNDLTVCIC8gJXg1RC03RVxuICogICAgICAgICAgICAgICAgICAgICA7IFVTLUFTQ0lJIGNoYXJhY3RlcnMgZXhjbHVkaW5nIENUTHMsXG4gKiAgICAgICAgICAgICAgICAgICAgIDsgd2hpdGVzcGFjZSBEUVVPVEUsIGNvbW1hLCBzZW1pY29sb24sXG4gKiAgICAgICAgICAgICAgICAgICAgIDsgYW5kIGJhY2tzbGFzaFxuICovXG5cbnZhciBjb29raWVWYWx1ZVJlZ0V4cCA9IC9eKFwiPylbXFx1MDAyMVxcdTAwMjMtXFx1MDAyQlxcdTAwMkQtXFx1MDAzQVxcdTAwM0MtXFx1MDA1QlxcdTAwNUQtXFx1MDA3RV0qXFwxJC87XG5cbi8qKlxuICogUmVnRXhwIHRvIG1hdGNoIGRvbWFpbi12YWx1ZSBpbiBSRkMgNjI2NSBzZWMgNC4xLjFcbiAqXG4gKiBkb21haW4tdmFsdWUgICAgICA9IDxzdWJkb21haW4+XG4gKiAgICAgICAgICAgICAgICAgICAgIDsgZGVmaW5lZCBpbiBbUkZDMTAzNF0sIFNlY3Rpb24gMy41LCBhc1xuICogICAgICAgICAgICAgICAgICAgICA7IGVuaGFuY2VkIGJ5IFtSRkMxMTIzXSwgU2VjdGlvbiAyLjFcbiAqIDxzdWJkb21haW4+ICAgICAgID0gPGxhYmVsPiB8IDxzdWJkb21haW4+IFwiLlwiIDxsYWJlbD5cbiAqIDxsYWJlbD4gICAgICAgICAgID0gPGxldC1kaWc+IFsgWyA8bGRoLXN0cj4gXSA8bGV0LWRpZz4gXVxuICogICAgICAgICAgICAgICAgICAgICBMYWJlbHMgbXVzdCBiZSA2MyBjaGFyYWN0ZXJzIG9yIGxlc3MuXG4gKiAgICAgICAgICAgICAgICAgICAgICdsZXQtZGlnJyBub3QgJ2xldHRlcicgaW4gdGhlIGZpcnN0IGNoYXIsIHBlciBSRkMxMTIzXG4gKiA8bGRoLXN0cj4gICAgICAgICA9IDxsZXQtZGlnLWh5cD4gfCA8bGV0LWRpZy1oeXA+IDxsZGgtc3RyPlxuICogPGxldC1kaWctaHlwPiAgICAgPSA8bGV0LWRpZz4gfCBcIi1cIlxuICogPGxldC1kaWc+ICAgICAgICAgPSA8bGV0dGVyPiB8IDxkaWdpdD5cbiAqIDxsZXR0ZXI+ICAgICAgICAgID0gYW55IG9uZSBvZiB0aGUgNTIgYWxwaGFiZXRpYyBjaGFyYWN0ZXJzIEEgdGhyb3VnaCBaIGluXG4gKiAgICAgICAgICAgICAgICAgICAgIHVwcGVyIGNhc2UgYW5kIGEgdGhyb3VnaCB6IGluIGxvd2VyIGNhc2VcbiAqIDxkaWdpdD4gICAgICAgICAgID0gYW55IG9uZSBvZiB0aGUgdGVuIGRpZ2l0cyAwIHRocm91Z2ggOVxuICpcbiAqIEtlZXAgc3VwcG9ydCBmb3IgbGVhZGluZyBkb3Q6IGh0dHBzOi8vZ2l0aHViLmNvbS9qc2h0dHAvY29va2llL2lzc3Vlcy8xNzNcbiAqXG4gKiA+IChOb3RlIHRoYXQgYSBsZWFkaW5nICV4MkUgKFwiLlwiKSwgaWYgcHJlc2VudCwgaXMgaWdub3JlZCBldmVuIHRob3VnaCB0aGF0XG4gKiBjaGFyYWN0ZXIgaXMgbm90IHBlcm1pdHRlZCwgYnV0IGEgdHJhaWxpbmcgJXgyRSAoXCIuXCIpLCBpZiBwcmVzZW50LCB3aWxsXG4gKiBjYXVzZSB0aGUgdXNlciBhZ2VudCB0byBpZ25vcmUgdGhlIGF0dHJpYnV0ZS4pXG4gKi9cblxudmFyIGRvbWFpblZhbHVlUmVnRXhwID0gL14oWy5dP1thLXowLTldKFthLXowLTktXXswLDYxfVthLXowLTldKT8pKFsuXVthLXowLTldKFthLXowLTktXXswLDYxfVthLXowLTldKT8pKiQvaTtcblxuLyoqXG4gKiBSZWdFeHAgdG8gbWF0Y2ggcGF0aC12YWx1ZSBpbiBSRkMgNjI2NSBzZWMgNC4xLjFcbiAqXG4gKiBwYXRoLXZhbHVlICAgICAgICA9IDxhbnkgQ0hBUiBleGNlcHQgQ1RMcyBvciBcIjtcIj5cbiAqIENIQVIgICAgICAgICAgICAgID0gJXgwMS03RlxuICogICAgICAgICAgICAgICAgICAgICA7IGRlZmluZWQgaW4gUkZDIDUyMzQgYXBwZW5kaXggQi4xXG4gKi9cblxudmFyIHBhdGhWYWx1ZVJlZ0V4cCA9IC9eW1xcdTAwMjAtXFx1MDAzQVxcdTAwM0QtXFx1MDA3RV0qJC87XG5cbi8qKlxuICogUGFyc2UgYSBjb29raWUgaGVhZGVyLlxuICpcbiAqIFBhcnNlIHRoZSBnaXZlbiBjb29raWUgaGVhZGVyIHN0cmluZyBpbnRvIGFuIG9iamVjdFxuICogVGhlIG9iamVjdCBoYXMgdGhlIHZhcmlvdXMgY29va2llcyBhcyBrZXlzKG5hbWVzKSA9PiB2YWx1ZXNcbiAqXG4gKiBAcGFyYW0ge3N0cmluZ30gc3RyXG4gKiBAcGFyYW0ge29iamVjdH0gW29wdF1cbiAqIEByZXR1cm4ge29iamVjdH1cbiAqIEBwdWJsaWNcbiAqL1xuXG5mdW5jdGlvbiBwYXJzZShzdHIsIG9wdCkge1xuICBpZiAodHlwZW9mIHN0ciAhPT0gJ3N0cmluZycpIHtcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdhcmd1bWVudCBzdHIgbXVzdCBiZSBhIHN0cmluZycpO1xuICB9XG5cbiAgdmFyIG9iaiA9IHt9O1xuICB2YXIgbGVuID0gc3RyLmxlbmd0aDtcbiAgLy8gUkZDIDYyNjUgc2VjIDQuMS4xLCBSRkMgMjYxNiAyLjIgZGVmaW5lcyBhIGNvb2tpZSBuYW1lIGNvbnNpc3RzIG9mIG9uZSBjaGFyIG1pbmltdW0sIHBsdXMgJz0nLlxuICBpZiAobGVuIDwgMikgcmV0dXJuIG9iajtcblxuICB2YXIgZGVjID0gKG9wdCAmJiBvcHQuZGVjb2RlKSB8fCBkZWNvZGU7XG4gIHZhciBpbmRleCA9IDA7XG4gIHZhciBlcUlkeCA9IDA7XG4gIHZhciBlbmRJZHggPSAwO1xuXG4gIGRvIHtcbiAgICBlcUlkeCA9IHN0ci5pbmRleE9mKCc9JywgaW5kZXgpO1xuICAgIGlmIChlcUlkeCA9PT0gLTEpIGJyZWFrOyAvLyBObyBtb3JlIGNvb2tpZSBwYWlycy5cblxuICAgIGVuZElkeCA9IHN0ci5pbmRleE9mKCc7JywgaW5kZXgpO1xuXG4gICAgaWYgKGVuZElkeCA9PT0gLTEpIHtcbiAgICAgIGVuZElkeCA9IGxlbjtcbiAgICB9IGVsc2UgaWYgKGVxSWR4ID4gZW5kSWR4KSB7XG4gICAgICAvLyBiYWNrdHJhY2sgb24gcHJpb3Igc2VtaWNvbG9uXG4gICAgICBpbmRleCA9IHN0ci5sYXN0SW5kZXhPZignOycsIGVxSWR4IC0gMSkgKyAxO1xuICAgICAgY29udGludWU7XG4gICAgfVxuXG4gICAgdmFyIGtleVN0YXJ0SWR4ID0gc3RhcnRJbmRleChzdHIsIGluZGV4LCBlcUlkeCk7XG4gICAgdmFyIGtleUVuZElkeCA9IGVuZEluZGV4KHN0ciwgZXFJZHgsIGtleVN0YXJ0SWR4KTtcbiAgICB2YXIga2V5ID0gc3RyLnNsaWNlKGtleVN0YXJ0SWR4LCBrZXlFbmRJZHgpO1xuXG4gICAgLy8gb25seSBhc3NpZ24gb25jZVxuICAgIGlmICghX19oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwga2V5KSkge1xuICAgICAgdmFyIHZhbFN0YXJ0SWR4ID0gc3RhcnRJbmRleChzdHIsIGVxSWR4ICsgMSwgZW5kSWR4KTtcbiAgICAgIHZhciB2YWxFbmRJZHggPSBlbmRJbmRleChzdHIsIGVuZElkeCwgdmFsU3RhcnRJZHgpO1xuXG4gICAgICBpZiAoc3RyLmNoYXJDb2RlQXQodmFsU3RhcnRJZHgpID09PSAweDIyIC8qIFwiICovICYmIHN0ci5jaGFyQ29kZUF0KHZhbEVuZElkeCAtIDEpID09PSAweDIyIC8qIFwiICovKSB7XG4gICAgICAgIHZhbFN0YXJ0SWR4Kys7XG4gICAgICAgIHZhbEVuZElkeC0tO1xuICAgICAgfVxuXG4gICAgICB2YXIgdmFsID0gc3RyLnNsaWNlKHZhbFN0YXJ0SWR4LCB2YWxFbmRJZHgpO1xuICAgICAgb2JqW2tleV0gPSB0cnlEZWNvZGUodmFsLCBkZWMpO1xuICAgIH1cblxuICAgIGluZGV4ID0gZW5kSWR4ICsgMVxuICB9IHdoaWxlIChpbmRleCA8IGxlbik7XG5cbiAgcmV0dXJuIG9iajtcbn1cblxuZnVuY3Rpb24gc3RhcnRJbmRleChzdHIsIGluZGV4LCBtYXgpIHtcbiAgZG8ge1xuICAgIHZhciBjb2RlID0gc3RyLmNoYXJDb2RlQXQoaW5kZXgpO1xuICAgIGlmIChjb2RlICE9PSAweDIwIC8qICAgKi8gJiYgY29kZSAhPT0gMHgwOSAvKiBcXHQgKi8pIHJldHVybiBpbmRleDtcbiAgfSB3aGlsZSAoKytpbmRleCA8IG1heCk7XG4gIHJldHVybiBtYXg7XG59XG5cbmZ1bmN0aW9uIGVuZEluZGV4KHN0ciwgaW5kZXgsIG1pbikge1xuICB3aGlsZSAoaW5kZXggPiBtaW4pIHtcbiAgICB2YXIgY29kZSA9IHN0ci5jaGFyQ29kZUF0KC0taW5kZXgpO1xuICAgIGlmIChjb2RlICE9PSAweDIwIC8qICAgKi8gJiYgY29kZSAhPT0gMHgwOSAvKiBcXHQgKi8pIHJldHVybiBpbmRleCArIDE7XG4gIH1cbiAgcmV0dXJuIG1pbjtcbn1cblxuLyoqXG4gKiBTZXJpYWxpemUgZGF0YSBpbnRvIGEgY29va2llIGhlYWRlci5cbiAqXG4gKiBTZXJpYWxpemUgYSBuYW1lIHZhbHVlIHBhaXIgaW50byBhIGNvb2tpZSBzdHJpbmcgc3VpdGFibGUgZm9yXG4gKiBodHRwIGhlYWRlcnMuIEFuIG9wdGlvbmFsIG9wdGlvbnMgb2JqZWN0IHNwZWNpZmllcyBjb29raWUgcGFyYW1ldGVycy5cbiAqXG4gKiBzZXJpYWxpemUoJ2ZvbycsICdiYXInLCB7IGh0dHBPbmx5OiB0cnVlIH0pXG4gKiAgID0+IFwiZm9vPWJhcjsgaHR0cE9ubHlcIlxuICpcbiAqIEBwYXJhbSB7c3RyaW5nfSBuYW1lXG4gKiBAcGFyYW0ge3N0cmluZ30gdmFsXG4gKiBAcGFyYW0ge29iamVjdH0gW29wdF1cbiAqIEByZXR1cm4ge3N0cmluZ31cbiAqIEBwdWJsaWNcbiAqL1xuXG5mdW5jdGlvbiBzZXJpYWxpemUobmFtZSwgdmFsLCBvcHQpIHtcbiAgdmFyIGVuYyA9IChvcHQgJiYgb3B0LmVuY29kZSkgfHwgZW5jb2RlVVJJQ29tcG9uZW50O1xuXG4gIGlmICh0eXBlb2YgZW5jICE9PSAnZnVuY3Rpb24nKSB7XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcignb3B0aW9uIGVuY29kZSBpcyBpbnZhbGlkJyk7XG4gIH1cblxuICBpZiAoIWNvb2tpZU5hbWVSZWdFeHAudGVzdChuYW1lKSkge1xuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ2FyZ3VtZW50IG5hbWUgaXMgaW52YWxpZCcpO1xuICB9XG5cbiAgdmFyIHZhbHVlID0gZW5jKHZhbCk7XG5cbiAgaWYgKCFjb29raWVWYWx1ZVJlZ0V4cC50ZXN0KHZhbHVlKSkge1xuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ2FyZ3VtZW50IHZhbCBpcyBpbnZhbGlkJyk7XG4gIH1cblxuICB2YXIgc3RyID0gbmFtZSArICc9JyArIHZhbHVlO1xuICBpZiAoIW9wdCkgcmV0dXJuIHN0cjtcblxuICBpZiAobnVsbCAhPSBvcHQubWF4QWdlKSB7XG4gICAgdmFyIG1heEFnZSA9IE1hdGguZmxvb3Iob3B0Lm1heEFnZSk7XG5cbiAgICBpZiAoIWlzRmluaXRlKG1heEFnZSkpIHtcbiAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ29wdGlvbiBtYXhBZ2UgaXMgaW52YWxpZCcpXG4gICAgfVxuXG4gICAgc3RyICs9ICc7IE1heC1BZ2U9JyArIG1heEFnZTtcbiAgfVxuXG4gIGlmIChvcHQuZG9tYWluKSB7XG4gICAgaWYgKCFkb21haW5WYWx1ZVJlZ0V4cC50ZXN0KG9wdC5kb21haW4pKSB7XG4gICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdvcHRpb24gZG9tYWluIGlzIGludmFsaWQnKTtcbiAgICB9XG5cbiAgICBzdHIgKz0gJzsgRG9tYWluPScgKyBvcHQuZG9tYWluO1xuICB9XG5cbiAgaWYgKG9wdC5wYXRoKSB7XG4gICAgaWYgKCFwYXRoVmFsdWVSZWdFeHAudGVzdChvcHQucGF0aCkpIHtcbiAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ29wdGlvbiBwYXRoIGlzIGludmFsaWQnKTtcbiAgICB9XG5cbiAgICBzdHIgKz0gJzsgUGF0aD0nICsgb3B0LnBhdGg7XG4gIH1cblxuICBpZiAob3B0LmV4cGlyZXMpIHtcbiAgICB2YXIgZXhwaXJlcyA9IG9wdC5leHBpcmVzXG5cbiAgICBpZiAoIWlzRGF0ZShleHBpcmVzKSB8fCBpc05hTihleHBpcmVzLnZhbHVlT2YoKSkpIHtcbiAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ29wdGlvbiBleHBpcmVzIGlzIGludmFsaWQnKTtcbiAgICB9XG5cbiAgICBzdHIgKz0gJzsgRXhwaXJlcz0nICsgZXhwaXJlcy50b1VUQ1N0cmluZygpXG4gIH1cblxuICBpZiAob3B0Lmh0dHBPbmx5KSB7XG4gICAgc3RyICs9ICc7IEh0dHBPbmx5JztcbiAgfVxuXG4gIGlmIChvcHQuc2VjdXJlKSB7XG4gICAgc3RyICs9ICc7IFNlY3VyZSc7XG4gIH1cblxuICBpZiAob3B0LnBhcnRpdGlvbmVkKSB7XG4gICAgc3RyICs9ICc7IFBhcnRpdGlvbmVkJ1xuICB9XG5cbiAgaWYgKG9wdC5wcmlvcml0eSkge1xuICAgIHZhciBwcmlvcml0eSA9IHR5cGVvZiBvcHQucHJpb3JpdHkgPT09ICdzdHJpbmcnXG4gICAgICA/IG9wdC5wcmlvcml0eS50b0xvd2VyQ2FzZSgpIDogb3B0LnByaW9yaXR5O1xuXG4gICAgc3dpdGNoIChwcmlvcml0eSkge1xuICAgICAgY2FzZSAnbG93JzpcbiAgICAgICAgc3RyICs9ICc7IFByaW9yaXR5PUxvdydcbiAgICAgICAgYnJlYWtcbiAgICAgIGNhc2UgJ21lZGl1bSc6XG4gICAgICAgIHN0ciArPSAnOyBQcmlvcml0eT1NZWRpdW0nXG4gICAgICAgIGJyZWFrXG4gICAgICBjYXNlICdoaWdoJzpcbiAgICAgICAgc3RyICs9ICc7IFByaW9yaXR5PUhpZ2gnXG4gICAgICAgIGJyZWFrXG4gICAgICBkZWZhdWx0OlxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdvcHRpb24gcHJpb3JpdHkgaXMgaW52YWxpZCcpXG4gICAgfVxuICB9XG5cbiAgaWYgKG9wdC5zYW1lU2l0ZSkge1xuICAgIHZhciBzYW1lU2l0ZSA9IHR5cGVvZiBvcHQuc2FtZVNpdGUgPT09ICdzdHJpbmcnXG4gICAgICA/IG9wdC5zYW1lU2l0ZS50b0xvd2VyQ2FzZSgpIDogb3B0LnNhbWVTaXRlO1xuXG4gICAgc3dpdGNoIChzYW1lU2l0ZSkge1xuICAgICAgY2FzZSB0cnVlOlxuICAgICAgICBzdHIgKz0gJzsgU2FtZVNpdGU9U3RyaWN0JztcbiAgICAgICAgYnJlYWs7XG4gICAgICBjYXNlICdsYXgnOlxuICAgICAgICBzdHIgKz0gJzsgU2FtZVNpdGU9TGF4JztcbiAgICAgICAgYnJlYWs7XG4gICAgICBjYXNlICdzdHJpY3QnOlxuICAgICAgICBzdHIgKz0gJzsgU2FtZVNpdGU9U3RyaWN0JztcbiAgICAgICAgYnJlYWs7XG4gICAgICBjYXNlICdub25lJzpcbiAgICAgICAgc3RyICs9ICc7IFNhbWVTaXRlPU5vbmUnO1xuICAgICAgICBicmVhaztcbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ29wdGlvbiBzYW1lU2l0ZSBpcyBpbnZhbGlkJyk7XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIHN0cjtcbn1cblxuLyoqXG4gKiBVUkwtZGVjb2RlIHN0cmluZyB2YWx1ZS4gT3B0aW1pemVkIHRvIHNraXAgbmF0aXZlIGNhbGwgd2hlbiBubyAlLlxuICpcbiAqIEBwYXJhbSB7c3RyaW5nfSBzdHJcbiAqIEByZXR1cm5zIHtzdHJpbmd9XG4gKi9cblxuZnVuY3Rpb24gZGVjb2RlIChzdHIpIHtcbiAgcmV0dXJuIHN0ci5pbmRleE9mKCclJykgIT09IC0xXG4gICAgPyBkZWNvZGVVUklDb21wb25lbnQoc3RyKVxuICAgIDogc3RyXG59XG5cbi8qKlxuICogRGV0ZXJtaW5lIGlmIHZhbHVlIGlzIGEgRGF0ZS5cbiAqXG4gKiBAcGFyYW0geyp9IHZhbFxuICogQHByaXZhdGVcbiAqL1xuXG5mdW5jdGlvbiBpc0RhdGUgKHZhbCkge1xuICByZXR1cm4gX190b1N0cmluZy5jYWxsKHZhbCkgPT09ICdbb2JqZWN0IERhdGVdJztcbn1cblxuLyoqXG4gKiBUcnkgZGVjb2RpbmcgYSBzdHJpbmcgdXNpbmcgYSBkZWNvZGluZyBmdW5jdGlvbi5cbiAqXG4gKiBAcGFyYW0ge3N0cmluZ30gc3RyXG4gKiBAcGFyYW0ge2Z1bmN0aW9ufSBkZWNvZGVcbiAqIEBwcml2YXRlXG4gKi9cblxuZnVuY3Rpb24gdHJ5RGVjb2RlKHN0ciwgZGVjb2RlKSB7XG4gIHRyeSB7XG4gICAgcmV0dXJuIGRlY29kZShzdHIpO1xuICB9IGNhdGNoIChlKSB7XG4gICAgcmV0dXJuIHN0cjtcbiAgfVxufVxuIiwiKGZ1bmN0aW9uICgpIHtcblxuICAndXNlIHN0cmljdCc7XG5cbiAgdmFyIGFzc2lnbiA9IHJlcXVpcmUoJ29iamVjdC1hc3NpZ24nKTtcbiAgdmFyIHZhcnkgPSByZXF1aXJlKCd2YXJ5Jyk7XG5cbiAgdmFyIGRlZmF1bHRzID0ge1xuICAgIG9yaWdpbjogJyonLFxuICAgIG1ldGhvZHM6ICdHRVQsSEVBRCxQVVQsUEFUQ0gsUE9TVCxERUxFVEUnLFxuICAgIHByZWZsaWdodENvbnRpbnVlOiBmYWxzZSxcbiAgICBvcHRpb25zU3VjY2Vzc1N0YXR1czogMjA0XG4gIH07XG5cbiAgZnVuY3Rpb24gaXNTdHJpbmcocykge1xuICAgIHJldHVybiB0eXBlb2YgcyA9PT0gJ3N0cmluZycgfHwgcyBpbnN0YW5jZW9mIFN0cmluZztcbiAgfVxuXG4gIGZ1bmN0aW9uIGlzT3JpZ2luQWxsb3dlZChvcmlnaW4sIGFsbG93ZWRPcmlnaW4pIHtcbiAgICBpZiAoQXJyYXkuaXNBcnJheShhbGxvd2VkT3JpZ2luKSkge1xuICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBhbGxvd2VkT3JpZ2luLmxlbmd0aDsgKytpKSB7XG4gICAgICAgIGlmIChpc09yaWdpbkFsbG93ZWQob3JpZ2luLCBhbGxvd2VkT3JpZ2luW2ldKSkge1xuICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfSBlbHNlIGlmIChpc1N0cmluZyhhbGxvd2VkT3JpZ2luKSkge1xuICAgICAgcmV0dXJuIG9yaWdpbiA9PT0gYWxsb3dlZE9yaWdpbjtcbiAgICB9IGVsc2UgaWYgKGFsbG93ZWRPcmlnaW4gaW5zdGFuY2VvZiBSZWdFeHApIHtcbiAgICAgIHJldHVybiBhbGxvd2VkT3JpZ2luLnRlc3Qob3JpZ2luKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmV0dXJuICEhYWxsb3dlZE9yaWdpbjtcbiAgICB9XG4gIH1cblxuICBmdW5jdGlvbiBjb25maWd1cmVPcmlnaW4ob3B0aW9ucywgcmVxKSB7XG4gICAgdmFyIHJlcXVlc3RPcmlnaW4gPSByZXEuaGVhZGVycy5vcmlnaW4sXG4gICAgICBoZWFkZXJzID0gW10sXG4gICAgICBpc0FsbG93ZWQ7XG5cbiAgICBpZiAoIW9wdGlvbnMub3JpZ2luIHx8IG9wdGlvbnMub3JpZ2luID09PSAnKicpIHtcbiAgICAgIC8vIGFsbG93IGFueSBvcmlnaW5cbiAgICAgIGhlYWRlcnMucHVzaChbe1xuICAgICAgICBrZXk6ICdBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4nLFxuICAgICAgICB2YWx1ZTogJyonXG4gICAgICB9XSk7XG4gICAgfSBlbHNlIGlmIChpc1N0cmluZyhvcHRpb25zLm9yaWdpbikpIHtcbiAgICAgIC8vIGZpeGVkIG9yaWdpblxuICAgICAgaGVhZGVycy5wdXNoKFt7XG4gICAgICAgIGtleTogJ0FjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbicsXG4gICAgICAgIHZhbHVlOiBvcHRpb25zLm9yaWdpblxuICAgICAgfV0pO1xuICAgICAgaGVhZGVycy5wdXNoKFt7XG4gICAgICAgIGtleTogJ1ZhcnknLFxuICAgICAgICB2YWx1ZTogJ09yaWdpbidcbiAgICAgIH1dKTtcbiAgICB9IGVsc2Uge1xuICAgICAgaXNBbGxvd2VkID0gaXNPcmlnaW5BbGxvd2VkKHJlcXVlc3RPcmlnaW4sIG9wdGlvbnMub3JpZ2luKTtcbiAgICAgIC8vIHJlZmxlY3Qgb3JpZ2luXG4gICAgICBoZWFkZXJzLnB1c2goW3tcbiAgICAgICAga2V5OiAnQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luJyxcbiAgICAgICAgdmFsdWU6IGlzQWxsb3dlZCA/IHJlcXVlc3RPcmlnaW4gOiBmYWxzZVxuICAgICAgfV0pO1xuICAgICAgaGVhZGVycy5wdXNoKFt7XG4gICAgICAgIGtleTogJ1ZhcnknLFxuICAgICAgICB2YWx1ZTogJ09yaWdpbidcbiAgICAgIH1dKTtcbiAgICB9XG5cbiAgICByZXR1cm4gaGVhZGVycztcbiAgfVxuXG4gIGZ1bmN0aW9uIGNvbmZpZ3VyZU1ldGhvZHMob3B0aW9ucykge1xuICAgIHZhciBtZXRob2RzID0gb3B0aW9ucy5tZXRob2RzO1xuICAgIGlmIChtZXRob2RzLmpvaW4pIHtcbiAgICAgIG1ldGhvZHMgPSBvcHRpb25zLm1ldGhvZHMuam9pbignLCcpOyAvLyAubWV0aG9kcyBpcyBhbiBhcnJheSwgc28gdHVybiBpdCBpbnRvIGEgc3RyaW5nXG4gICAgfVxuICAgIHJldHVybiB7XG4gICAgICBrZXk6ICdBY2Nlc3MtQ29udHJvbC1BbGxvdy1NZXRob2RzJyxcbiAgICAgIHZhbHVlOiBtZXRob2RzXG4gICAgfTtcbiAgfVxuXG4gIGZ1bmN0aW9uIGNvbmZpZ3VyZUNyZWRlbnRpYWxzKG9wdGlvbnMpIHtcbiAgICBpZiAob3B0aW9ucy5jcmVkZW50aWFscyA9PT0gdHJ1ZSkge1xuICAgICAgcmV0dXJuIHtcbiAgICAgICAga2V5OiAnQWNjZXNzLUNvbnRyb2wtQWxsb3ctQ3JlZGVudGlhbHMnLFxuICAgICAgICB2YWx1ZTogJ3RydWUnXG4gICAgICB9O1xuICAgIH1cbiAgICByZXR1cm4gbnVsbDtcbiAgfVxuXG4gIGZ1bmN0aW9uIGNvbmZpZ3VyZUFsbG93ZWRIZWFkZXJzKG9wdGlvbnMsIHJlcSkge1xuICAgIHZhciBhbGxvd2VkSGVhZGVycyA9IG9wdGlvbnMuYWxsb3dlZEhlYWRlcnMgfHwgb3B0aW9ucy5oZWFkZXJzO1xuICAgIHZhciBoZWFkZXJzID0gW107XG5cbiAgICBpZiAoIWFsbG93ZWRIZWFkZXJzKSB7XG4gICAgICBhbGxvd2VkSGVhZGVycyA9IHJlcS5oZWFkZXJzWydhY2Nlc3MtY29udHJvbC1yZXF1ZXN0LWhlYWRlcnMnXTsgLy8gLmhlYWRlcnMgd2Fzbid0IHNwZWNpZmllZCwgc28gcmVmbGVjdCB0aGUgcmVxdWVzdCBoZWFkZXJzXG4gICAgICBoZWFkZXJzLnB1c2goW3tcbiAgICAgICAga2V5OiAnVmFyeScsXG4gICAgICAgIHZhbHVlOiAnQWNjZXNzLUNvbnRyb2wtUmVxdWVzdC1IZWFkZXJzJ1xuICAgICAgfV0pO1xuICAgIH0gZWxzZSBpZiAoYWxsb3dlZEhlYWRlcnMuam9pbikge1xuICAgICAgYWxsb3dlZEhlYWRlcnMgPSBhbGxvd2VkSGVhZGVycy5qb2luKCcsJyk7IC8vIC5oZWFkZXJzIGlzIGFuIGFycmF5LCBzbyB0dXJuIGl0IGludG8gYSBzdHJpbmdcbiAgICB9XG4gICAgaWYgKGFsbG93ZWRIZWFkZXJzICYmIGFsbG93ZWRIZWFkZXJzLmxlbmd0aCkge1xuICAgICAgaGVhZGVycy5wdXNoKFt7XG4gICAgICAgIGtleTogJ0FjY2Vzcy1Db250cm9sLUFsbG93LUhlYWRlcnMnLFxuICAgICAgICB2YWx1ZTogYWxsb3dlZEhlYWRlcnNcbiAgICAgIH1dKTtcbiAgICB9XG5cbiAgICByZXR1cm4gaGVhZGVycztcbiAgfVxuXG4gIGZ1bmN0aW9uIGNvbmZpZ3VyZUV4cG9zZWRIZWFkZXJzKG9wdGlvbnMpIHtcbiAgICB2YXIgaGVhZGVycyA9IG9wdGlvbnMuZXhwb3NlZEhlYWRlcnM7XG4gICAgaWYgKCFoZWFkZXJzKSB7XG4gICAgICByZXR1cm4gbnVsbDtcbiAgICB9IGVsc2UgaWYgKGhlYWRlcnMuam9pbikge1xuICAgICAgaGVhZGVycyA9IGhlYWRlcnMuam9pbignLCcpOyAvLyAuaGVhZGVycyBpcyBhbiBhcnJheSwgc28gdHVybiBpdCBpbnRvIGEgc3RyaW5nXG4gICAgfVxuICAgIGlmIChoZWFkZXJzICYmIGhlYWRlcnMubGVuZ3RoKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBrZXk6ICdBY2Nlc3MtQ29udHJvbC1FeHBvc2UtSGVhZGVycycsXG4gICAgICAgIHZhbHVlOiBoZWFkZXJzXG4gICAgICB9O1xuICAgIH1cbiAgICByZXR1cm4gbnVsbDtcbiAgfVxuXG4gIGZ1bmN0aW9uIGNvbmZpZ3VyZU1heEFnZShvcHRpb25zKSB7XG4gICAgdmFyIG1heEFnZSA9ICh0eXBlb2Ygb3B0aW9ucy5tYXhBZ2UgPT09ICdudW1iZXInIHx8IG9wdGlvbnMubWF4QWdlKSAmJiBvcHRpb25zLm1heEFnZS50b1N0cmluZygpXG4gICAgaWYgKG1heEFnZSAmJiBtYXhBZ2UubGVuZ3RoKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBrZXk6ICdBY2Nlc3MtQ29udHJvbC1NYXgtQWdlJyxcbiAgICAgICAgdmFsdWU6IG1heEFnZVxuICAgICAgfTtcbiAgICB9XG4gICAgcmV0dXJuIG51bGw7XG4gIH1cblxuICBmdW5jdGlvbiBhcHBseUhlYWRlcnMoaGVhZGVycywgcmVzKSB7XG4gICAgZm9yICh2YXIgaSA9IDAsIG4gPSBoZWFkZXJzLmxlbmd0aDsgaSA8IG47IGkrKykge1xuICAgICAgdmFyIGhlYWRlciA9IGhlYWRlcnNbaV07XG4gICAgICBpZiAoaGVhZGVyKSB7XG4gICAgICAgIGlmIChBcnJheS5pc0FycmF5KGhlYWRlcikpIHtcbiAgICAgICAgICBhcHBseUhlYWRlcnMoaGVhZGVyLCByZXMpO1xuICAgICAgICB9IGVsc2UgaWYgKGhlYWRlci5rZXkgPT09ICdWYXJ5JyAmJiBoZWFkZXIudmFsdWUpIHtcbiAgICAgICAgICB2YXJ5KHJlcywgaGVhZGVyLnZhbHVlKTtcbiAgICAgICAgfSBlbHNlIGlmIChoZWFkZXIudmFsdWUpIHtcbiAgICAgICAgICByZXMuc2V0SGVhZGVyKGhlYWRlci5rZXksIGhlYWRlci52YWx1ZSk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICBmdW5jdGlvbiBjb3JzKG9wdGlvbnMsIHJlcSwgcmVzLCBuZXh0KSB7XG4gICAgdmFyIGhlYWRlcnMgPSBbXSxcbiAgICAgIG1ldGhvZCA9IHJlcS5tZXRob2QgJiYgcmVxLm1ldGhvZC50b1VwcGVyQ2FzZSAmJiByZXEubWV0aG9kLnRvVXBwZXJDYXNlKCk7XG5cbiAgICBpZiAobWV0aG9kID09PSAnT1BUSU9OUycpIHtcbiAgICAgIC8vIHByZWZsaWdodFxuICAgICAgaGVhZGVycy5wdXNoKGNvbmZpZ3VyZU9yaWdpbihvcHRpb25zLCByZXEpKTtcbiAgICAgIGhlYWRlcnMucHVzaChjb25maWd1cmVDcmVkZW50aWFscyhvcHRpb25zLCByZXEpKTtcbiAgICAgIGhlYWRlcnMucHVzaChjb25maWd1cmVNZXRob2RzKG9wdGlvbnMsIHJlcSkpO1xuICAgICAgaGVhZGVycy5wdXNoKGNvbmZpZ3VyZUFsbG93ZWRIZWFkZXJzKG9wdGlvbnMsIHJlcSkpO1xuICAgICAgaGVhZGVycy5wdXNoKGNvbmZpZ3VyZU1heEFnZShvcHRpb25zLCByZXEpKTtcbiAgICAgIGhlYWRlcnMucHVzaChjb25maWd1cmVFeHBvc2VkSGVhZGVycyhvcHRpb25zLCByZXEpKTtcbiAgICAgIGFwcGx5SGVhZGVycyhoZWFkZXJzLCByZXMpO1xuXG4gICAgICBpZiAob3B0aW9ucy5wcmVmbGlnaHRDb250aW51ZSkge1xuICAgICAgICBuZXh0KCk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAvLyBTYWZhcmkgKGFuZCBwb3RlbnRpYWxseSBvdGhlciBicm93c2VycykgbmVlZCBjb250ZW50LWxlbmd0aCAwLFxuICAgICAgICAvLyAgIGZvciAyMDQgb3IgdGhleSBqdXN0IGhhbmcgd2FpdGluZyBmb3IgYSBib2R5XG4gICAgICAgIHJlcy5zdGF0dXNDb2RlID0gb3B0aW9ucy5vcHRpb25zU3VjY2Vzc1N0YXR1cztcbiAgICAgICAgcmVzLnNldEhlYWRlcignQ29udGVudC1MZW5ndGgnLCAnMCcpO1xuICAgICAgICByZXMuZW5kKCk7XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIGFjdHVhbCByZXNwb25zZVxuICAgICAgaGVhZGVycy5wdXNoKGNvbmZpZ3VyZU9yaWdpbihvcHRpb25zLCByZXEpKTtcbiAgICAgIGhlYWRlcnMucHVzaChjb25maWd1cmVDcmVkZW50aWFscyhvcHRpb25zLCByZXEpKTtcbiAgICAgIGhlYWRlcnMucHVzaChjb25maWd1cmVFeHBvc2VkSGVhZGVycyhvcHRpb25zLCByZXEpKTtcbiAgICAgIGFwcGx5SGVhZGVycyhoZWFkZXJzLCByZXMpO1xuICAgICAgbmV4dCgpO1xuICAgIH1cbiAgfVxuXG4gIGZ1bmN0aW9uIG1pZGRsZXdhcmVXcmFwcGVyKG8pIHtcbiAgICAvLyBpZiBvcHRpb25zIGFyZSBzdGF0aWMgKGVpdGhlciB2aWEgZGVmYXVsdHMgb3IgY3VzdG9tIG9wdGlvbnMgcGFzc2VkIGluKSwgd3JhcCBpbiBhIGZ1bmN0aW9uXG4gICAgdmFyIG9wdGlvbnNDYWxsYmFjayA9IG51bGw7XG4gICAgaWYgKHR5cGVvZiBvID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICBvcHRpb25zQ2FsbGJhY2sgPSBvO1xuICAgIH0gZWxzZSB7XG4gICAgICBvcHRpb25zQ2FsbGJhY2sgPSBmdW5jdGlvbiAocmVxLCBjYikge1xuICAgICAgICBjYihudWxsLCBvKTtcbiAgICAgIH07XG4gICAgfVxuXG4gICAgcmV0dXJuIGZ1bmN0aW9uIGNvcnNNaWRkbGV3YXJlKHJlcSwgcmVzLCBuZXh0KSB7XG4gICAgICBvcHRpb25zQ2FsbGJhY2socmVxLCBmdW5jdGlvbiAoZXJyLCBvcHRpb25zKSB7XG4gICAgICAgIGlmIChlcnIpIHtcbiAgICAgICAgICBuZXh0KGVycik7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdmFyIGNvcnNPcHRpb25zID0gYXNzaWduKHt9LCBkZWZhdWx0cywgb3B0aW9ucyk7XG4gICAgICAgICAgdmFyIG9yaWdpbkNhbGxiYWNrID0gbnVsbDtcbiAgICAgICAgICBpZiAoY29yc09wdGlvbnMub3JpZ2luICYmIHR5cGVvZiBjb3JzT3B0aW9ucy5vcmlnaW4gPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAgICAgIG9yaWdpbkNhbGxiYWNrID0gY29yc09wdGlvbnMub3JpZ2luO1xuICAgICAgICAgIH0gZWxzZSBpZiAoY29yc09wdGlvbnMub3JpZ2luKSB7XG4gICAgICAgICAgICBvcmlnaW5DYWxsYmFjayA9IGZ1bmN0aW9uIChvcmlnaW4sIGNiKSB7XG4gICAgICAgICAgICAgIGNiKG51bGwsIGNvcnNPcHRpb25zLm9yaWdpbik7XG4gICAgICAgICAgICB9O1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChvcmlnaW5DYWxsYmFjaykge1xuICAgICAgICAgICAgb3JpZ2luQ2FsbGJhY2socmVxLmhlYWRlcnMub3JpZ2luLCBmdW5jdGlvbiAoZXJyMiwgb3JpZ2luKSB7XG4gICAgICAgICAgICAgIGlmIChlcnIyIHx8ICFvcmlnaW4pIHtcbiAgICAgICAgICAgICAgICBuZXh0KGVycjIpO1xuICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIGNvcnNPcHRpb25zLm9yaWdpbiA9IG9yaWdpbjtcbiAgICAgICAgICAgICAgICBjb3JzKGNvcnNPcHRpb25zLCByZXEsIHJlcywgbmV4dCk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBuZXh0KCk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9O1xuICB9XG5cbiAgLy8gY2FuIHBhc3MgZWl0aGVyIGFuIG9wdGlvbnMgaGFzaCwgYW4gb3B0aW9ucyBkZWxlZ2F0ZSwgb3Igbm90aGluZ1xuICBtb2R1bGUuZXhwb3J0cyA9IG1pZGRsZXdhcmVXcmFwcGVyO1xuXG59KCkpO1xuIiwiLypcbm9iamVjdC1hc3NpZ25cbihjKSBTaW5kcmUgU29yaHVzXG5AbGljZW5zZSBNSVRcbiovXG5cbid1c2Ugc3RyaWN0Jztcbi8qIGVzbGludC1kaXNhYmxlIG5vLXVudXNlZC12YXJzICovXG52YXIgZ2V0T3duUHJvcGVydHlTeW1ib2xzID0gT2JqZWN0LmdldE93blByb3BlcnR5U3ltYm9scztcbnZhciBoYXNPd25Qcm9wZXJ0eSA9IE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHk7XG52YXIgcHJvcElzRW51bWVyYWJsZSA9IE9iamVjdC5wcm90b3R5cGUucHJvcGVydHlJc0VudW1lcmFibGU7XG5cbmZ1bmN0aW9uIHRvT2JqZWN0KHZhbCkge1xuXHRpZiAodmFsID09PSBudWxsIHx8IHZhbCA9PT0gdW5kZWZpbmVkKSB7XG5cdFx0dGhyb3cgbmV3IFR5cGVFcnJvcignT2JqZWN0LmFzc2lnbiBjYW5ub3QgYmUgY2FsbGVkIHdpdGggbnVsbCBvciB1bmRlZmluZWQnKTtcblx0fVxuXG5cdHJldHVybiBPYmplY3QodmFsKTtcbn1cblxuZnVuY3Rpb24gc2hvdWxkVXNlTmF0aXZlKCkge1xuXHR0cnkge1xuXHRcdGlmICghT2JqZWN0LmFzc2lnbikge1xuXHRcdFx0cmV0dXJuIGZhbHNlO1xuXHRcdH1cblxuXHRcdC8vIERldGVjdCBidWdneSBwcm9wZXJ0eSBlbnVtZXJhdGlvbiBvcmRlciBpbiBvbGRlciBWOCB2ZXJzaW9ucy5cblxuXHRcdC8vIGh0dHBzOi8vYnVncy5jaHJvbWl1bS5vcmcvcC92OC9pc3N1ZXMvZGV0YWlsP2lkPTQxMThcblx0XHR2YXIgdGVzdDEgPSBuZXcgU3RyaW5nKCdhYmMnKTsgIC8vIGVzbGludC1kaXNhYmxlLWxpbmUgbm8tbmV3LXdyYXBwZXJzXG5cdFx0dGVzdDFbNV0gPSAnZGUnO1xuXHRcdGlmIChPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0ZXN0MSlbMF0gPT09ICc1Jykge1xuXHRcdFx0cmV0dXJuIGZhbHNlO1xuXHRcdH1cblxuXHRcdC8vIGh0dHBzOi8vYnVncy5jaHJvbWl1bS5vcmcvcC92OC9pc3N1ZXMvZGV0YWlsP2lkPTMwNTZcblx0XHR2YXIgdGVzdDIgPSB7fTtcblx0XHRmb3IgKHZhciBpID0gMDsgaSA8IDEwOyBpKyspIHtcblx0XHRcdHRlc3QyWydfJyArIFN0cmluZy5mcm9tQ2hhckNvZGUoaSldID0gaTtcblx0XHR9XG5cdFx0dmFyIG9yZGVyMiA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHRlc3QyKS5tYXAoZnVuY3Rpb24gKG4pIHtcblx0XHRcdHJldHVybiB0ZXN0MltuXTtcblx0XHR9KTtcblx0XHRpZiAob3JkZXIyLmpvaW4oJycpICE9PSAnMDEyMzQ1Njc4OScpIHtcblx0XHRcdHJldHVybiBmYWxzZTtcblx0XHR9XG5cblx0XHQvLyBodHRwczovL2J1Z3MuY2hyb21pdW0ub3JnL3AvdjgvaXNzdWVzL2RldGFpbD9pZD0zMDU2XG5cdFx0dmFyIHRlc3QzID0ge307XG5cdFx0J2FiY2RlZmdoaWprbG1ub3BxcnN0Jy5zcGxpdCgnJykuZm9yRWFjaChmdW5jdGlvbiAobGV0dGVyKSB7XG5cdFx0XHR0ZXN0M1tsZXR0ZXJdID0gbGV0dGVyO1xuXHRcdH0pO1xuXHRcdGlmIChPYmplY3Qua2V5cyhPYmplY3QuYXNzaWduKHt9LCB0ZXN0MykpLmpvaW4oJycpICE9PVxuXHRcdFx0XHQnYWJjZGVmZ2hpamtsbW5vcHFyc3QnKSB7XG5cdFx0XHRyZXR1cm4gZmFsc2U7XG5cdFx0fVxuXG5cdFx0cmV0dXJuIHRydWU7XG5cdH0gY2F0Y2ggKGVycikge1xuXHRcdC8vIFdlIGRvbid0IGV4cGVjdCBhbnkgb2YgdGhlIGFib3ZlIHRvIHRocm93LCBidXQgYmV0dGVyIHRvIGJlIHNhZmUuXG5cdFx0cmV0dXJuIGZhbHNlO1xuXHR9XG59XG5cbm1vZHVsZS5leHBvcnRzID0gc2hvdWxkVXNlTmF0aXZlKCkgPyBPYmplY3QuYXNzaWduIDogZnVuY3Rpb24gKHRhcmdldCwgc291cmNlKSB7XG5cdHZhciBmcm9tO1xuXHR2YXIgdG8gPSB0b09iamVjdCh0YXJnZXQpO1xuXHR2YXIgc3ltYm9scztcblxuXHRmb3IgKHZhciBzID0gMTsgcyA8IGFyZ3VtZW50cy5sZW5ndGg7IHMrKykge1xuXHRcdGZyb20gPSBPYmplY3QoYXJndW1lbnRzW3NdKTtcblxuXHRcdGZvciAodmFyIGtleSBpbiBmcm9tKSB7XG5cdFx0XHRpZiAoaGFzT3duUHJvcGVydHkuY2FsbChmcm9tLCBrZXkpKSB7XG5cdFx0XHRcdHRvW2tleV0gPSBmcm9tW2tleV07XG5cdFx0XHR9XG5cdFx0fVxuXG5cdFx0aWYgKGdldE93blByb3BlcnR5U3ltYm9scykge1xuXHRcdFx0c3ltYm9scyA9IGdldE93blByb3BlcnR5U3ltYm9scyhmcm9tKTtcblx0XHRcdGZvciAodmFyIGkgPSAwOyBpIDwgc3ltYm9scy5sZW5ndGg7IGkrKykge1xuXHRcdFx0XHRpZiAocHJvcElzRW51bWVyYWJsZS5jYWxsKGZyb20sIHN5bWJvbHNbaV0pKSB7XG5cdFx0XHRcdFx0dG9bc3ltYm9sc1tpXV0gPSBmcm9tW3N5bWJvbHNbaV1dO1xuXHRcdFx0XHR9XG5cdFx0XHR9XG5cdFx0fVxuXHR9XG5cblx0cmV0dXJuIHRvO1xufTtcbiIsIi8qIVxuICogdmFyeVxuICogQ29weXJpZ2h0KGMpIDIwMTQtMjAxNyBEb3VnbGFzIENocmlzdG9waGVyIFdpbHNvblxuICogTUlUIExpY2Vuc2VkXG4gKi9cblxuJ3VzZSBzdHJpY3QnXG5cbi8qKlxuICogTW9kdWxlIGV4cG9ydHMuXG4gKi9cblxubW9kdWxlLmV4cG9ydHMgPSB2YXJ5XG5tb2R1bGUuZXhwb3J0cy5hcHBlbmQgPSBhcHBlbmRcblxuLyoqXG4gKiBSZWdFeHAgdG8gbWF0Y2ggZmllbGQtbmFtZSBpbiBSRkMgNzIzMCBzZWMgMy4yXG4gKlxuICogZmllbGQtbmFtZSAgICA9IHRva2VuXG4gKiB0b2tlbiAgICAgICAgID0gMSp0Y2hhclxuICogdGNoYXIgICAgICAgICA9IFwiIVwiIC8gXCIjXCIgLyBcIiRcIiAvIFwiJVwiIC8gXCImXCIgLyBcIidcIiAvIFwiKlwiXG4gKiAgICAgICAgICAgICAgIC8gXCIrXCIgLyBcIi1cIiAvIFwiLlwiIC8gXCJeXCIgLyBcIl9cIiAvIFwiYFwiIC8gXCJ8XCIgLyBcIn5cIlxuICogICAgICAgICAgICAgICAvIERJR0lUIC8gQUxQSEFcbiAqICAgICAgICAgICAgICAgOyBhbnkgVkNIQVIsIGV4Y2VwdCBkZWxpbWl0ZXJzXG4gKi9cblxudmFyIEZJRUxEX05BTUVfUkVHRVhQID0gL15bISMkJSYnKitcXC0uXl9gfH4wLTlBLVphLXpdKyQvXG5cbi8qKlxuICogQXBwZW5kIGEgZmllbGQgdG8gYSB2YXJ5IGhlYWRlci5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gaGVhZGVyXG4gKiBAcGFyYW0ge1N0cmluZ3xBcnJheX0gZmllbGRcbiAqIEByZXR1cm4ge1N0cmluZ31cbiAqIEBwdWJsaWNcbiAqL1xuXG5mdW5jdGlvbiBhcHBlbmQgKGhlYWRlciwgZmllbGQpIHtcbiAgaWYgKHR5cGVvZiBoZWFkZXIgIT09ICdzdHJpbmcnKSB7XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcignaGVhZGVyIGFyZ3VtZW50IGlzIHJlcXVpcmVkJylcbiAgfVxuXG4gIGlmICghZmllbGQpIHtcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdmaWVsZCBhcmd1bWVudCBpcyByZXF1aXJlZCcpXG4gIH1cblxuICAvLyBnZXQgZmllbGRzIGFycmF5XG4gIHZhciBmaWVsZHMgPSAhQXJyYXkuaXNBcnJheShmaWVsZClcbiAgICA/IHBhcnNlKFN0cmluZyhmaWVsZCkpXG4gICAgOiBmaWVsZFxuXG4gIC8vIGFzc2VydCBvbiBpbnZhbGlkIGZpZWxkIG5hbWVzXG4gIGZvciAodmFyIGogPSAwOyBqIDwgZmllbGRzLmxlbmd0aDsgaisrKSB7XG4gICAgaWYgKCFGSUVMRF9OQU1FX1JFR0VYUC50ZXN0KGZpZWxkc1tqXSkpIHtcbiAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ2ZpZWxkIGFyZ3VtZW50IGNvbnRhaW5zIGFuIGludmFsaWQgaGVhZGVyIG5hbWUnKVxuICAgIH1cbiAgfVxuXG4gIC8vIGV4aXN0aW5nLCB1bnNwZWNpZmllZCB2YXJ5XG4gIGlmIChoZWFkZXIgPT09ICcqJykge1xuICAgIHJldHVybiBoZWFkZXJcbiAgfVxuXG4gIC8vIGVudW1lcmF0ZSBjdXJyZW50IHZhbHVlc1xuICB2YXIgdmFsID0gaGVhZGVyXG4gIHZhciB2YWxzID0gcGFyc2UoaGVhZGVyLnRvTG93ZXJDYXNlKCkpXG5cbiAgLy8gdW5zcGVjaWZpZWQgdmFyeVxuICBpZiAoZmllbGRzLmluZGV4T2YoJyonKSAhPT0gLTEgfHwgdmFscy5pbmRleE9mKCcqJykgIT09IC0xKSB7XG4gICAgcmV0dXJuICcqJ1xuICB9XG5cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBmaWVsZHMubGVuZ3RoOyBpKyspIHtcbiAgICB2YXIgZmxkID0gZmllbGRzW2ldLnRvTG93ZXJDYXNlKClcblxuICAgIC8vIGFwcGVuZCB2YWx1ZSAoY2FzZS1wcmVzZXJ2aW5nKVxuICAgIGlmICh2YWxzLmluZGV4T2YoZmxkKSA9PT0gLTEpIHtcbiAgICAgIHZhbHMucHVzaChmbGQpXG4gICAgICB2YWwgPSB2YWxcbiAgICAgICAgPyB2YWwgKyAnLCAnICsgZmllbGRzW2ldXG4gICAgICAgIDogZmllbGRzW2ldXG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIHZhbFxufVxuXG4vKipcbiAqIFBhcnNlIGEgdmFyeSBoZWFkZXIgaW50byBhbiBhcnJheS5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gaGVhZGVyXG4gKiBAcmV0dXJuIHtBcnJheX1cbiAqIEBwcml2YXRlXG4gKi9cblxuZnVuY3Rpb24gcGFyc2UgKGhlYWRlcikge1xuICB2YXIgZW5kID0gMFxuICB2YXIgbGlzdCA9IFtdXG4gIHZhciBzdGFydCA9IDBcblxuICAvLyBnYXRoZXIgdG9rZW5zXG4gIGZvciAodmFyIGkgPSAwLCBsZW4gPSBoZWFkZXIubGVuZ3RoOyBpIDwgbGVuOyBpKyspIHtcbiAgICBzd2l0Y2ggKGhlYWRlci5jaGFyQ29kZUF0KGkpKSB7XG4gICAgICBjYXNlIDB4MjA6IC8qICAgKi9cbiAgICAgICAgaWYgKHN0YXJ0ID09PSBlbmQpIHtcbiAgICAgICAgICBzdGFydCA9IGVuZCA9IGkgKyAxXG4gICAgICAgIH1cbiAgICAgICAgYnJlYWtcbiAgICAgIGNhc2UgMHgyYzogLyogLCAqL1xuICAgICAgICBsaXN0LnB1c2goaGVhZGVyLnN1YnN0cmluZyhzdGFydCwgZW5kKSlcbiAgICAgICAgc3RhcnQgPSBlbmQgPSBpICsgMVxuICAgICAgICBicmVha1xuICAgICAgZGVmYXVsdDpcbiAgICAgICAgZW5kID0gaSArIDFcbiAgICAgICAgYnJlYWtcbiAgICB9XG4gIH1cblxuICAvLyBmaW5hbCB0b2tlblxuICBsaXN0LnB1c2goaGVhZGVyLnN1YnN0cmluZyhzdGFydCwgZW5kKSlcblxuICByZXR1cm4gbGlzdFxufVxuXG4vKipcbiAqIE1hcmsgdGhhdCBhIHJlcXVlc3QgaXMgdmFyaWVkIG9uIGEgaGVhZGVyIGZpZWxkLlxuICpcbiAqIEBwYXJhbSB7T2JqZWN0fSByZXNcbiAqIEBwYXJhbSB7U3RyaW5nfEFycmF5fSBmaWVsZFxuICogQHB1YmxpY1xuICovXG5cbmZ1bmN0aW9uIHZhcnkgKHJlcywgZmllbGQpIHtcbiAgaWYgKCFyZXMgfHwgIXJlcy5nZXRIZWFkZXIgfHwgIXJlcy5zZXRIZWFkZXIpIHtcbiAgICAvLyBxdWFjayBxdWFja1xuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3JlcyBhcmd1bWVudCBpcyByZXF1aXJlZCcpXG4gIH1cblxuICAvLyBnZXQgZXhpc3RpbmcgaGVhZGVyXG4gIHZhciB2YWwgPSByZXMuZ2V0SGVhZGVyKCdWYXJ5JykgfHwgJydcbiAgdmFyIGhlYWRlciA9IEFycmF5LmlzQXJyYXkodmFsKVxuICAgID8gdmFsLmpvaW4oJywgJylcbiAgICA6IFN0cmluZyh2YWwpXG5cbiAgLy8gc2V0IG5ldyBoZWFkZXJcbiAgaWYgKCh2YWwgPSBhcHBlbmQoaGVhZGVyLCBmaWVsZCkpKSB7XG4gICAgcmVzLnNldEhlYWRlcignVmFyeScsIHZhbClcbiAgfVxufVxuIiwiZXhwb3J0IGNvbnN0IFBST0pFQ1RfSUQgPSAnOTg3enl4JztcbmV4cG9ydCBjb25zdCBMT0dfMV9JRCA9ICdhYmMxMjMnO1xuZXhwb3J0IGNvbnN0IExPR18yX0lEID0gJ2RlZjQ1Nic7XG4iLCJleHBvcnQgKiBmcm9tICcuL2NvbnN0YW50cyc7XG5leHBvcnQgKiBmcm9tICcuL3R5cGVzJztcbiIsImltcG9ydCB7IFV1aWQgfSBmcm9tICcuLi8uLi9zZXJ2ZXIvc3JjL2RvbWFpbi9lbnRpdGllcy9VdWlkJztcbmV4cG9ydCB0eXBlIERhdGVMaWtlID0gRGF0ZSB8IHN0cmluZztcblxuZXhwb3J0IHR5cGUgTG9nRW50cnlSZXNwb25zZSA9IHtcblx0aWQ6IHN0cmluZztcblx0bG9nSWQ6IHN0cmluZztcblx0bG9nRGF0ZTogRGF0ZUxpa2U7XG5cdGxvZ1ZhbHVlOiBudW1iZXI7XG59O1xuXG5leHBvcnQgdHlwZSBMb2dFbnRyeVJlcXVlc3QgPSB7XG5cdGxvZ0RhdGU6IERhdGVMaWtlO1xuXHRsb2dWYWx1ZTogbnVtYmVyO1xufTtcblxuZXhwb3J0IHR5cGUgRWRpdExvZ0VudHJ5UmVxdWVzdCA9IExvZ0VudHJ5UmVxdWVzdCAmIHtcblx0aWQ6IFV1aWQ7XG5cdGxvZ0lkOiBzdHJpbmc7XG59O1xuXG5leHBvcnQgZW51bSBIdHRwU3RhdHVzQ29kZSB7XG5cdE9LID0gMjAwLFxuXHRDUkVBVEVEID0gMjAxLFxuXHRURU1QT1JBUllfUkVESVJFQ1QgPSAzMDIsXG5cdElOVkFMSURfUkVRVUVTVCA9IDQwMCxcblx0SU5WQUxJRF9DUkVERU5USUFMUyA9IDQwMSxcblx0VU5BVVRIT1JJWkVEX1JFUVVFU1QgPSA0MDMsXG5cdE5PVF9GT1VORCA9IDQwNCxcblx0Q09ORkxJQ1QgPSA0MDksXG5cdE1JU1NJTkdfUVVFUllfUEFSQU0gPSA0MjIsXG5cdE1JU1NJTkdfREFUQSA9IDQyMixcblx0SU5WQUxJRF9EQVRBID0gNDIyLFxuXHRTRVJWRVJfRVJST1IgPSA1MDAsXG5cdFVOSU1QTEVNRU5URURfRVJST1IgPSA1MDEsXG59XG4iLCJpbXBvcnQge1xuXHRMb2dFbnRyeVJlcXVlc3QsXG5cdExvZ0VudHJ5UmVzcG9uc2UsXG5cdEVkaXRMb2dFbnRyeVJlcXVlc3QsXG59IGZyb20gJ0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNoYXJlZCc7XG5pbXBvcnQgeyBMb2dFbnRyeSB9IGZyb20gJy4uLy4uL2RvbWFpbi9lbnRpdGllcy9Mb2dFbnRyeSc7XG5cbmV4cG9ydCBjbGFzcyBMb2dFbnRyaWVzQXBpTWFwcGVyIHtcblx0cHVibGljIHRvUmVzcG9uc2UobG9nRW50cnk6IExvZ0VudHJ5KTogTG9nRW50cnlSZXNwb25zZSB7XG5cdFx0cmV0dXJuIHtcblx0XHRcdGlkOiBsb2dFbnRyeS5pZC50b1N0cmluZygpLFxuXHRcdFx0bG9nSWQ6IGxvZ0VudHJ5LmxvZ0lkLFxuXHRcdFx0bG9nRGF0ZTogbG9nRW50cnkubG9nRGF0ZSxcblx0XHRcdGxvZ1ZhbHVlOiBsb2dFbnRyeS5sb2dWYWx1ZSxcblx0XHR9O1xuXHR9XG5cblx0cHVibGljIGZyb21DcmVhdGVSZXF1ZXN0KFxuXHRcdGxvZ0lkOiBzdHJpbmcsXG5cdFx0Y3JlYXRlTG9nRW50cnk6IExvZ0VudHJ5UmVxdWVzdFxuXHQpOiBMb2dFbnRyeSB7XG5cdFx0cmV0dXJuIExvZ0VudHJ5LmNyZWF0ZSh7XG5cdFx0XHRsb2dJZCxcblx0XHRcdGxvZ0RhdGU6IG5ldyBEYXRlKGNyZWF0ZUxvZ0VudHJ5LmxvZ0RhdGUpLFxuXHRcdFx0bG9nVmFsdWU6IGNyZWF0ZUxvZ0VudHJ5LmxvZ1ZhbHVlLFxuXHRcdH0pO1xuXHR9XG5cblx0cHVibGljIGZyb21VcGRhdGVSZXF1ZXN0KHVwZGF0ZUxvZ0VudHJ5OiBFZGl0TG9nRW50cnlSZXF1ZXN0KTogTG9nRW50cnkge1xuXHRcdHJldHVybiBMb2dFbnRyeS51cGRhdGUoe1xuXHRcdFx0aWQ6IHVwZGF0ZUxvZ0VudHJ5LmlkLFxuXHRcdFx0bG9nSWQ6IHVwZGF0ZUxvZ0VudHJ5LmxvZ0lkLFxuXHRcdFx0bG9nRGF0ZTogbmV3IERhdGUodXBkYXRlTG9nRW50cnkubG9nRGF0ZSksXG5cdFx0XHRsb2dWYWx1ZTogdXBkYXRlTG9nRW50cnkubG9nVmFsdWUsXG5cdFx0fSk7XG5cdH1cbn1cbiIsImltcG9ydCB7XG5cdExvZ0VudHJ5UmVxdWVzdCxcblx0TG9nRW50cnlSZXNwb25zZSxcblx0RWRpdExvZ0VudHJ5UmVxdWVzdCxcbn0gZnJvbSAnQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2hhcmVkJztcbmltcG9ydCB7IExvZ0VudHJpZXNRdWVyeVJlcG9zaXRvcnkgfSBmcm9tICcuLi8uLi9wZXJzaXN0ZW5jZS9yZXBvc2l0b3JpZXMvTG9nRW50cmllc1F1ZXJ5UmVwb3NpdG9yeSc7XG5pbXBvcnQgeyBMb2dFbnRyaWVzUmVwb3NpdG9yeSB9IGZyb20gJy4uLy4uL3BlcnNpc3RlbmNlL3JlcG9zaXRvcmllcy9Mb2dFbnRyaWVzUmVwb3NpdG9yeSc7XG5pbXBvcnQgeyBMb2dFbnRyaWVzQXBpTWFwcGVyIH0gZnJvbSAnLi4vbWFwcGVycy9Mb2dFbnRyaWVzQXBpTWFwcGVyJztcblxuZXhwb3J0IGNsYXNzIExvZ0VudHJpZXNTZXJ2aWNlIHtcblx0Z2V0TG9nRW50cmllcyhsb2dJZDogc3RyaW5nKTogUHJvbWlzZTxMb2dFbnRyeVJlc3BvbnNlW10+IHtcblx0XHRjb25zdCBsb2dFbnRyeVJlcG9zaXRvcnkgPSBuZXcgTG9nRW50cmllc1F1ZXJ5UmVwb3NpdG9yeSgpO1xuXHRcdHJldHVybiBsb2dFbnRyeVJlcG9zaXRvcnkuZmluZExvZ0VudHJpZXMobG9nSWQpO1xuXHR9XG5cblx0YXN5bmMgY3JlYXRlTG9nRW50cnkoXG5cdFx0bG9nSWQ6IHN0cmluZyxcblx0XHRjcmVhdGVMb2dFbnRyeTogTG9nRW50cnlSZXF1ZXN0XG5cdCk6IFByb21pc2U8TG9nRW50cnlSZXNwb25zZT4ge1xuXHRcdGNvbnN0IG1hcHBlciA9IG5ldyBMb2dFbnRyaWVzQXBpTWFwcGVyKCk7XG5cdFx0Y29uc3QgbG9nRW50cnkgPSBtYXBwZXIuZnJvbUNyZWF0ZVJlcXVlc3QobG9nSWQsIGNyZWF0ZUxvZ0VudHJ5KTtcblx0XHRjb25zdCByZXBvc2l0b3J5ID0gbmV3IExvZ0VudHJpZXNSZXBvc2l0b3J5KGxvZ0lkKTtcblx0XHRjb25zdCBuZXdFbnRyeSA9IGF3YWl0IHJlcG9zaXRvcnkuY3JlYXRlTG9nRW50cnkobG9nRW50cnkpO1xuXHRcdHJldHVybiBtYXBwZXIudG9SZXNwb25zZShuZXdFbnRyeSk7XG5cdH1cblxuXHRhc3luYyBkZWxldGVMb2dFbnRyeShsb2dJZDogc3RyaW5nLCBsb2dFbnRyeUlkOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuXHRcdGNvbnN0IGxvZ0VudHJ5UmVwb3NpdG9yeSA9IG5ldyBMb2dFbnRyaWVzUmVwb3NpdG9yeShsb2dJZCk7XG5cdFx0Y29uc3QgbG9nRW50cnkgPSBhd2FpdCBsb2dFbnRyeVJlcG9zaXRvcnkuZmluZEJ5SWQobG9nRW50cnlJZCk7XG5cdFx0cmV0dXJuIGxvZ0VudHJ5UmVwb3NpdG9yeS5kZXN0cm95TG9nRW50cnkobG9nRW50cnkpO1xuXHR9XG5cblx0YXN5bmMgdXBkYXRlTG9nRW50cnkoXG5cdFx0dXBkYXRlTG9nRW50cnk6IEVkaXRMb2dFbnRyeVJlcXVlc3Rcblx0KTogUHJvbWlzZTxMb2dFbnRyeVJlc3BvbnNlPiB7XG5cdFx0Y29uc3QgbWFwcGVyID0gbmV3IExvZ0VudHJpZXNBcGlNYXBwZXIoKTtcblx0XHRjb25zdCBsb2dFbnRyeSA9IG1hcHBlci5mcm9tVXBkYXRlUmVxdWVzdCh1cGRhdGVMb2dFbnRyeSk7XG5cdFx0Y29uc3QgcmVwb3NpdG9yeSA9IG5ldyBMb2dFbnRyaWVzUmVwb3NpdG9yeSh1cGRhdGVMb2dFbnRyeS5sb2dJZCk7XG5cdFx0Y29uc3QgdXBkYXRlZEVudHJ5ID0gYXdhaXQgcmVwb3NpdG9yeS51cGRhdGVMb2dFbnRyeShsb2dFbnRyeSk7XG5cdFx0cmV0dXJuIG1hcHBlci50b1Jlc3BvbnNlKHVwZGF0ZWRFbnRyeSk7XG5cdH1cbn1cbiIsImltcG9ydCB7IFV1aWQgfSBmcm9tICcuL1V1aWQnO1xuXG5leHBvcnQgY2xhc3MgRW50aXR5PFQ+IHtcbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG5vLXVuZGVyc2NvcmUtZGFuZ2xlXG4gIHByb3RlY3RlZCByZWFkb25seSBfaWQ6IFV1aWQ7XG5cbiAgcHJvdGVjdGVkIGNvbnN0cnVjdG9yKHByb3RlY3RlZCBwcm9wczogVCwgaWQ/OiBVdWlkKSB7XG4gICAgdGhpcy5faWQgPSBpZCB8fCBVdWlkLmNyZWF0ZSgpO1xuICB9XG5cbiAgZ2V0IGlkKCk6IFV1aWQge1xuICAgIHJldHVybiB0aGlzLl9pZDtcbiAgfVxufVxuIiwiaW1wb3J0IHsgVmFsaWRhdGlvbkVycm9yIH0gZnJvbSAnLi4vLi4vc2hhcmVkL2Vycm9ycyc7XG5pbXBvcnQgeyBFbnRpdHkgfSBmcm9tICcuL0VudGl0eSc7XG5pbXBvcnQgeyBVdWlkIH0gZnJvbSAnLi9VdWlkJztcblxuaW50ZXJmYWNlIExvZ0VudHJ5UHJvcHMge1xuXHRsb2dEYXRlOiBEYXRlO1xuXHRsb2dWYWx1ZTogbnVtYmVyO1xuXHRsb2dJZDogc3RyaW5nO1xufVxuXG50eXBlIENyZWF0ZUxvZ0VudHJ5UHJvcHMgPSBMb2dFbnRyeVByb3BzO1xudHlwZSBVcGRhdGVMb2dFbnRyeVByb3BzID0gTG9nRW50cnlQcm9wcyAmIHsgaWQ6IFV1aWQgfTtcblxuZXhwb3J0IGNsYXNzIExvZ0VudHJ5IGV4dGVuZHMgRW50aXR5PExvZ0VudHJ5UHJvcHM+IHtcblx0c3RhdGljIGNyZWF0ZUZyb21QZXJzaXN0ZW5jZShwcm9wczogTG9nRW50cnlQcm9wcywgaWQ6IHN0cmluZykge1xuXHRcdHJldHVybiBuZXcgTG9nRW50cnkocHJvcHMsIFV1aWQuY3JlYXRlKGlkKSk7XG5cdH1cblxuXHRzdGF0aWMgY3JlYXRlKGNyZWF0ZUxvZ0VudHJ5UHJvcHM6IENyZWF0ZUxvZ0VudHJ5UHJvcHMpIHtcblx0XHRpZiAoIXRoaXMuaXNWYWxpZChjcmVhdGVMb2dFbnRyeVByb3BzKSkge1xuXHRcdFx0dGhyb3cgbmV3IFZhbGlkYXRpb25FcnJvcihcblx0XHRcdFx0J0Nhbm5vdCBjcmVhdGUgbG9nIGVudHJ5LiBQcm9wcyBhcmUgbm90IHZhbGlkLidcblx0XHRcdCk7XG5cdFx0fVxuXHRcdHJldHVybiBuZXcgTG9nRW50cnkoY3JlYXRlTG9nRW50cnlQcm9wcyk7XG5cdH1cblxuXHRzdGF0aWMgdXBkYXRlKHVwZGF0ZUxvZ0VudHJ5UHJvcHM6IFVwZGF0ZUxvZ0VudHJ5UHJvcHMpIHtcblx0XHRpZiAoIXRoaXMuaXNWYWxpZCh1cGRhdGVMb2dFbnRyeVByb3BzKSkge1xuXHRcdFx0dGhyb3cgbmV3IFZhbGlkYXRpb25FcnJvcihcblx0XHRcdFx0J0Nhbm5vdCB1cGRhdGUgbG9nIGVudHJ5LiBQcm9wcyBhcmUgbm90IHZhbGlkLidcblx0XHRcdCk7XG5cdFx0fVxuXHRcdHJldHVybiBuZXcgTG9nRW50cnkodXBkYXRlTG9nRW50cnlQcm9wcywgdXBkYXRlTG9nRW50cnlQcm9wcy5pZCk7XG5cdH1cblxuXHRwcml2YXRlIHN0YXRpYyBpc1ZhbGlkKGNyZWF0ZUxvZ0VudHJ5UHJvcHM6IENyZWF0ZUxvZ0VudHJ5UHJvcHMpOiBib29sZWFuIHtcblx0XHRyZXR1cm4gdHlwZW9mIGNyZWF0ZUxvZ0VudHJ5UHJvcHMubG9nVmFsdWUgPT09ICdudW1iZXInO1xuXHR9XG5cblx0Z2V0IGxvZ0RhdGUoKSB7XG5cdFx0cmV0dXJuIHRoaXMucHJvcHMubG9nRGF0ZTtcblx0fVxuXG5cdGdldCBsb2dWYWx1ZSgpIHtcblx0XHRyZXR1cm4gdGhpcy5wcm9wcy5sb2dWYWx1ZTtcblx0fVxuXG5cdGdldCBsb2dJZCgpIHtcblx0XHRyZXR1cm4gdGhpcy5wcm9wcy5sb2dJZDtcblx0fVxufVxuIiwiaW1wb3J0IGNyeXB0byBmcm9tICdjcnlwdG8nO1xuXG5leHBvcnQgY2xhc3MgVXVpZCB7XG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuby11bmRlcnNjb3JlLWRhbmdsZVxuICBwcml2YXRlIHJlYWRvbmx5IF9pZDogc3RyaW5nO1xuXG4gIHByb3RlY3RlZCBjb25zdHJ1Y3RvcihpZDogc3RyaW5nKSB7XG4gICAgdGhpcy5faWQgPSBpZDtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgdmFsdWUoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gdGhpcy5faWQ7XG4gIH1cblxuICBwdWJsaWMgdG9TdHJpbmcoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gdGhpcy52YWx1ZTtcbiAgfVxuXG4gIHB1YmxpYyBlcXVhbHMoaWQ/OiBVdWlkIHwgc3RyaW5nKTogYm9vbGVhbiB7XG4gICAgaWYgKGlkIGluc3RhbmNlb2YgVXVpZCkge1xuICAgICAgcmV0dXJuIGlkLnZhbHVlID09PSB0aGlzLnZhbHVlO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIGlkID09PSAnc3RyaW5nJykge1xuICAgICAgcmV0dXJuIGlkID09PSB0aGlzLl9pZDtcbiAgICB9XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgcHVibGljIHN0YXRpYyBjcmVhdGUoZ2l2ZW5JZD86IHN0cmluZyB8IG51bGwpOiBVdWlkIHtcbiAgICBpZiAoIWdpdmVuSWQpIHJldHVybiBuZXcgVXVpZChjcnlwdG8ucmFuZG9tVVVJRCgpKTtcbiAgICAvLyB3ZSBkb24ndCB2YWxpZGF0ZSB0aGF0IGl0J3MgYSBwcm9wZXIgdXVpZCBzbyB3ZSBjYW4gc3VwcG9ydCBjb21wb3NpdGUgSURzXG4gICAgcmV0dXJuIG5ldyBVdWlkKGdpdmVuSWQpO1xuICB9XG5cbiAgcHVibGljIHN0YXRpYyBpc1ZhbGlkKGdpdmVuSWQ6IHN0cmluZyk6IGJvb2xlYW4ge1xuICAgIHJldHVybiAvXlswLTlhLWZdezh9LVswLTlhLWZdezR9LVsxLTVdWzAtOWEtZl17M30tWzg5YWJdWzAtOWEtZl17M30tWzAtOWEtZl17MTJ9JC9pLnRlc3QoXG4gICAgICBnaXZlbklkLFxuICAgICk7XG4gIH1cbn1cbiIsImltcG9ydCB7IExvZ0VudHJ5IH0gZnJvbSAnLi4vLi4vZG9tYWluL2VudGl0aWVzL0xvZ0VudHJ5JztcbmltcG9ydCB7IExvZ0VudHJpZXNSZWNvcmQgfSBmcm9tICcuLi8uLi9zaGFyZWQvZGF0YWJhc2UnO1xuaW1wb3J0IHsgVXVpZCB9IGZyb20gJy4uLy4uL2RvbWFpbi9lbnRpdGllcy9VdWlkJztcblxuZXhwb3J0IGNsYXNzIExvZ0VudHJpZXNQZXJzaXN0ZW5jZU1hcHBlciB7XG5cdHN0YXRpYyB0b1BlcnNpc3RlbmNlKGxvZ0VudHJ5OiBMb2dFbnRyeSk6IExvZ0VudHJpZXNSZWNvcmQge1xuXHRcdHJldHVybiB7XG5cdFx0XHRpZDogbG9nRW50cnkuaWQudG9TdHJpbmcoKSxcblx0XHRcdGxvZ0lkOiBsb2dFbnRyeS5sb2dJZCxcblx0XHRcdGxvZ0RhdGU6IGxvZ0VudHJ5LmxvZ0RhdGUsXG5cdFx0XHRsb2dWYWx1ZTogbG9nRW50cnkubG9nVmFsdWUsXG5cdFx0fTtcblx0fVxuXG5cdHN0YXRpYyBmcm9tUGVyc2lzdGVuY2UobG9nRW50cmllc1JlY29yZDogTG9nRW50cmllc1JlY29yZCk6IExvZ0VudHJ5IHtcblx0XHRyZXR1cm4gTG9nRW50cnkuY3JlYXRlRnJvbVBlcnNpc3RlbmNlKFxuXHRcdFx0bG9nRW50cmllc1JlY29yZCxcblx0XHRcdGxvZ0VudHJpZXNSZWNvcmQuaWRcblx0XHQpO1xuXHR9XG5cblx0c3RhdGljIGZyb21VcGRhdGVQZXJzaXN0ZW5jZShsb2dFbnRyaWVzUmVjb3JkOiBMb2dFbnRyaWVzUmVjb3JkKTogTG9nRW50cnkge1xuXHRcdHJldHVybiBMb2dFbnRyeS5jcmVhdGVGcm9tUGVyc2lzdGVuY2UoXG5cdFx0XHRsb2dFbnRyaWVzUmVjb3JkLFxuXHRcdFx0bG9nRW50cmllc1JlY29yZC5pZFxuXHRcdCk7XG5cdH1cbn1cbiIsImltcG9ydCB7IERhdGFiYXNlLCBMb2dFbnRyaWVzUmVjb3JkIH0gZnJvbSAnLi4vLi4vc2hhcmVkL2RhdGFiYXNlJztcblxuZXhwb3J0IGNsYXNzIExvZ0VudHJpZXNRdWVyeVJlcG9zaXRvcnkge1xuICBhc3luYyBmaW5kTG9nRW50cmllcyhsb2dJZDogc3RyaW5nKTogUHJvbWlzZTxMb2dFbnRyaWVzUmVjb3JkW10+IHtcbiAgICByZXR1cm4gRGF0YWJhc2UuZ2V0QWxsTG9nRW50cmllcyhsb2dJZCk7XG4gIH1cbn1cbiIsImltcG9ydCB7IExvZ0VudHJ5IH0gZnJvbSAnLi4vLi4vZG9tYWluL2VudGl0aWVzL0xvZ0VudHJ5JztcbmltcG9ydCB7IERhdGFiYXNlLCBMb2dFbnRyaWVzUmVjb3JkIH0gZnJvbSAnLi4vLi4vc2hhcmVkL2RhdGFiYXNlJztcbmltcG9ydCB7IFJlY29yZE5vdEZvdW5kRXJyb3IgfSBmcm9tICcuLi8uLi9zaGFyZWQvZXJyb3JzJztcbmltcG9ydCB7IExvZ0VudHJpZXNQZXJzaXN0ZW5jZU1hcHBlciB9IGZyb20gJy4uL21hcHBlcnMvTG9nRW50cmllc1BlcnNpc3RlbmNlTWFwcGVyJztcblxuZXhwb3J0IGNsYXNzIExvZ0VudHJpZXNSZXBvc2l0b3J5IHtcblx0Y29uc3RydWN0b3IocHJvdGVjdGVkIGxvZ0lkOiBzdHJpbmcpIHt9XG5cblx0YXN5bmMgY3JlYXRlTG9nRW50cnkobG9nRW50cnk6IExvZ0VudHJ5KTogUHJvbWlzZTxMb2dFbnRyeT4ge1xuXHRcdGNvbnN0IGR0byA9IExvZ0VudHJpZXNQZXJzaXN0ZW5jZU1hcHBlci50b1BlcnNpc3RlbmNlKGxvZ0VudHJ5KTtcblx0XHRhd2FpdCBEYXRhYmFzZS5jcmVhdGVMb2dFbnRyeShkdG8pO1xuXHRcdHJldHVybiBsb2dFbnRyeTtcblx0fVxuXG5cdGFzeW5jIGZpbmRCeUlkKGxvZ0VudHJ5SWQ6IHN0cmluZyk6IFByb21pc2U8TG9nRW50cnk+IHtcblx0XHRjb25zdCByZWNvcmQgPSBhd2FpdCBEYXRhYmFzZS5maW5kQnlJZChsb2dFbnRyeUlkKTtcblx0XHRpZiAoIXJlY29yZCkge1xuXHRcdFx0dGhyb3cgbmV3IFJlY29yZE5vdEZvdW5kRXJyb3IoXG5cdFx0XHRcdGBsb2cgZW50cnkgbm90IGZvdW5kIGZvciBpZDogJHtsb2dFbnRyeUlkfWBcblx0XHRcdCk7XG5cdFx0fVxuXHRcdHJldHVybiBMb2dFbnRyaWVzUGVyc2lzdGVuY2VNYXBwZXIuZnJvbVBlcnNpc3RlbmNlKHJlY29yZCk7XG5cdH1cblxuXHRhc3luYyBkZXN0cm95TG9nRW50cnkobG9nRW50cnk6IExvZ0VudHJ5KTogUHJvbWlzZTxzdHJpbmc+IHtcblx0XHRhd2FpdCBEYXRhYmFzZS5kZWxldGVMb2dFbnRyeShsb2dFbnRyeS5pZC52YWx1ZSk7XG5cdFx0cmV0dXJuIGxvZ0VudHJ5LmlkLnZhbHVlO1xuXHR9XG5cblx0YXN5bmMgdXBkYXRlTG9nRW50cnkobG9nRW50cnk6IExvZ0VudHJ5KTogUHJvbWlzZTxMb2dFbnRyeT4ge1xuXHRcdGNvbnN0IGR0byA9IExvZ0VudHJpZXNQZXJzaXN0ZW5jZU1hcHBlci50b1BlcnNpc3RlbmNlKGxvZ0VudHJ5KTtcblx0XHRjb25zdCB1cGRhdGVkRW50cnkgPSBhd2FpdCBEYXRhYmFzZS51cGRhdGVMb2dFbnRyeShkdG8pO1xuXHRcdHJldHVybiBMb2dFbnRyaWVzUGVyc2lzdGVuY2VNYXBwZXIuZnJvbVBlcnNpc3RlbmNlKHVwZGF0ZWRFbnRyeSk7XG5cdH1cbn1cbiIsImltcG9ydCB7IEh0dHBTdGF0dXNDb2RlIH0gZnJvbSAnQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2hhcmVkJztcbmltcG9ydCB7IFJvdXRlciB9IGZyb20gJ2V4cHJlc3MnO1xuaW1wb3J0IHsgTG9nRW50cmllc1NlcnZpY2UgfSBmcm9tICcuLi8uLi9hcHBsaWNhdGlvbi9zZXJ2aWNlcy9Mb2dFbnRyaWVzU2VydmljZSc7XG5pbXBvcnQgeyBSZWNvcmROb3RGb3VuZEVycm9yLCBWYWxpZGF0aW9uRXJyb3IgfSBmcm9tICcuLi8uLi9zaGFyZWQvZXJyb3JzJztcblxuZXhwb3J0IGNvbnN0IGxvZ0VudHJpZXNDb250cm9sbGVyID0gUm91dGVyKCk7XG5cbmxvZ0VudHJpZXNDb250cm9sbGVyLmdldCgnL2xvZ3MvOmxvZ0lkL2xvZy1lbnRyaWVzJywgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG5cdGNvbnN0IHsgbG9nSWQgfSA9IHJlcS5wYXJhbXM7XG5cdGNvbnN0IGxvZ0VudHJ5U2VydmljZSA9IG5ldyBMb2dFbnRyaWVzU2VydmljZSgpO1xuXHRjb25zdCBsb2dFbnRyaWVzID0gYXdhaXQgbG9nRW50cnlTZXJ2aWNlLmdldExvZ0VudHJpZXMobG9nSWQpO1xuXHRyZXMuanNvbihsb2dFbnRyaWVzKTtcbn0pO1xuXG5sb2dFbnRyaWVzQ29udHJvbGxlci5wb3N0KCcvbG9ncy86bG9nSWQvbG9nLWVudHJpZXMnLCBhc3luYyAocmVxLCByZXMpID0+IHtcblx0Y29uc3QgeyBsb2dJZCB9ID0gcmVxLnBhcmFtcztcblx0Y29uc3QgeyBsb2dFbnRyeSB9ID0gcmVxLmJvZHk7XG5cdGNvbnN0IGxvZ0VudHJ5U2VydmljZSA9IG5ldyBMb2dFbnRyaWVzU2VydmljZSgpO1xuXHR0cnkge1xuXHRcdGNvbnN0IGxvZ0VudHJpZXMgPSBhd2FpdCBsb2dFbnRyeVNlcnZpY2UuY3JlYXRlTG9nRW50cnkoXG5cdFx0XHRsb2dJZCxcblx0XHRcdGxvZ0VudHJ5XG5cdFx0KTtcblx0XHRyZXMuanNvbihsb2dFbnRyaWVzKTtcblx0fSBjYXRjaCAoZTogdW5rbm93bikge1xuXHRcdGlmIChlIGluc3RhbmNlb2YgVmFsaWRhdGlvbkVycm9yKSB7XG5cdFx0XHRyZXMuc3RhdHVzKEh0dHBTdGF0dXNDb2RlLklOVkFMSURfREFUQSk7XG5cdFx0XHRyZXMuc2VuZChlLnRvU3RyaW5nKCkpO1xuXHRcdH0gZWxzZSB7XG5cdFx0XHRyZXMuc3RhdHVzKEh0dHBTdGF0dXNDb2RlLlNFUlZFUl9FUlJPUik7XG5cdFx0XHRyZXMuc2VuZCgpO1xuXHRcdH1cblx0fVxufSk7XG5cbmxvZ0VudHJpZXNDb250cm9sbGVyLmRlbGV0ZShcblx0Jy9sb2dzLzpsb2dJZC9sb2ctZW50cmllcy86bG9nRW50cnlJZCcsXG5cdGFzeW5jIChyZXEsIHJlcykgPT4ge1xuXHRcdGNvbnN0IHsgbG9nSWQsIGxvZ0VudHJ5SWQgfSA9IHJlcS5wYXJhbXM7XG5cdFx0Y29uc3QgbG9nRW50cnlTZXJ2aWNlID0gbmV3IExvZ0VudHJpZXNTZXJ2aWNlKCk7XG5cdFx0dHJ5IHtcblx0XHRcdGNvbnN0IGxvZ0VudHJpZXMgPSBhd2FpdCBsb2dFbnRyeVNlcnZpY2UuZGVsZXRlTG9nRW50cnkoXG5cdFx0XHRcdGxvZ0lkLFxuXHRcdFx0XHRsb2dFbnRyeUlkXG5cdFx0XHQpO1xuXHRcdFx0cmVzLmpzb24obG9nRW50cmllcyk7XG5cdFx0fSBjYXRjaCAoZTogdW5rbm93bikge1xuXHRcdFx0aWYgKGUgaW5zdGFuY2VvZiBSZWNvcmROb3RGb3VuZEVycm9yKSB7XG5cdFx0XHRcdHJlcy5zdGF0dXMoSHR0cFN0YXR1c0NvZGUuSU5WQUxJRF9EQVRBKTtcblx0XHRcdFx0cmVzLnNlbmQoZS50b1N0cmluZygpKTtcblx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdHJlcy5zdGF0dXMoSHR0cFN0YXR1c0NvZGUuU0VSVkVSX0VSUk9SKTtcblx0XHRcdFx0cmVzLnNlbmQoKTtcblx0XHRcdH1cblx0XHRcdHJlcy5qc29uKCk7XG5cdFx0fVxuXHR9XG4pO1xuXG5sb2dFbnRyaWVzQ29udHJvbGxlci5wdXQoJy9sb2dzL2xvZy1lbnRyaWVzJywgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG5cdGNvbnN0IHsgbG9nRW50cnkgfSA9IHJlcS5ib2R5O1xuXHRjb25zdCBsb2dFbnRyeVNlcnZpY2UgPSBuZXcgTG9nRW50cmllc1NlcnZpY2UoKTtcblx0dHJ5IHtcblx0XHRjb25zdCBsb2dFbnRyaWVzID0gYXdhaXQgbG9nRW50cnlTZXJ2aWNlLnVwZGF0ZUxvZ0VudHJ5KGxvZ0VudHJ5KTtcblx0XHRyZXMuanNvbihsb2dFbnRyaWVzKTtcblx0fSBjYXRjaCAoZTogdW5rbm93bikge1xuXHRcdGlmIChlIGluc3RhbmNlb2YgVmFsaWRhdGlvbkVycm9yKSB7XG5cdFx0XHRyZXMuc3RhdHVzKEh0dHBTdGF0dXNDb2RlLklOVkFMSURfREFUQSk7XG5cdFx0XHRyZXMuc2VuZChlLnRvU3RyaW5nKCkpO1xuXHRcdH0gZWxzZSB7XG5cdFx0XHRyZXMuc3RhdHVzKEh0dHBTdGF0dXNDb2RlLlNFUlZFUl9FUlJPUik7XG5cdFx0XHRyZXMuc2VuZCgpO1xuXHRcdH1cblx0fVxufSk7XG4iLCJpbXBvcnQgeyBMT0dfMV9JRCwgTE9HXzJfSUQgfSBmcm9tICdAbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zaGFyZWQnO1xuaW1wb3J0IGNyeXB0byBmcm9tICdjcnlwdG8nO1xuaW1wb3J0IGZzIGZyb20gJ2ZzJztcblxuZXhwb3J0IHR5cGUgTG9nRW50cmllc1JlY29yZCA9IHtcblx0aWQ6IHN0cmluZztcblx0bG9nSWQ6IHN0cmluZztcblx0bG9nRGF0ZTogRGF0ZTtcblx0bG9nVmFsdWU6IG51bWJlcjtcbn07XG5cbmNvbnN0IExPR19FTlRSSUVTX1RBQkxFX1NFRUQ6IExvZ0VudHJpZXNSZWNvcmRbXSA9IFtcblx0e1xuXHRcdGlkOiBjcnlwdG8ucmFuZG9tVVVJRCgpLnRvU3RyaW5nKCksXG5cdFx0bG9nSWQ6IExPR18xX0lELFxuXHRcdGxvZ0RhdGU6IG5ldyBEYXRlKCcyMDI0LTAxLTAxJyksXG5cdFx0bG9nVmFsdWU6IDUsXG5cdH0sXG5cdHtcblx0XHRpZDogY3J5cHRvLnJhbmRvbVVVSUQoKS50b1N0cmluZygpLFxuXHRcdGxvZ0lkOiBMT0dfMV9JRCxcblx0XHRsb2dEYXRlOiBuZXcgRGF0ZSgnMjAyNC0wMS0wMicpLFxuXHRcdGxvZ1ZhbHVlOiAxNSxcblx0fSxcblx0e1xuXHRcdGlkOiBjcnlwdG8ucmFuZG9tVVVJRCgpLnRvU3RyaW5nKCksXG5cdFx0bG9nSWQ6IExPR18xX0lELFxuXHRcdGxvZ0RhdGU6IG5ldyBEYXRlKCcyMDI0LTAxLTAzJyksXG5cdFx0bG9nVmFsdWU6IDIzLFxuXHR9LFxuXHR7XG5cdFx0aWQ6IGNyeXB0by5yYW5kb21VVUlEKCkudG9TdHJpbmcoKSxcblx0XHRsb2dJZDogTE9HXzJfSUQsXG5cdFx0bG9nRGF0ZTogbmV3IERhdGUoJzIwMjQtMDEtMDEnKSxcblx0XHRsb2dWYWx1ZTogMTUsXG5cdH0sXG5dO1xuXG5jb25zdCBGSUxFX05BTUUgPSAnZGF0YWJhc2UnO1xuXG5leHBvcnQgY2xhc3MgRGF0YWJhc2Uge1xuXHRwdWJsaWMgc3RhdGljIGFzeW5jIGdldEFsbExvZ0VudHJpZXMobG9nSWQ6IHN0cmluZykge1xuXHRcdGxldCBhbGxFbnRyaWVzO1xuXHRcdHRyeSB7XG5cdFx0XHRhd2FpdCB0aGlzLnNpbXVsYXRlRGJTbG93bmVzcygpO1xuXHRcdFx0Y29uc3QgZGIgPSBhd2FpdCBmcy5yZWFkRmlsZVN5bmMoRklMRV9OQU1FLCAndXRmOCcpO1xuXHRcdFx0YWxsRW50cmllcyA9IEpTT04ucGFyc2UoZGIpIGFzIExvZ0VudHJpZXNSZWNvcmRbXTtcblx0XHR9IGNhdGNoIChlKSB7XG5cdFx0XHRhd2FpdCBmcy53cml0ZUZpbGVTeW5jKFxuXHRcdFx0XHRGSUxFX05BTUUsXG5cdFx0XHRcdEpTT04uc3RyaW5naWZ5KExPR19FTlRSSUVTX1RBQkxFX1NFRUQpXG5cdFx0XHQpO1xuXHRcdFx0YWxsRW50cmllcyA9IExPR19FTlRSSUVTX1RBQkxFX1NFRUQ7XG5cdFx0fVxuXHRcdHJldHVybiBhbGxFbnRyaWVzLmZpbHRlcigobGUpID0+IGxlLmxvZ0lkID09PSBsb2dJZCk7XG5cdH1cblxuXHRwdWJsaWMgc3RhdGljIGFzeW5jIGNyZWF0ZUxvZ0VudHJ5KGVudHJ5OiBMb2dFbnRyaWVzUmVjb3JkKSB7XG5cdFx0YXdhaXQgdGhpcy5zaW11bGF0ZURiU2xvd25lc3MoKTtcblx0XHRjb25zdCBkYiA9IGF3YWl0IGZzLnJlYWRGaWxlU3luYyhGSUxFX05BTUUsICd1dGY4Jyk7XG5cdFx0Y29uc3QgYWxsRW50cmllcyA9IEpTT04ucGFyc2UoZGIpO1xuXHRcdGFsbEVudHJpZXMucHVzaChlbnRyeSk7XG5cdFx0YXdhaXQgZnMud3JpdGVGaWxlU3luYyhGSUxFX05BTUUsIEpTT04uc3RyaW5naWZ5KGFsbEVudHJpZXMpKTtcblx0XHRyZXR1cm4gZW50cnk7XG5cdH1cblxuXHRwdWJsaWMgc3RhdGljIGFzeW5jIGZpbmRCeUlkKFxuXHRcdGxvZ0VudHJ5SWQ6IHN0cmluZ1xuXHQpOiBQcm9taXNlPExvZ0VudHJpZXNSZWNvcmQgfCBudWxsPiB7XG5cdFx0YXdhaXQgdGhpcy5zaW11bGF0ZURiU2xvd25lc3MoKTtcblx0XHRjb25zdCBkYiA9IGF3YWl0IGZzLnJlYWRGaWxlU3luYyhGSUxFX05BTUUsICd1dGY4Jyk7XG5cdFx0Y29uc3QgYWxsRW50cmllcyA9IEpTT04ucGFyc2UoZGIpIGFzIExvZ0VudHJpZXNSZWNvcmRbXTtcblx0XHRyZXR1cm4gYWxsRW50cmllcy5maW5kKChsZSkgPT4gbGUuaWQgPT09IGxvZ0VudHJ5SWQpIHx8IG51bGw7XG5cdH1cblxuXHRwdWJsaWMgc3RhdGljIGFzeW5jIGRlbGV0ZUxvZ0VudHJ5KGxvZ0VudHJ5SWQ6IHN0cmluZykge1xuXHRcdGF3YWl0IHRoaXMuc2ltdWxhdGVEYlNsb3duZXNzKCk7XG5cdFx0Y29uc3QgZGIgPSBhd2FpdCBmcy5yZWFkRmlsZVN5bmMoRklMRV9OQU1FLCAndXRmOCcpO1xuXHRcdGNvbnN0IGFsbEVudHJpZXMgPSBKU09OLnBhcnNlKGRiKSBhcyBMb2dFbnRyaWVzUmVjb3JkW107XG5cdFx0Y29uc3QgaW5kZXggPSBhbGxFbnRyaWVzLmZpbmRJbmRleCgobGUpID0+IGxlLmlkID09PSBsb2dFbnRyeUlkKTtcblx0XHRhbGxFbnRyaWVzLnNwbGljZShpbmRleCwgMSk7XG5cdFx0YXdhaXQgZnMud3JpdGVGaWxlU3luYyhGSUxFX05BTUUsIEpTT04uc3RyaW5naWZ5KGFsbEVudHJpZXMpKTtcblx0XHRyZXR1cm4gbG9nRW50cnlJZDtcblx0fVxuXG5cdHB1YmxpYyBzdGF0aWMgYXN5bmMgdXBkYXRlTG9nRW50cnkoZW50cnk6IExvZ0VudHJpZXNSZWNvcmQpIHtcblx0XHRhd2FpdCB0aGlzLnNpbXVsYXRlRGJTbG93bmVzcygpO1xuXHRcdGNvbnN0IGRiID0gYXdhaXQgZnMucmVhZEZpbGVTeW5jKEZJTEVfTkFNRSwgJ3V0ZjgnKTtcblx0XHRjb25zdCBhbGxFbnRyaWVzID0gSlNPTi5wYXJzZShkYikgYXMgTG9nRW50cmllc1JlY29yZFtdO1xuXHRcdGNvbnN0IGluZGV4ID0gYWxsRW50cmllcy5maW5kSW5kZXgoKGxlKSA9PiBsZS5pZCA9PT0gZW50cnkuaWQpO1xuXHRcdGlmIChpbmRleCAhPT0gLTEpIHtcblx0XHRcdGFsbEVudHJpZXNbaW5kZXhdID0gZW50cnk7XG5cdFx0XHRhd2FpdCBmcy53cml0ZUZpbGVTeW5jKEZJTEVfTkFNRSwgSlNPTi5zdHJpbmdpZnkoYWxsRW50cmllcykpO1xuXHRcdFx0cmV0dXJuIGVudHJ5O1xuXHRcdH1cblx0XHR0aHJvdyBuZXcgRXJyb3IoYExvZyBlbnRyeSB3aXRoIGlkICR7ZW50cnkuaWR9IG5vdCBmb3VuZGApO1xuXHR9XG5cblx0cHJpdmF0ZSBzdGF0aWMgc2ltdWxhdGVEYlNsb3duZXNzKG1zID0gMTAwMCkge1xuXHRcdHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSkgPT4ge1xuXHRcdFx0c2V0VGltZW91dChyZXNvbHZlLCBtcyk7XG5cdFx0fSk7XG5cdH1cbn1cbiIsIi8qIGVzbGludC1kaXNhYmxlIG1heC1jbGFzc2VzLXBlci1maWxlICovXG5cbmV4cG9ydCBjbGFzcyBSZWNvcmROb3RGb3VuZEVycm9yIGV4dGVuZHMgRXJyb3Ige31cblxuZXhwb3J0IGNsYXNzIFZhbGlkYXRpb25FcnJvciBleHRlbmRzIEVycm9yIHt9XG4iLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJjcnlwdG9cIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiZXhwcmVzc1wiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJmc1wiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJodHRwXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIm1vcmdhblwiKTsiLCIvLyBUaGUgbW9kdWxlIGNhY2hlXG52YXIgX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fID0ge307XG5cbi8vIFRoZSByZXF1aXJlIGZ1bmN0aW9uXG5mdW5jdGlvbiBfX3dlYnBhY2tfcmVxdWlyZV9fKG1vZHVsZUlkKSB7XG5cdC8vIENoZWNrIGlmIG1vZHVsZSBpcyBpbiBjYWNoZVxuXHR2YXIgY2FjaGVkTW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXTtcblx0aWYgKGNhY2hlZE1vZHVsZSAhPT0gdW5kZWZpbmVkKSB7XG5cdFx0cmV0dXJuIGNhY2hlZE1vZHVsZS5leHBvcnRzO1xuXHR9XG5cdC8vIENyZWF0ZSBhIG5ldyBtb2R1bGUgKGFuZCBwdXQgaXQgaW50byB0aGUgY2FjaGUpXG5cdHZhciBtb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdID0ge1xuXHRcdC8vIG5vIG1vZHVsZS5pZCBuZWVkZWRcblx0XHQvLyBubyBtb2R1bGUubG9hZGVkIG5lZWRlZFxuXHRcdGV4cG9ydHM6IHt9XG5cdH07XG5cblx0Ly8gRXhlY3V0ZSB0aGUgbW9kdWxlIGZ1bmN0aW9uXG5cdF9fd2VicGFja19tb2R1bGVzX19bbW9kdWxlSWRdKG1vZHVsZSwgbW9kdWxlLmV4cG9ydHMsIF9fd2VicGFja19yZXF1aXJlX18pO1xuXG5cdC8vIFJldHVybiB0aGUgZXhwb3J0cyBvZiB0aGUgbW9kdWxlXG5cdHJldHVybiBtb2R1bGUuZXhwb3J0cztcbn1cblxuIiwiLy8gZ2V0RGVmYXVsdEV4cG9ydCBmdW5jdGlvbiBmb3IgY29tcGF0aWJpbGl0eSB3aXRoIG5vbi1oYXJtb255IG1vZHVsZXNcbl9fd2VicGFja19yZXF1aXJlX18ubiA9IChtb2R1bGUpID0+IHtcblx0dmFyIGdldHRlciA9IG1vZHVsZSAmJiBtb2R1bGUuX19lc01vZHVsZSA/XG5cdFx0KCkgPT4gKG1vZHVsZVsnZGVmYXVsdCddKSA6XG5cdFx0KCkgPT4gKG1vZHVsZSk7XG5cdF9fd2VicGFja19yZXF1aXJlX18uZChnZXR0ZXIsIHsgYTogZ2V0dGVyIH0pO1xuXHRyZXR1cm4gZ2V0dGVyO1xufTsiLCIvLyBkZWZpbmUgZ2V0dGVyIGZ1bmN0aW9ucyBmb3IgaGFybW9ueSBleHBvcnRzXG5fX3dlYnBhY2tfcmVxdWlyZV9fLmQgPSAoZXhwb3J0cywgZGVmaW5pdGlvbikgPT4ge1xuXHRmb3IodmFyIGtleSBpbiBkZWZpbml0aW9uKSB7XG5cdFx0aWYoX193ZWJwYWNrX3JlcXVpcmVfXy5vKGRlZmluaXRpb24sIGtleSkgJiYgIV9fd2VicGFja19yZXF1aXJlX18ubyhleHBvcnRzLCBrZXkpKSB7XG5cdFx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywga2V5LCB7IGVudW1lcmFibGU6IHRydWUsIGdldDogZGVmaW5pdGlvbltrZXldIH0pO1xuXHRcdH1cblx0fVxufTsiLCJfX3dlYnBhY2tfcmVxdWlyZV9fLm8gPSAob2JqLCBwcm9wKSA9PiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwgcHJvcCkpIiwiLy8gZGVmaW5lIF9fZXNNb2R1bGUgb24gZXhwb3J0c1xuX193ZWJwYWNrX3JlcXVpcmVfXy5yID0gKGV4cG9ydHMpID0+IHtcblx0aWYodHlwZW9mIFN5bWJvbCAhPT0gJ3VuZGVmaW5lZCcgJiYgU3ltYm9sLnRvU3RyaW5nVGFnKSB7XG5cdFx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIFN5bWJvbC50b1N0cmluZ1RhZywgeyB2YWx1ZTogJ01vZHVsZScgfSk7XG5cdH1cblx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsICdfX2VzTW9kdWxlJywgeyB2YWx1ZTogdHJ1ZSB9KTtcbn07IiwiaW1wb3J0IGNvb2tpZVBhcnNlciBmcm9tICdjb29raWUtcGFyc2VyJztcbmltcG9ydCBjb3JzIGZyb20gJ2NvcnMnO1xuaW1wb3J0IGV4cHJlc3MgZnJvbSAnZXhwcmVzcyc7XG5pbXBvcnQgaHR0cCBmcm9tICdodHRwJztcbmltcG9ydCBsb2dnZXIgZnJvbSAnbW9yZ2FuJztcbmltcG9ydCB7IGxvZ0VudHJpZXNDb250cm9sbGVyIH0gZnJvbSAnLi9wcmVzZW50YXRpb24vY29udHJvbGxlcnMvbG9nRW50cmllc0NvbnRyb2xsZXInO1xuXG5leHBvcnQgY29uc3QgYXBwID0gZXhwcmVzcygpO1xuXG5hcHAudXNlKGxvZ2dlcignZGV2JykpO1xuYXBwLnVzZShleHByZXNzLmpzb24oKSk7XG5hcHAudXNlKGV4cHJlc3MudXJsZW5jb2RlZCh7IGV4dGVuZGVkOiBmYWxzZSB9KSk7XG5hcHAudXNlKGNvb2tpZVBhcnNlcigpKTtcbmFwcC51c2UoY29ycyh7IG9yaWdpbjogJ2h0dHA6Ly9sb2NhbGhvc3Q6MzAwMScgfSkpO1xuYXBwLnVzZSgnL2FwaScsIGxvZ0VudHJpZXNDb250cm9sbGVyKTtcblxuLyoqXG4gKiBOb3JtYWxpemUgYSBwb3J0IGludG8gYSBudW1iZXIsIHN0cmluZywgb3IgZmFsc2UuXG4gKi9cblxuZnVuY3Rpb24gbm9ybWFsaXplUG9ydCh2YWw6IHN0cmluZykge1xuICBjb25zdCBwb3J0ID0gcGFyc2VJbnQodmFsLCAxMCk7XG5cbiAgaWYgKE51bWJlci5pc05hTihwb3J0KSkge1xuICAgIC8vIG5hbWVkIHBpcGVcbiAgICByZXR1cm4gdmFsO1xuICB9XG5cbiAgaWYgKHBvcnQgPj0gMCkge1xuICAgIC8vIHBvcnQgbnVtYmVyXG4gICAgcmV0dXJuIHBvcnQ7XG4gIH1cblxuICByZXR1cm4gZmFsc2U7XG59XG5cbi8qKlxuICogR2V0IHBvcnQgZnJvbSBlbnZpcm9ubWVudCBhbmQgc3RvcmUgaW4gRXhwcmVzcy5cbiAqL1xuXG5jb25zdCBwb3J0ID0gbm9ybWFsaXplUG9ydChwcm9jZXNzLmVudi5QT1JUIHx8ICczMDAwJyk7XG5hcHAuc2V0KCdwb3J0JywgcG9ydCk7XG5cbi8qKlxuICogQ3JlYXRlIEhUVFAgc2VydmVyLlxuICovXG5cbmNvbnN0IHNlcnZlciA9IGh0dHAuY3JlYXRlU2VydmVyKGFwcCk7XG5cbi8qKlxuICogRXZlbnQgbGlzdGVuZXIgZm9yIEhUVFAgc2VydmVyIFwiZXJyb3JcIiBldmVudC5cbiAqL1xuXG5mdW5jdGlvbiBvbkVycm9yKGVycm9yOiBOb2RlSlMuRXJybm9FeGNlcHRpb24pIHtcbiAgaWYgKGVycm9yLnN5c2NhbGwgIT09ICdsaXN0ZW4nKSB7XG4gICAgdGhyb3cgZXJyb3I7XG4gIH1cblxuICBjb25zdCBiaW5kID0gdHlwZW9mIHBvcnQgPT09ICdzdHJpbmcnID8gYFBpcGUgJHtwb3J0fWAgOiBgUG9ydCAke3BvcnR9YDtcblxuICAvLyBoYW5kbGUgc3BlY2lmaWMgbGlzdGVuIGVycm9ycyB3aXRoIGZyaWVuZGx5IG1lc3NhZ2VzXG4gIHN3aXRjaCAoZXJyb3IuY29kZSkge1xuICAgIGNhc2UgJ0VBQ0NFUyc6XG4gICAgICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbm8tY29uc29sZVxuICAgICAgY29uc29sZS5lcnJvcihgJHtiaW5kfSByZXF1aXJlcyBlbGV2YXRlZCBwcml2aWxlZ2VzYCk7XG4gICAgICBwcm9jZXNzLmV4aXQoMSk7XG4gICAgICBicmVhaztcbiAgICBjYXNlICdFQUREUklOVVNFJzpcbiAgICAgIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuby1jb25zb2xlXG4gICAgICBjb25zb2xlLmVycm9yKGAke2JpbmR9IGlzIGFscmVhZHkgaW4gdXNlYCk7XG4gICAgICBwcm9jZXNzLmV4aXQoMSk7XG4gICAgICBicmVhaztcbiAgICBkZWZhdWx0OlxuICAgICAgdGhyb3cgZXJyb3I7XG4gIH1cbn1cblxuLyoqXG4gKiBFdmVudCBsaXN0ZW5lciBmb3IgSFRUUCBzZXJ2ZXIgXCJsaXN0ZW5pbmdcIiBldmVudC5cbiAqL1xuXG5mdW5jdGlvbiBvbkxpc3RlbmluZygpIHtcbiAgY29uc3QgYWRkciA9IHNlcnZlci5hZGRyZXNzKCk7XG4gIGNvbnN0IGJpbmQgPSB0eXBlb2YgYWRkciA9PT0gJ3N0cmluZycgPyBgcGlwZSAke2FkZHJ9YCA6IGBwb3J0ICR7YWRkcj8ucG9ydH1gO1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbm8tY29uc29sZVxuICBjb25zb2xlLmxvZyhgTGlzdGVuaW5nIG9uICR7YmluZH1gKTtcbn1cblxuLyoqXG4gKiBMaXN0ZW4gb24gcHJvdmlkZWQgcG9ydCwgb24gYWxsIG5ldHdvcmsgaW50ZXJmYWNlcy5cbiAqL1xuXG5zZXJ2ZXIubGlzdGVuKHBvcnQpO1xuc2VydmVyLm9uKCdlcnJvcicsIG9uRXJyb3IpO1xuc2VydmVyLm9uKCdsaXN0ZW5pbmcnLCBvbkxpc3RlbmluZyk7XG4iXSwibmFtZXMiOltdLCJzb3VyY2VSb290IjoiIn0=