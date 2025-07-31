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
        return new LogEntry(updateLogEntryProps);
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,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LENBQUM7WUFDaEIsTUFBTTtRQUNSLEtBQUssWUFBWTtZQUNmLHNDQUFzQztZQUN0QyxPQUFPLENBQUMsS0FBSyxDQUFDLEdBQUcsSUFBSSxvQkFBb0IsQ0FBQyxDQUFDO1lBQzNDLE9BQU8sQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUM7WUFDaEIsTUFBTTtRQUNSO1lBQ0UsTUFBTSxLQUFLLENBQUM7S0FDZjtBQUNILENBQUM7QUFFRDs7R0FFRztBQUVILFNBQVMsV0FBVztJQUNsQixNQUFNLElBQUksR0FBRyxNQUFNLENBQUMsT0FBTyxFQUFFLENBQUM7SUFDOUIsTUFBTSxJQUFJLEdBQUcsT0FBTyxJQUFJLEtBQUssUUFBUSxDQUFDLENBQUMsQ0FBQyxRQUFRLElBQUksRUFBRSxDQUFDLENBQUMsQ0FBQyxRQUFRLElBQUksRUFBRSxJQUFJLEVBQUUsQ0FBQztJQUM5RSxzQ0FBc0M7SUFDdEMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxnQkFBZ0IsSUFBSSxFQUFFLENBQUMsQ0FBQztBQUN0QyxDQUFDO0FBRUQ7O0dBRUc7QUFFSCxNQUFNLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxDQUFDO0FBQ3BCLE1BQU0sQ0FBQyxFQUFFLENBQUMsT0FBTyxFQUFFLE9BQU8sQ0FBQyxDQUFDO0FBQzVCLE1BQU0sQ0FBQyxFQUFFLENBQUMsV0FBVyxFQUFFLFdBQVcsQ0FBQyxDQUFDIiwic291cmNlcyI6WyJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4uLy4uL25vZGVfbW9kdWxlcy9jb29raWUtcGFyc2VyL2luZGV4LmpzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uLi8uLi9ub2RlX21vZHVsZXMvY29va2llLXNpZ25hdHVyZS9pbmRleC5qcyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi4vLi4vbm9kZV9tb2R1bGVzL2Nvb2tpZS9pbmRleC5qcyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi4vLi4vbm9kZV9tb2R1bGVzL2NvcnMvbGliL2luZGV4LmpzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uLi8uLi9ub2RlX21vZHVsZXMvb2JqZWN0LWFzc2lnbi9pbmRleC5qcyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi4vLi4vbm9kZV9tb2R1bGVzL3ZhcnkvaW5kZXguanMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4uL3NoYXJlZC9zcmMvY29uc3RhbnRzLnRzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uLi9zaGFyZWQvc3JjL2luZGV4LnRzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uLi9zaGFyZWQvc3JjL3R5cGVzLnRzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uL3NyYy9hcHBsaWNhdGlvbi9tYXBwZXJzL0xvZ0VudHJpZXNBcGlNYXBwZXIudHMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4vc3JjL2FwcGxpY2F0aW9uL3NlcnZpY2VzL0xvZ0VudHJpZXNTZXJ2aWNlLnRzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uL3NyYy9kb21haW4vZW50aXRpZXMvRW50aXR5LnRzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uL3NyYy9kb21haW4vZW50aXRpZXMvTG9nRW50cnkudHMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4vc3JjL2RvbWFpbi9lbnRpdGllcy9VdWlkLnRzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uL3NyYy9wZXJzaXN0ZW5jZS9tYXBwZXJzL0xvZ0VudHJpZXNQZXJzaXN0ZW5jZU1hcHBlci50cyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi9zcmMvcGVyc2lzdGVuY2UvcmVwb3NpdG9yaWVzL0xvZ0VudHJpZXNRdWVyeVJlcG9zaXRvcnkudHMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4vc3JjL3BlcnNpc3RlbmNlL3JlcG9zaXRvcmllcy9Mb2dFbnRyaWVzUmVwb3NpdG9yeS50cyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi9zcmMvcHJlc2VudGF0aW9uL2NvbnRyb2xsZXJzL2xvZ0VudHJpZXNDb250cm9sbGVyLnRzIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci8uL3NyYy9zaGFyZWQvZGF0YWJhc2UudHMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyLy4vc3JjL3NoYXJlZC9lcnJvcnMudHMiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyL2V4dGVybmFsIG5vZGUtY29tbW9uanMgXCJjcnlwdG9cIiIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvZXh0ZXJuYWwgY29tbW9uanMgXCJleHByZXNzXCIiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyL2V4dGVybmFsIG5vZGUtY29tbW9uanMgXCJmc1wiIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci9leHRlcm5hbCBub2RlLWNvbW1vbmpzIFwiaHR0cFwiIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci9leHRlcm5hbCBjb21tb25qcyBcIm1vcmdhblwiIiwid2VicGFjazovL0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNlcnZlci93ZWJwYWNrL2Jvb3RzdHJhcCIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvd2VicGFjay9ydW50aW1lL2NvbXBhdCBnZXQgZGVmYXVsdCBleHBvcnQiLCJ3ZWJwYWNrOi8vQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2VydmVyL3dlYnBhY2svcnVudGltZS9kZWZpbmUgcHJvcGVydHkgZ2V0dGVycyIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvd2VicGFjay9ydW50aW1lL2hhc093blByb3BlcnR5IHNob3J0aGFuZCIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvd2VicGFjay9ydW50aW1lL21ha2UgbmFtZXNwYWNlIG9iamVjdCIsIndlYnBhY2s6Ly9AbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zZXJ2ZXIvLi9zcmMvYXBwLnRzIl0sInNvdXJjZXNDb250ZW50IjpbIi8qIVxuICogY29va2llLXBhcnNlclxuICogQ29weXJpZ2h0KGMpIDIwMTQgVEogSG9sb3dheWNodWtcbiAqIENvcHlyaWdodChjKSAyMDE1IERvdWdsYXMgQ2hyaXN0b3BoZXIgV2lsc29uXG4gKiBNSVQgTGljZW5zZWRcbiAqL1xuXG4ndXNlIHN0cmljdCdcblxuLyoqXG4gKiBNb2R1bGUgZGVwZW5kZW5jaWVzLlxuICogQHByaXZhdGVcbiAqL1xuXG52YXIgY29va2llID0gcmVxdWlyZSgnY29va2llJylcbnZhciBzaWduYXR1cmUgPSByZXF1aXJlKCdjb29raWUtc2lnbmF0dXJlJylcblxuLyoqXG4gKiBNb2R1bGUgZXhwb3J0cy5cbiAqIEBwdWJsaWNcbiAqL1xuXG5tb2R1bGUuZXhwb3J0cyA9IGNvb2tpZVBhcnNlclxubW9kdWxlLmV4cG9ydHMuSlNPTkNvb2tpZSA9IEpTT05Db29raWVcbm1vZHVsZS5leHBvcnRzLkpTT05Db29raWVzID0gSlNPTkNvb2tpZXNcbm1vZHVsZS5leHBvcnRzLnNpZ25lZENvb2tpZSA9IHNpZ25lZENvb2tpZVxubW9kdWxlLmV4cG9ydHMuc2lnbmVkQ29va2llcyA9IHNpZ25lZENvb2tpZXNcblxuLyoqXG4gKiBQYXJzZSBDb29raWUgaGVhZGVyIGFuZCBwb3B1bGF0ZSBgcmVxLmNvb2tpZXNgXG4gKiB3aXRoIGFuIG9iamVjdCBrZXllZCBieSB0aGUgY29va2llIG5hbWVzLlxuICpcbiAqIEBwYXJhbSB7c3RyaW5nfGFycmF5fSBbc2VjcmV0XSBBIHN0cmluZyAob3IgYXJyYXkgb2Ygc3RyaW5ncykgcmVwcmVzZW50aW5nIGNvb2tpZSBzaWduaW5nIHNlY3JldChzKS5cbiAqIEBwYXJhbSB7T2JqZWN0fSBbb3B0aW9uc11cbiAqIEByZXR1cm4ge0Z1bmN0aW9ufVxuICogQHB1YmxpY1xuICovXG5cbmZ1bmN0aW9uIGNvb2tpZVBhcnNlciAoc2VjcmV0LCBvcHRpb25zKSB7XG4gIHZhciBzZWNyZXRzID0gIXNlY3JldCB8fCBBcnJheS5pc0FycmF5KHNlY3JldClcbiAgICA/IChzZWNyZXQgfHwgW10pXG4gICAgOiBbc2VjcmV0XVxuXG4gIHJldHVybiBmdW5jdGlvbiBjb29raWVQYXJzZXIgKHJlcSwgcmVzLCBuZXh0KSB7XG4gICAgaWYgKHJlcS5jb29raWVzKSB7XG4gICAgICByZXR1cm4gbmV4dCgpXG4gICAgfVxuXG4gICAgdmFyIGNvb2tpZXMgPSByZXEuaGVhZGVycy5jb29raWVcblxuICAgIHJlcS5zZWNyZXQgPSBzZWNyZXRzWzBdXG4gICAgcmVxLmNvb2tpZXMgPSBPYmplY3QuY3JlYXRlKG51bGwpXG4gICAgcmVxLnNpZ25lZENvb2tpZXMgPSBPYmplY3QuY3JlYXRlKG51bGwpXG5cbiAgICAvLyBubyBjb29raWVzXG4gICAgaWYgKCFjb29raWVzKSB7XG4gICAgICByZXR1cm4gbmV4dCgpXG4gICAgfVxuXG4gICAgcmVxLmNvb2tpZXMgPSBjb29raWUucGFyc2UoY29va2llcywgb3B0aW9ucylcblxuICAgIC8vIHBhcnNlIHNpZ25lZCBjb29raWVzXG4gICAgaWYgKHNlY3JldHMubGVuZ3RoICE9PSAwKSB7XG4gICAgICByZXEuc2lnbmVkQ29va2llcyA9IHNpZ25lZENvb2tpZXMocmVxLmNvb2tpZXMsIHNlY3JldHMpXG4gICAgICByZXEuc2lnbmVkQ29va2llcyA9IEpTT05Db29raWVzKHJlcS5zaWduZWRDb29raWVzKVxuICAgIH1cblxuICAgIC8vIHBhcnNlIEpTT04gY29va2llc1xuICAgIHJlcS5jb29raWVzID0gSlNPTkNvb2tpZXMocmVxLmNvb2tpZXMpXG5cbiAgICBuZXh0KClcbiAgfVxufVxuXG4vKipcbiAqIFBhcnNlIEpTT04gY29va2llIHN0cmluZy5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gc3RyXG4gKiBAcmV0dXJuIHtPYmplY3R9IFBhcnNlZCBvYmplY3Qgb3IgdW5kZWZpbmVkIGlmIG5vdCBqc29uIGNvb2tpZVxuICogQHB1YmxpY1xuICovXG5cbmZ1bmN0aW9uIEpTT05Db29raWUgKHN0cikge1xuICBpZiAodHlwZW9mIHN0ciAhPT0gJ3N0cmluZycgfHwgc3RyLnN1YnN0cigwLCAyKSAhPT0gJ2o6Jykge1xuICAgIHJldHVybiB1bmRlZmluZWRcbiAgfVxuXG4gIHRyeSB7XG4gICAgcmV0dXJuIEpTT04ucGFyc2Uoc3RyLnNsaWNlKDIpKVxuICB9IGNhdGNoIChlcnIpIHtcbiAgICByZXR1cm4gdW5kZWZpbmVkXG4gIH1cbn1cblxuLyoqXG4gKiBQYXJzZSBKU09OIGNvb2tpZXMuXG4gKlxuICogQHBhcmFtIHtPYmplY3R9IG9ialxuICogQHJldHVybiB7T2JqZWN0fVxuICogQHB1YmxpY1xuICovXG5cbmZ1bmN0aW9uIEpTT05Db29raWVzIChvYmopIHtcbiAgdmFyIGNvb2tpZXMgPSBPYmplY3Qua2V5cyhvYmopXG4gIHZhciBrZXlcbiAgdmFyIHZhbFxuXG4gIGZvciAodmFyIGkgPSAwOyBpIDwgY29va2llcy5sZW5ndGg7IGkrKykge1xuICAgIGtleSA9IGNvb2tpZXNbaV1cbiAgICB2YWwgPSBKU09OQ29va2llKG9ialtrZXldKVxuXG4gICAgaWYgKHZhbCkge1xuICAgICAgb2JqW2tleV0gPSB2YWxcbiAgICB9XG4gIH1cblxuICByZXR1cm4gb2JqXG59XG5cbi8qKlxuICogUGFyc2UgYSBzaWduZWQgY29va2llIHN0cmluZywgcmV0dXJuIHRoZSBkZWNvZGVkIHZhbHVlLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSBzdHIgc2lnbmVkIGNvb2tpZSBzdHJpbmdcbiAqIEBwYXJhbSB7c3RyaW5nfGFycmF5fSBzZWNyZXRcbiAqIEByZXR1cm4ge1N0cmluZ30gZGVjb2RlZCB2YWx1ZVxuICogQHB1YmxpY1xuICovXG5cbmZ1bmN0aW9uIHNpZ25lZENvb2tpZSAoc3RyLCBzZWNyZXQpIHtcbiAgaWYgKHR5cGVvZiBzdHIgIT09ICdzdHJpbmcnKSB7XG4gICAgcmV0dXJuIHVuZGVmaW5lZFxuICB9XG5cbiAgaWYgKHN0ci5zdWJzdHIoMCwgMikgIT09ICdzOicpIHtcbiAgICByZXR1cm4gc3RyXG4gIH1cblxuICB2YXIgc2VjcmV0cyA9ICFzZWNyZXQgfHwgQXJyYXkuaXNBcnJheShzZWNyZXQpXG4gICAgPyAoc2VjcmV0IHx8IFtdKVxuICAgIDogW3NlY3JldF1cblxuICBmb3IgKHZhciBpID0gMDsgaSA8IHNlY3JldHMubGVuZ3RoOyBpKyspIHtcbiAgICB2YXIgdmFsID0gc2lnbmF0dXJlLnVuc2lnbihzdHIuc2xpY2UoMiksIHNlY3JldHNbaV0pXG5cbiAgICBpZiAodmFsICE9PSBmYWxzZSkge1xuICAgICAgcmV0dXJuIHZhbFxuICAgIH1cbiAgfVxuXG4gIHJldHVybiBmYWxzZVxufVxuXG4vKipcbiAqIFBhcnNlIHNpZ25lZCBjb29raWVzLCByZXR1cm5pbmcgYW4gb2JqZWN0IGNvbnRhaW5pbmcgdGhlIGRlY29kZWQga2V5L3ZhbHVlXG4gKiBwYWlycywgd2hpbGUgcmVtb3ZpbmcgdGhlIHNpZ25lZCBrZXkgZnJvbSBvYmouXG4gKlxuICogQHBhcmFtIHtPYmplY3R9IG9ialxuICogQHBhcmFtIHtzdHJpbmd8YXJyYXl9IHNlY3JldFxuICogQHJldHVybiB7T2JqZWN0fVxuICogQHB1YmxpY1xuICovXG5cbmZ1bmN0aW9uIHNpZ25lZENvb2tpZXMgKG9iaiwgc2VjcmV0KSB7XG4gIHZhciBjb29raWVzID0gT2JqZWN0LmtleXMob2JqKVxuICB2YXIgZGVjXG4gIHZhciBrZXlcbiAgdmFyIHJldCA9IE9iamVjdC5jcmVhdGUobnVsbClcbiAgdmFyIHZhbFxuXG4gIGZvciAodmFyIGkgPSAwOyBpIDwgY29va2llcy5sZW5ndGg7IGkrKykge1xuICAgIGtleSA9IGNvb2tpZXNbaV1cbiAgICB2YWwgPSBvYmpba2V5XVxuICAgIGRlYyA9IHNpZ25lZENvb2tpZSh2YWwsIHNlY3JldClcblxuICAgIGlmICh2YWwgIT09IGRlYykge1xuICAgICAgcmV0W2tleV0gPSBkZWNcbiAgICAgIGRlbGV0ZSBvYmpba2V5XVxuICAgIH1cbiAgfVxuXG4gIHJldHVybiByZXRcbn1cbiIsIi8qKlxuICogTW9kdWxlIGRlcGVuZGVuY2llcy5cbiAqL1xuXG52YXIgY3J5cHRvID0gcmVxdWlyZSgnY3J5cHRvJyk7XG5cbi8qKlxuICogU2lnbiB0aGUgZ2l2ZW4gYHZhbGAgd2l0aCBgc2VjcmV0YC5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gdmFsXG4gKiBAcGFyYW0ge1N0cmluZ30gc2VjcmV0XG4gKiBAcmV0dXJuIHtTdHJpbmd9XG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5leHBvcnRzLnNpZ24gPSBmdW5jdGlvbih2YWwsIHNlY3JldCl7XG4gIGlmICgnc3RyaW5nJyAhPSB0eXBlb2YgdmFsKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiQ29va2llIHZhbHVlIG11c3QgYmUgcHJvdmlkZWQgYXMgYSBzdHJpbmcuXCIpO1xuICBpZiAoJ3N0cmluZycgIT0gdHlwZW9mIHNlY3JldCkgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlNlY3JldCBzdHJpbmcgbXVzdCBiZSBwcm92aWRlZC5cIik7XG4gIHJldHVybiB2YWwgKyAnLicgKyBjcnlwdG9cbiAgICAuY3JlYXRlSG1hYygnc2hhMjU2Jywgc2VjcmV0KVxuICAgIC51cGRhdGUodmFsKVxuICAgIC5kaWdlc3QoJ2Jhc2U2NCcpXG4gICAgLnJlcGxhY2UoL1xcPSskLywgJycpO1xufTtcblxuLyoqXG4gKiBVbnNpZ24gYW5kIGRlY29kZSB0aGUgZ2l2ZW4gYHZhbGAgd2l0aCBgc2VjcmV0YCxcbiAqIHJldHVybmluZyBgZmFsc2VgIGlmIHRoZSBzaWduYXR1cmUgaXMgaW52YWxpZC5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gdmFsXG4gKiBAcGFyYW0ge1N0cmluZ30gc2VjcmV0XG4gKiBAcmV0dXJuIHtTdHJpbmd8Qm9vbGVhbn1cbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cbmV4cG9ydHMudW5zaWduID0gZnVuY3Rpb24odmFsLCBzZWNyZXQpe1xuICBpZiAoJ3N0cmluZycgIT0gdHlwZW9mIHZhbCkgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlNpZ25lZCBjb29raWUgc3RyaW5nIG11c3QgYmUgcHJvdmlkZWQuXCIpO1xuICBpZiAoJ3N0cmluZycgIT0gdHlwZW9mIHNlY3JldCkgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlNlY3JldCBzdHJpbmcgbXVzdCBiZSBwcm92aWRlZC5cIik7XG4gIHZhciBzdHIgPSB2YWwuc2xpY2UoMCwgdmFsLmxhc3RJbmRleE9mKCcuJykpXG4gICAgLCBtYWMgPSBleHBvcnRzLnNpZ24oc3RyLCBzZWNyZXQpO1xuICBcbiAgcmV0dXJuIHNoYTEobWFjKSA9PSBzaGExKHZhbCkgPyBzdHIgOiBmYWxzZTtcbn07XG5cbi8qKlxuICogUHJpdmF0ZVxuICovXG5cbmZ1bmN0aW9uIHNoYTEoc3RyKXtcbiAgcmV0dXJuIGNyeXB0by5jcmVhdGVIYXNoKCdzaGExJykudXBkYXRlKHN0cikuZGlnZXN0KCdoZXgnKTtcbn1cbiIsIi8qIVxuICogY29va2llXG4gKiBDb3B5cmlnaHQoYykgMjAxMi0yMDE0IFJvbWFuIFNodHlsbWFuXG4gKiBDb3B5cmlnaHQoYykgMjAxNSBEb3VnbGFzIENocmlzdG9waGVyIFdpbHNvblxuICogTUlUIExpY2Vuc2VkXG4gKi9cblxuJ3VzZSBzdHJpY3QnO1xuXG4vKipcbiAqIE1vZHVsZSBleHBvcnRzLlxuICogQHB1YmxpY1xuICovXG5cbmV4cG9ydHMucGFyc2UgPSBwYXJzZTtcbmV4cG9ydHMuc2VyaWFsaXplID0gc2VyaWFsaXplO1xuXG4vKipcbiAqIE1vZHVsZSB2YXJpYWJsZXMuXG4gKiBAcHJpdmF0ZVxuICovXG5cbnZhciBfX3RvU3RyaW5nID0gT2JqZWN0LnByb3RvdHlwZS50b1N0cmluZ1xudmFyIF9faGFzT3duUHJvcGVydHkgPSBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5XG5cbi8qKlxuICogUmVnRXhwIHRvIG1hdGNoIGNvb2tpZS1uYW1lIGluIFJGQyA2MjY1IHNlYyA0LjEuMVxuICogVGhpcyByZWZlcnMgb3V0IHRvIHRoZSBvYnNvbGV0ZWQgZGVmaW5pdGlvbiBvZiB0b2tlbiBpbiBSRkMgMjYxNiBzZWMgMi4yXG4gKiB3aGljaCBoYXMgYmVlbiByZXBsYWNlZCBieSB0aGUgdG9rZW4gZGVmaW5pdGlvbiBpbiBSRkMgNzIzMCBhcHBlbmRpeCBCLlxuICpcbiAqIGNvb2tpZS1uYW1lICAgICAgID0gdG9rZW5cbiAqIHRva2VuICAgICAgICAgICAgID0gMSp0Y2hhclxuICogdGNoYXIgICAgICAgICAgICAgPSBcIiFcIiAvIFwiI1wiIC8gXCIkXCIgLyBcIiVcIiAvIFwiJlwiIC8gXCInXCIgL1xuICogICAgICAgICAgICAgICAgICAgICBcIipcIiAvIFwiK1wiIC8gXCItXCIgLyBcIi5cIiAvIFwiXlwiIC8gXCJfXCIgL1xuICogICAgICAgICAgICAgICAgICAgICBcImBcIiAvIFwifFwiIC8gXCJ+XCIgLyBESUdJVCAvIEFMUEhBXG4gKi9cblxudmFyIGNvb2tpZU5hbWVSZWdFeHAgPSAvXlshIyQlJicqK1xcLS5eX2B8fjAtOUEtWmEtel0rJC87XG5cbi8qKlxuICogUmVnRXhwIHRvIG1hdGNoIGNvb2tpZS12YWx1ZSBpbiBSRkMgNjI2NSBzZWMgNC4xLjFcbiAqXG4gKiBjb29raWUtdmFsdWUgICAgICA9ICpjb29raWUtb2N0ZXQgLyAoIERRVU9URSAqY29va2llLW9jdGV0IERRVU9URSApXG4gKiBjb29raWUtb2N0ZXQgICAgICA9ICV4MjEgLyAleDIzLTJCIC8gJXgyRC0zQSAvICV4M0MtNUIgLyAleDVELTdFXG4gKiAgICAgICAgICAgICAgICAgICAgIDsgVVMtQVNDSUkgY2hhcmFjdGVycyBleGNsdWRpbmcgQ1RMcyxcbiAqICAgICAgICAgICAgICAgICAgICAgOyB3aGl0ZXNwYWNlIERRVU9URSwgY29tbWEsIHNlbWljb2xvbixcbiAqICAgICAgICAgICAgICAgICAgICAgOyBhbmQgYmFja3NsYXNoXG4gKi9cblxudmFyIGNvb2tpZVZhbHVlUmVnRXhwID0gL14oXCI/KVtcXHUwMDIxXFx1MDAyMy1cXHUwMDJCXFx1MDAyRC1cXHUwMDNBXFx1MDAzQy1cXHUwMDVCXFx1MDA1RC1cXHUwMDdFXSpcXDEkLztcblxuLyoqXG4gKiBSZWdFeHAgdG8gbWF0Y2ggZG9tYWluLXZhbHVlIGluIFJGQyA2MjY1IHNlYyA0LjEuMVxuICpcbiAqIGRvbWFpbi12YWx1ZSAgICAgID0gPHN1YmRvbWFpbj5cbiAqICAgICAgICAgICAgICAgICAgICAgOyBkZWZpbmVkIGluIFtSRkMxMDM0XSwgU2VjdGlvbiAzLjUsIGFzXG4gKiAgICAgICAgICAgICAgICAgICAgIDsgZW5oYW5jZWQgYnkgW1JGQzExMjNdLCBTZWN0aW9uIDIuMVxuICogPHN1YmRvbWFpbj4gICAgICAgPSA8bGFiZWw+IHwgPHN1YmRvbWFpbj4gXCIuXCIgPGxhYmVsPlxuICogPGxhYmVsPiAgICAgICAgICAgPSA8bGV0LWRpZz4gWyBbIDxsZGgtc3RyPiBdIDxsZXQtZGlnPiBdXG4gKiAgICAgICAgICAgICAgICAgICAgIExhYmVscyBtdXN0IGJlIDYzIGNoYXJhY3RlcnMgb3IgbGVzcy5cbiAqICAgICAgICAgICAgICAgICAgICAgJ2xldC1kaWcnIG5vdCAnbGV0dGVyJyBpbiB0aGUgZmlyc3QgY2hhciwgcGVyIFJGQzExMjNcbiAqIDxsZGgtc3RyPiAgICAgICAgID0gPGxldC1kaWctaHlwPiB8IDxsZXQtZGlnLWh5cD4gPGxkaC1zdHI+XG4gKiA8bGV0LWRpZy1oeXA+ICAgICA9IDxsZXQtZGlnPiB8IFwiLVwiXG4gKiA8bGV0LWRpZz4gICAgICAgICA9IDxsZXR0ZXI+IHwgPGRpZ2l0PlxuICogPGxldHRlcj4gICAgICAgICAgPSBhbnkgb25lIG9mIHRoZSA1MiBhbHBoYWJldGljIGNoYXJhY3RlcnMgQSB0aHJvdWdoIFogaW5cbiAqICAgICAgICAgICAgICAgICAgICAgdXBwZXIgY2FzZSBhbmQgYSB0aHJvdWdoIHogaW4gbG93ZXIgY2FzZVxuICogPGRpZ2l0PiAgICAgICAgICAgPSBhbnkgb25lIG9mIHRoZSB0ZW4gZGlnaXRzIDAgdGhyb3VnaCA5XG4gKlxuICogS2VlcCBzdXBwb3J0IGZvciBsZWFkaW5nIGRvdDogaHR0cHM6Ly9naXRodWIuY29tL2pzaHR0cC9jb29raWUvaXNzdWVzLzE3M1xuICpcbiAqID4gKE5vdGUgdGhhdCBhIGxlYWRpbmcgJXgyRSAoXCIuXCIpLCBpZiBwcmVzZW50LCBpcyBpZ25vcmVkIGV2ZW4gdGhvdWdoIHRoYXRcbiAqIGNoYXJhY3RlciBpcyBub3QgcGVybWl0dGVkLCBidXQgYSB0cmFpbGluZyAleDJFIChcIi5cIiksIGlmIHByZXNlbnQsIHdpbGxcbiAqIGNhdXNlIHRoZSB1c2VyIGFnZW50IHRvIGlnbm9yZSB0aGUgYXR0cmlidXRlLilcbiAqL1xuXG52YXIgZG9tYWluVmFsdWVSZWdFeHAgPSAvXihbLl0/W2EtejAtOV0oW2EtejAtOS1dezAsNjF9W2EtejAtOV0pPykoWy5dW2EtejAtOV0oW2EtejAtOS1dezAsNjF9W2EtejAtOV0pPykqJC9pO1xuXG4vKipcbiAqIFJlZ0V4cCB0byBtYXRjaCBwYXRoLXZhbHVlIGluIFJGQyA2MjY1IHNlYyA0LjEuMVxuICpcbiAqIHBhdGgtdmFsdWUgICAgICAgID0gPGFueSBDSEFSIGV4Y2VwdCBDVExzIG9yIFwiO1wiPlxuICogQ0hBUiAgICAgICAgICAgICAgPSAleDAxLTdGXG4gKiAgICAgICAgICAgICAgICAgICAgIDsgZGVmaW5lZCBpbiBSRkMgNTIzNCBhcHBlbmRpeCBCLjFcbiAqL1xuXG52YXIgcGF0aFZhbHVlUmVnRXhwID0gL15bXFx1MDAyMC1cXHUwMDNBXFx1MDAzRC1cXHUwMDdFXSokLztcblxuLyoqXG4gKiBQYXJzZSBhIGNvb2tpZSBoZWFkZXIuXG4gKlxuICogUGFyc2UgdGhlIGdpdmVuIGNvb2tpZSBoZWFkZXIgc3RyaW5nIGludG8gYW4gb2JqZWN0XG4gKiBUaGUgb2JqZWN0IGhhcyB0aGUgdmFyaW91cyBjb29raWVzIGFzIGtleXMobmFtZXMpID0+IHZhbHVlc1xuICpcbiAqIEBwYXJhbSB7c3RyaW5nfSBzdHJcbiAqIEBwYXJhbSB7b2JqZWN0fSBbb3B0XVxuICogQHJldHVybiB7b2JqZWN0fVxuICogQHB1YmxpY1xuICovXG5cbmZ1bmN0aW9uIHBhcnNlKHN0ciwgb3B0KSB7XG4gIGlmICh0eXBlb2Ygc3RyICE9PSAnc3RyaW5nJykge1xuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ2FyZ3VtZW50IHN0ciBtdXN0IGJlIGEgc3RyaW5nJyk7XG4gIH1cblxuICB2YXIgb2JqID0ge307XG4gIHZhciBsZW4gPSBzdHIubGVuZ3RoO1xuICAvLyBSRkMgNjI2NSBzZWMgNC4xLjEsIFJGQyAyNjE2IDIuMiBkZWZpbmVzIGEgY29va2llIG5hbWUgY29uc2lzdHMgb2Ygb25lIGNoYXIgbWluaW11bSwgcGx1cyAnPScuXG4gIGlmIChsZW4gPCAyKSByZXR1cm4gb2JqO1xuXG4gIHZhciBkZWMgPSAob3B0ICYmIG9wdC5kZWNvZGUpIHx8IGRlY29kZTtcbiAgdmFyIGluZGV4ID0gMDtcbiAgdmFyIGVxSWR4ID0gMDtcbiAgdmFyIGVuZElkeCA9IDA7XG5cbiAgZG8ge1xuICAgIGVxSWR4ID0gc3RyLmluZGV4T2YoJz0nLCBpbmRleCk7XG4gICAgaWYgKGVxSWR4ID09PSAtMSkgYnJlYWs7IC8vIE5vIG1vcmUgY29va2llIHBhaXJzLlxuXG4gICAgZW5kSWR4ID0gc3RyLmluZGV4T2YoJzsnLCBpbmRleCk7XG5cbiAgICBpZiAoZW5kSWR4ID09PSAtMSkge1xuICAgICAgZW5kSWR4ID0gbGVuO1xuICAgIH0gZWxzZSBpZiAoZXFJZHggPiBlbmRJZHgpIHtcbiAgICAgIC8vIGJhY2t0cmFjayBvbiBwcmlvciBzZW1pY29sb25cbiAgICAgIGluZGV4ID0gc3RyLmxhc3RJbmRleE9mKCc7JywgZXFJZHggLSAxKSArIDE7XG4gICAgICBjb250aW51ZTtcbiAgICB9XG5cbiAgICB2YXIga2V5U3RhcnRJZHggPSBzdGFydEluZGV4KHN0ciwgaW5kZXgsIGVxSWR4KTtcbiAgICB2YXIga2V5RW5kSWR4ID0gZW5kSW5kZXgoc3RyLCBlcUlkeCwga2V5U3RhcnRJZHgpO1xuICAgIHZhciBrZXkgPSBzdHIuc2xpY2Uoa2V5U3RhcnRJZHgsIGtleUVuZElkeCk7XG5cbiAgICAvLyBvbmx5IGFzc2lnbiBvbmNlXG4gICAgaWYgKCFfX2hhc093blByb3BlcnR5LmNhbGwob2JqLCBrZXkpKSB7XG4gICAgICB2YXIgdmFsU3RhcnRJZHggPSBzdGFydEluZGV4KHN0ciwgZXFJZHggKyAxLCBlbmRJZHgpO1xuICAgICAgdmFyIHZhbEVuZElkeCA9IGVuZEluZGV4KHN0ciwgZW5kSWR4LCB2YWxTdGFydElkeCk7XG5cbiAgICAgIGlmIChzdHIuY2hhckNvZGVBdCh2YWxTdGFydElkeCkgPT09IDB4MjIgLyogXCIgKi8gJiYgc3RyLmNoYXJDb2RlQXQodmFsRW5kSWR4IC0gMSkgPT09IDB4MjIgLyogXCIgKi8pIHtcbiAgICAgICAgdmFsU3RhcnRJZHgrKztcbiAgICAgICAgdmFsRW5kSWR4LS07XG4gICAgICB9XG5cbiAgICAgIHZhciB2YWwgPSBzdHIuc2xpY2UodmFsU3RhcnRJZHgsIHZhbEVuZElkeCk7XG4gICAgICBvYmpba2V5XSA9IHRyeURlY29kZSh2YWwsIGRlYyk7XG4gICAgfVxuXG4gICAgaW5kZXggPSBlbmRJZHggKyAxXG4gIH0gd2hpbGUgKGluZGV4IDwgbGVuKTtcblxuICByZXR1cm4gb2JqO1xufVxuXG5mdW5jdGlvbiBzdGFydEluZGV4KHN0ciwgaW5kZXgsIG1heCkge1xuICBkbyB7XG4gICAgdmFyIGNvZGUgPSBzdHIuY2hhckNvZGVBdChpbmRleCk7XG4gICAgaWYgKGNvZGUgIT09IDB4MjAgLyogICAqLyAmJiBjb2RlICE9PSAweDA5IC8qIFxcdCAqLykgcmV0dXJuIGluZGV4O1xuICB9IHdoaWxlICgrK2luZGV4IDwgbWF4KTtcbiAgcmV0dXJuIG1heDtcbn1cblxuZnVuY3Rpb24gZW5kSW5kZXgoc3RyLCBpbmRleCwgbWluKSB7XG4gIHdoaWxlIChpbmRleCA+IG1pbikge1xuICAgIHZhciBjb2RlID0gc3RyLmNoYXJDb2RlQXQoLS1pbmRleCk7XG4gICAgaWYgKGNvZGUgIT09IDB4MjAgLyogICAqLyAmJiBjb2RlICE9PSAweDA5IC8qIFxcdCAqLykgcmV0dXJuIGluZGV4ICsgMTtcbiAgfVxuICByZXR1cm4gbWluO1xufVxuXG4vKipcbiAqIFNlcmlhbGl6ZSBkYXRhIGludG8gYSBjb29raWUgaGVhZGVyLlxuICpcbiAqIFNlcmlhbGl6ZSBhIG5hbWUgdmFsdWUgcGFpciBpbnRvIGEgY29va2llIHN0cmluZyBzdWl0YWJsZSBmb3JcbiAqIGh0dHAgaGVhZGVycy4gQW4gb3B0aW9uYWwgb3B0aW9ucyBvYmplY3Qgc3BlY2lmaWVzIGNvb2tpZSBwYXJhbWV0ZXJzLlxuICpcbiAqIHNlcmlhbGl6ZSgnZm9vJywgJ2JhcicsIHsgaHR0cE9ubHk6IHRydWUgfSlcbiAqICAgPT4gXCJmb289YmFyOyBodHRwT25seVwiXG4gKlxuICogQHBhcmFtIHtzdHJpbmd9IG5hbWVcbiAqIEBwYXJhbSB7c3RyaW5nfSB2YWxcbiAqIEBwYXJhbSB7b2JqZWN0fSBbb3B0XVxuICogQHJldHVybiB7c3RyaW5nfVxuICogQHB1YmxpY1xuICovXG5cbmZ1bmN0aW9uIHNlcmlhbGl6ZShuYW1lLCB2YWwsIG9wdCkge1xuICB2YXIgZW5jID0gKG9wdCAmJiBvcHQuZW5jb2RlKSB8fCBlbmNvZGVVUklDb21wb25lbnQ7XG5cbiAgaWYgKHR5cGVvZiBlbmMgIT09ICdmdW5jdGlvbicpIHtcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdvcHRpb24gZW5jb2RlIGlzIGludmFsaWQnKTtcbiAgfVxuXG4gIGlmICghY29va2llTmFtZVJlZ0V4cC50ZXN0KG5hbWUpKSB7XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcignYXJndW1lbnQgbmFtZSBpcyBpbnZhbGlkJyk7XG4gIH1cblxuICB2YXIgdmFsdWUgPSBlbmModmFsKTtcblxuICBpZiAoIWNvb2tpZVZhbHVlUmVnRXhwLnRlc3QodmFsdWUpKSB7XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcignYXJndW1lbnQgdmFsIGlzIGludmFsaWQnKTtcbiAgfVxuXG4gIHZhciBzdHIgPSBuYW1lICsgJz0nICsgdmFsdWU7XG4gIGlmICghb3B0KSByZXR1cm4gc3RyO1xuXG4gIGlmIChudWxsICE9IG9wdC5tYXhBZ2UpIHtcbiAgICB2YXIgbWF4QWdlID0gTWF0aC5mbG9vcihvcHQubWF4QWdlKTtcblxuICAgIGlmICghaXNGaW5pdGUobWF4QWdlKSkge1xuICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignb3B0aW9uIG1heEFnZSBpcyBpbnZhbGlkJylcbiAgICB9XG5cbiAgICBzdHIgKz0gJzsgTWF4LUFnZT0nICsgbWF4QWdlO1xuICB9XG5cbiAgaWYgKG9wdC5kb21haW4pIHtcbiAgICBpZiAoIWRvbWFpblZhbHVlUmVnRXhwLnRlc3Qob3B0LmRvbWFpbikpIHtcbiAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ29wdGlvbiBkb21haW4gaXMgaW52YWxpZCcpO1xuICAgIH1cblxuICAgIHN0ciArPSAnOyBEb21haW49JyArIG9wdC5kb21haW47XG4gIH1cblxuICBpZiAob3B0LnBhdGgpIHtcbiAgICBpZiAoIXBhdGhWYWx1ZVJlZ0V4cC50ZXN0KG9wdC5wYXRoKSkge1xuICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignb3B0aW9uIHBhdGggaXMgaW52YWxpZCcpO1xuICAgIH1cblxuICAgIHN0ciArPSAnOyBQYXRoPScgKyBvcHQucGF0aDtcbiAgfVxuXG4gIGlmIChvcHQuZXhwaXJlcykge1xuICAgIHZhciBleHBpcmVzID0gb3B0LmV4cGlyZXNcblxuICAgIGlmICghaXNEYXRlKGV4cGlyZXMpIHx8IGlzTmFOKGV4cGlyZXMudmFsdWVPZigpKSkge1xuICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignb3B0aW9uIGV4cGlyZXMgaXMgaW52YWxpZCcpO1xuICAgIH1cblxuICAgIHN0ciArPSAnOyBFeHBpcmVzPScgKyBleHBpcmVzLnRvVVRDU3RyaW5nKClcbiAgfVxuXG4gIGlmIChvcHQuaHR0cE9ubHkpIHtcbiAgICBzdHIgKz0gJzsgSHR0cE9ubHknO1xuICB9XG5cbiAgaWYgKG9wdC5zZWN1cmUpIHtcbiAgICBzdHIgKz0gJzsgU2VjdXJlJztcbiAgfVxuXG4gIGlmIChvcHQucGFydGl0aW9uZWQpIHtcbiAgICBzdHIgKz0gJzsgUGFydGl0aW9uZWQnXG4gIH1cblxuICBpZiAob3B0LnByaW9yaXR5KSB7XG4gICAgdmFyIHByaW9yaXR5ID0gdHlwZW9mIG9wdC5wcmlvcml0eSA9PT0gJ3N0cmluZydcbiAgICAgID8gb3B0LnByaW9yaXR5LnRvTG93ZXJDYXNlKCkgOiBvcHQucHJpb3JpdHk7XG5cbiAgICBzd2l0Y2ggKHByaW9yaXR5KSB7XG4gICAgICBjYXNlICdsb3cnOlxuICAgICAgICBzdHIgKz0gJzsgUHJpb3JpdHk9TG93J1xuICAgICAgICBicmVha1xuICAgICAgY2FzZSAnbWVkaXVtJzpcbiAgICAgICAgc3RyICs9ICc7IFByaW9yaXR5PU1lZGl1bSdcbiAgICAgICAgYnJlYWtcbiAgICAgIGNhc2UgJ2hpZ2gnOlxuICAgICAgICBzdHIgKz0gJzsgUHJpb3JpdHk9SGlnaCdcbiAgICAgICAgYnJlYWtcbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ29wdGlvbiBwcmlvcml0eSBpcyBpbnZhbGlkJylcbiAgICB9XG4gIH1cblxuICBpZiAob3B0LnNhbWVTaXRlKSB7XG4gICAgdmFyIHNhbWVTaXRlID0gdHlwZW9mIG9wdC5zYW1lU2l0ZSA9PT0gJ3N0cmluZydcbiAgICAgID8gb3B0LnNhbWVTaXRlLnRvTG93ZXJDYXNlKCkgOiBvcHQuc2FtZVNpdGU7XG5cbiAgICBzd2l0Y2ggKHNhbWVTaXRlKSB7XG4gICAgICBjYXNlIHRydWU6XG4gICAgICAgIHN0ciArPSAnOyBTYW1lU2l0ZT1TdHJpY3QnO1xuICAgICAgICBicmVhaztcbiAgICAgIGNhc2UgJ2xheCc6XG4gICAgICAgIHN0ciArPSAnOyBTYW1lU2l0ZT1MYXgnO1xuICAgICAgICBicmVhaztcbiAgICAgIGNhc2UgJ3N0cmljdCc6XG4gICAgICAgIHN0ciArPSAnOyBTYW1lU2l0ZT1TdHJpY3QnO1xuICAgICAgICBicmVhaztcbiAgICAgIGNhc2UgJ25vbmUnOlxuICAgICAgICBzdHIgKz0gJzsgU2FtZVNpdGU9Tm9uZSc7XG4gICAgICAgIGJyZWFrO1xuICAgICAgZGVmYXVsdDpcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignb3B0aW9uIHNhbWVTaXRlIGlzIGludmFsaWQnKTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gc3RyO1xufVxuXG4vKipcbiAqIFVSTC1kZWNvZGUgc3RyaW5nIHZhbHVlLiBPcHRpbWl6ZWQgdG8gc2tpcCBuYXRpdmUgY2FsbCB3aGVuIG5vICUuXG4gKlxuICogQHBhcmFtIHtzdHJpbmd9IHN0clxuICogQHJldHVybnMge3N0cmluZ31cbiAqL1xuXG5mdW5jdGlvbiBkZWNvZGUgKHN0cikge1xuICByZXR1cm4gc3RyLmluZGV4T2YoJyUnKSAhPT0gLTFcbiAgICA/IGRlY29kZVVSSUNvbXBvbmVudChzdHIpXG4gICAgOiBzdHJcbn1cblxuLyoqXG4gKiBEZXRlcm1pbmUgaWYgdmFsdWUgaXMgYSBEYXRlLlxuICpcbiAqIEBwYXJhbSB7Kn0gdmFsXG4gKiBAcHJpdmF0ZVxuICovXG5cbmZ1bmN0aW9uIGlzRGF0ZSAodmFsKSB7XG4gIHJldHVybiBfX3RvU3RyaW5nLmNhbGwodmFsKSA9PT0gJ1tvYmplY3QgRGF0ZV0nO1xufVxuXG4vKipcbiAqIFRyeSBkZWNvZGluZyBhIHN0cmluZyB1c2luZyBhIGRlY29kaW5nIGZ1bmN0aW9uLlxuICpcbiAqIEBwYXJhbSB7c3RyaW5nfSBzdHJcbiAqIEBwYXJhbSB7ZnVuY3Rpb259IGRlY29kZVxuICogQHByaXZhdGVcbiAqL1xuXG5mdW5jdGlvbiB0cnlEZWNvZGUoc3RyLCBkZWNvZGUpIHtcbiAgdHJ5IHtcbiAgICByZXR1cm4gZGVjb2RlKHN0cik7XG4gIH0gY2F0Y2ggKGUpIHtcbiAgICByZXR1cm4gc3RyO1xuICB9XG59XG4iLCIoZnVuY3Rpb24gKCkge1xuXG4gICd1c2Ugc3RyaWN0JztcblxuICB2YXIgYXNzaWduID0gcmVxdWlyZSgnb2JqZWN0LWFzc2lnbicpO1xuICB2YXIgdmFyeSA9IHJlcXVpcmUoJ3ZhcnknKTtcblxuICB2YXIgZGVmYXVsdHMgPSB7XG4gICAgb3JpZ2luOiAnKicsXG4gICAgbWV0aG9kczogJ0dFVCxIRUFELFBVVCxQQVRDSCxQT1NULERFTEVURScsXG4gICAgcHJlZmxpZ2h0Q29udGludWU6IGZhbHNlLFxuICAgIG9wdGlvbnNTdWNjZXNzU3RhdHVzOiAyMDRcbiAgfTtcblxuICBmdW5jdGlvbiBpc1N0cmluZyhzKSB7XG4gICAgcmV0dXJuIHR5cGVvZiBzID09PSAnc3RyaW5nJyB8fCBzIGluc3RhbmNlb2YgU3RyaW5nO1xuICB9XG5cbiAgZnVuY3Rpb24gaXNPcmlnaW5BbGxvd2VkKG9yaWdpbiwgYWxsb3dlZE9yaWdpbikge1xuICAgIGlmIChBcnJheS5pc0FycmF5KGFsbG93ZWRPcmlnaW4pKSB7XG4gICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGFsbG93ZWRPcmlnaW4ubGVuZ3RoOyArK2kpIHtcbiAgICAgICAgaWYgKGlzT3JpZ2luQWxsb3dlZChvcmlnaW4sIGFsbG93ZWRPcmlnaW5baV0pKSB7XG4gICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9IGVsc2UgaWYgKGlzU3RyaW5nKGFsbG93ZWRPcmlnaW4pKSB7XG4gICAgICByZXR1cm4gb3JpZ2luID09PSBhbGxvd2VkT3JpZ2luO1xuICAgIH0gZWxzZSBpZiAoYWxsb3dlZE9yaWdpbiBpbnN0YW5jZW9mIFJlZ0V4cCkge1xuICAgICAgcmV0dXJuIGFsbG93ZWRPcmlnaW4udGVzdChvcmlnaW4pO1xuICAgIH0gZWxzZSB7XG4gICAgICByZXR1cm4gISFhbGxvd2VkT3JpZ2luO1xuICAgIH1cbiAgfVxuXG4gIGZ1bmN0aW9uIGNvbmZpZ3VyZU9yaWdpbihvcHRpb25zLCByZXEpIHtcbiAgICB2YXIgcmVxdWVzdE9yaWdpbiA9IHJlcS5oZWFkZXJzLm9yaWdpbixcbiAgICAgIGhlYWRlcnMgPSBbXSxcbiAgICAgIGlzQWxsb3dlZDtcblxuICAgIGlmICghb3B0aW9ucy5vcmlnaW4gfHwgb3B0aW9ucy5vcmlnaW4gPT09ICcqJykge1xuICAgICAgLy8gYWxsb3cgYW55IG9yaWdpblxuICAgICAgaGVhZGVycy5wdXNoKFt7XG4gICAgICAgIGtleTogJ0FjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbicsXG4gICAgICAgIHZhbHVlOiAnKidcbiAgICAgIH1dKTtcbiAgICB9IGVsc2UgaWYgKGlzU3RyaW5nKG9wdGlvbnMub3JpZ2luKSkge1xuICAgICAgLy8gZml4ZWQgb3JpZ2luXG4gICAgICBoZWFkZXJzLnB1c2goW3tcbiAgICAgICAga2V5OiAnQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luJyxcbiAgICAgICAgdmFsdWU6IG9wdGlvbnMub3JpZ2luXG4gICAgICB9XSk7XG4gICAgICBoZWFkZXJzLnB1c2goW3tcbiAgICAgICAga2V5OiAnVmFyeScsXG4gICAgICAgIHZhbHVlOiAnT3JpZ2luJ1xuICAgICAgfV0pO1xuICAgIH0gZWxzZSB7XG4gICAgICBpc0FsbG93ZWQgPSBpc09yaWdpbkFsbG93ZWQocmVxdWVzdE9yaWdpbiwgb3B0aW9ucy5vcmlnaW4pO1xuICAgICAgLy8gcmVmbGVjdCBvcmlnaW5cbiAgICAgIGhlYWRlcnMucHVzaChbe1xuICAgICAgICBrZXk6ICdBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4nLFxuICAgICAgICB2YWx1ZTogaXNBbGxvd2VkID8gcmVxdWVzdE9yaWdpbiA6IGZhbHNlXG4gICAgICB9XSk7XG4gICAgICBoZWFkZXJzLnB1c2goW3tcbiAgICAgICAga2V5OiAnVmFyeScsXG4gICAgICAgIHZhbHVlOiAnT3JpZ2luJ1xuICAgICAgfV0pO1xuICAgIH1cblxuICAgIHJldHVybiBoZWFkZXJzO1xuICB9XG5cbiAgZnVuY3Rpb24gY29uZmlndXJlTWV0aG9kcyhvcHRpb25zKSB7XG4gICAgdmFyIG1ldGhvZHMgPSBvcHRpb25zLm1ldGhvZHM7XG4gICAgaWYgKG1ldGhvZHMuam9pbikge1xuICAgICAgbWV0aG9kcyA9IG9wdGlvbnMubWV0aG9kcy5qb2luKCcsJyk7IC8vIC5tZXRob2RzIGlzIGFuIGFycmF5LCBzbyB0dXJuIGl0IGludG8gYSBzdHJpbmdcbiAgICB9XG4gICAgcmV0dXJuIHtcbiAgICAgIGtleTogJ0FjY2Vzcy1Db250cm9sLUFsbG93LU1ldGhvZHMnLFxuICAgICAgdmFsdWU6IG1ldGhvZHNcbiAgICB9O1xuICB9XG5cbiAgZnVuY3Rpb24gY29uZmlndXJlQ3JlZGVudGlhbHMob3B0aW9ucykge1xuICAgIGlmIChvcHRpb25zLmNyZWRlbnRpYWxzID09PSB0cnVlKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBrZXk6ICdBY2Nlc3MtQ29udHJvbC1BbGxvdy1DcmVkZW50aWFscycsXG4gICAgICAgIHZhbHVlOiAndHJ1ZSdcbiAgICAgIH07XG4gICAgfVxuICAgIHJldHVybiBudWxsO1xuICB9XG5cbiAgZnVuY3Rpb24gY29uZmlndXJlQWxsb3dlZEhlYWRlcnMob3B0aW9ucywgcmVxKSB7XG4gICAgdmFyIGFsbG93ZWRIZWFkZXJzID0gb3B0aW9ucy5hbGxvd2VkSGVhZGVycyB8fCBvcHRpb25zLmhlYWRlcnM7XG4gICAgdmFyIGhlYWRlcnMgPSBbXTtcblxuICAgIGlmICghYWxsb3dlZEhlYWRlcnMpIHtcbiAgICAgIGFsbG93ZWRIZWFkZXJzID0gcmVxLmhlYWRlcnNbJ2FjY2Vzcy1jb250cm9sLXJlcXVlc3QtaGVhZGVycyddOyAvLyAuaGVhZGVycyB3YXNuJ3Qgc3BlY2lmaWVkLCBzbyByZWZsZWN0IHRoZSByZXF1ZXN0IGhlYWRlcnNcbiAgICAgIGhlYWRlcnMucHVzaChbe1xuICAgICAgICBrZXk6ICdWYXJ5JyxcbiAgICAgICAgdmFsdWU6ICdBY2Nlc3MtQ29udHJvbC1SZXF1ZXN0LUhlYWRlcnMnXG4gICAgICB9XSk7XG4gICAgfSBlbHNlIGlmIChhbGxvd2VkSGVhZGVycy5qb2luKSB7XG4gICAgICBhbGxvd2VkSGVhZGVycyA9IGFsbG93ZWRIZWFkZXJzLmpvaW4oJywnKTsgLy8gLmhlYWRlcnMgaXMgYW4gYXJyYXksIHNvIHR1cm4gaXQgaW50byBhIHN0cmluZ1xuICAgIH1cbiAgICBpZiAoYWxsb3dlZEhlYWRlcnMgJiYgYWxsb3dlZEhlYWRlcnMubGVuZ3RoKSB7XG4gICAgICBoZWFkZXJzLnB1c2goW3tcbiAgICAgICAga2V5OiAnQWNjZXNzLUNvbnRyb2wtQWxsb3ctSGVhZGVycycsXG4gICAgICAgIHZhbHVlOiBhbGxvd2VkSGVhZGVyc1xuICAgICAgfV0pO1xuICAgIH1cblxuICAgIHJldHVybiBoZWFkZXJzO1xuICB9XG5cbiAgZnVuY3Rpb24gY29uZmlndXJlRXhwb3NlZEhlYWRlcnMob3B0aW9ucykge1xuICAgIHZhciBoZWFkZXJzID0gb3B0aW9ucy5leHBvc2VkSGVhZGVycztcbiAgICBpZiAoIWhlYWRlcnMpIHtcbiAgICAgIHJldHVybiBudWxsO1xuICAgIH0gZWxzZSBpZiAoaGVhZGVycy5qb2luKSB7XG4gICAgICBoZWFkZXJzID0gaGVhZGVycy5qb2luKCcsJyk7IC8vIC5oZWFkZXJzIGlzIGFuIGFycmF5LCBzbyB0dXJuIGl0IGludG8gYSBzdHJpbmdcbiAgICB9XG4gICAgaWYgKGhlYWRlcnMgJiYgaGVhZGVycy5sZW5ndGgpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIGtleTogJ0FjY2Vzcy1Db250cm9sLUV4cG9zZS1IZWFkZXJzJyxcbiAgICAgICAgdmFsdWU6IGhlYWRlcnNcbiAgICAgIH07XG4gICAgfVxuICAgIHJldHVybiBudWxsO1xuICB9XG5cbiAgZnVuY3Rpb24gY29uZmlndXJlTWF4QWdlKG9wdGlvbnMpIHtcbiAgICB2YXIgbWF4QWdlID0gKHR5cGVvZiBvcHRpb25zLm1heEFnZSA9PT0gJ251bWJlcicgfHwgb3B0aW9ucy5tYXhBZ2UpICYmIG9wdGlvbnMubWF4QWdlLnRvU3RyaW5nKClcbiAgICBpZiAobWF4QWdlICYmIG1heEFnZS5sZW5ndGgpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIGtleTogJ0FjY2Vzcy1Db250cm9sLU1heC1BZ2UnLFxuICAgICAgICB2YWx1ZTogbWF4QWdlXG4gICAgICB9O1xuICAgIH1cbiAgICByZXR1cm4gbnVsbDtcbiAgfVxuXG4gIGZ1bmN0aW9uIGFwcGx5SGVhZGVycyhoZWFkZXJzLCByZXMpIHtcbiAgICBmb3IgKHZhciBpID0gMCwgbiA9IGhlYWRlcnMubGVuZ3RoOyBpIDwgbjsgaSsrKSB7XG4gICAgICB2YXIgaGVhZGVyID0gaGVhZGVyc1tpXTtcbiAgICAgIGlmIChoZWFkZXIpIHtcbiAgICAgICAgaWYgKEFycmF5LmlzQXJyYXkoaGVhZGVyKSkge1xuICAgICAgICAgIGFwcGx5SGVhZGVycyhoZWFkZXIsIHJlcyk7XG4gICAgICAgIH0gZWxzZSBpZiAoaGVhZGVyLmtleSA9PT0gJ1ZhcnknICYmIGhlYWRlci52YWx1ZSkge1xuICAgICAgICAgIHZhcnkocmVzLCBoZWFkZXIudmFsdWUpO1xuICAgICAgICB9IGVsc2UgaWYgKGhlYWRlci52YWx1ZSkge1xuICAgICAgICAgIHJlcy5zZXRIZWFkZXIoaGVhZGVyLmtleSwgaGVhZGVyLnZhbHVlKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIGZ1bmN0aW9uIGNvcnMob3B0aW9ucywgcmVxLCByZXMsIG5leHQpIHtcbiAgICB2YXIgaGVhZGVycyA9IFtdLFxuICAgICAgbWV0aG9kID0gcmVxLm1ldGhvZCAmJiByZXEubWV0aG9kLnRvVXBwZXJDYXNlICYmIHJlcS5tZXRob2QudG9VcHBlckNhc2UoKTtcblxuICAgIGlmIChtZXRob2QgPT09ICdPUFRJT05TJykge1xuICAgICAgLy8gcHJlZmxpZ2h0XG4gICAgICBoZWFkZXJzLnB1c2goY29uZmlndXJlT3JpZ2luKG9wdGlvbnMsIHJlcSkpO1xuICAgICAgaGVhZGVycy5wdXNoKGNvbmZpZ3VyZUNyZWRlbnRpYWxzKG9wdGlvbnMsIHJlcSkpO1xuICAgICAgaGVhZGVycy5wdXNoKGNvbmZpZ3VyZU1ldGhvZHMob3B0aW9ucywgcmVxKSk7XG4gICAgICBoZWFkZXJzLnB1c2goY29uZmlndXJlQWxsb3dlZEhlYWRlcnMob3B0aW9ucywgcmVxKSk7XG4gICAgICBoZWFkZXJzLnB1c2goY29uZmlndXJlTWF4QWdlKG9wdGlvbnMsIHJlcSkpO1xuICAgICAgaGVhZGVycy5wdXNoKGNvbmZpZ3VyZUV4cG9zZWRIZWFkZXJzKG9wdGlvbnMsIHJlcSkpO1xuICAgICAgYXBwbHlIZWFkZXJzKGhlYWRlcnMsIHJlcyk7XG5cbiAgICAgIGlmIChvcHRpb25zLnByZWZsaWdodENvbnRpbnVlKSB7XG4gICAgICAgIG5leHQoKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIC8vIFNhZmFyaSAoYW5kIHBvdGVudGlhbGx5IG90aGVyIGJyb3dzZXJzKSBuZWVkIGNvbnRlbnQtbGVuZ3RoIDAsXG4gICAgICAgIC8vICAgZm9yIDIwNCBvciB0aGV5IGp1c3QgaGFuZyB3YWl0aW5nIGZvciBhIGJvZHlcbiAgICAgICAgcmVzLnN0YXR1c0NvZGUgPSBvcHRpb25zLm9wdGlvbnNTdWNjZXNzU3RhdHVzO1xuICAgICAgICByZXMuc2V0SGVhZGVyKCdDb250ZW50LUxlbmd0aCcsICcwJyk7XG4gICAgICAgIHJlcy5lbmQoKTtcbiAgICAgIH1cbiAgICB9IGVsc2Uge1xuICAgICAgLy8gYWN0dWFsIHJlc3BvbnNlXG4gICAgICBoZWFkZXJzLnB1c2goY29uZmlndXJlT3JpZ2luKG9wdGlvbnMsIHJlcSkpO1xuICAgICAgaGVhZGVycy5wdXNoKGNvbmZpZ3VyZUNyZWRlbnRpYWxzKG9wdGlvbnMsIHJlcSkpO1xuICAgICAgaGVhZGVycy5wdXNoKGNvbmZpZ3VyZUV4cG9zZWRIZWFkZXJzKG9wdGlvbnMsIHJlcSkpO1xuICAgICAgYXBwbHlIZWFkZXJzKGhlYWRlcnMsIHJlcyk7XG4gICAgICBuZXh0KCk7XG4gICAgfVxuICB9XG5cbiAgZnVuY3Rpb24gbWlkZGxld2FyZVdyYXBwZXIobykge1xuICAgIC8vIGlmIG9wdGlvbnMgYXJlIHN0YXRpYyAoZWl0aGVyIHZpYSBkZWZhdWx0cyBvciBjdXN0b20gb3B0aW9ucyBwYXNzZWQgaW4pLCB3cmFwIGluIGEgZnVuY3Rpb25cbiAgICB2YXIgb3B0aW9uc0NhbGxiYWNrID0gbnVsbDtcbiAgICBpZiAodHlwZW9mIG8gPT09ICdmdW5jdGlvbicpIHtcbiAgICAgIG9wdGlvbnNDYWxsYmFjayA9IG87XG4gICAgfSBlbHNlIHtcbiAgICAgIG9wdGlvbnNDYWxsYmFjayA9IGZ1bmN0aW9uIChyZXEsIGNiKSB7XG4gICAgICAgIGNiKG51bGwsIG8pO1xuICAgICAgfTtcbiAgICB9XG5cbiAgICByZXR1cm4gZnVuY3Rpb24gY29yc01pZGRsZXdhcmUocmVxLCByZXMsIG5leHQpIHtcbiAgICAgIG9wdGlvbnNDYWxsYmFjayhyZXEsIGZ1bmN0aW9uIChlcnIsIG9wdGlvbnMpIHtcbiAgICAgICAgaWYgKGVycikge1xuICAgICAgICAgIG5leHQoZXJyKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICB2YXIgY29yc09wdGlvbnMgPSBhc3NpZ24oe30sIGRlZmF1bHRzLCBvcHRpb25zKTtcbiAgICAgICAgICB2YXIgb3JpZ2luQ2FsbGJhY2sgPSBudWxsO1xuICAgICAgICAgIGlmIChjb3JzT3B0aW9ucy5vcmlnaW4gJiYgdHlwZW9mIGNvcnNPcHRpb25zLm9yaWdpbiA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICAgICAgb3JpZ2luQ2FsbGJhY2sgPSBjb3JzT3B0aW9ucy5vcmlnaW47XG4gICAgICAgICAgfSBlbHNlIGlmIChjb3JzT3B0aW9ucy5vcmlnaW4pIHtcbiAgICAgICAgICAgIG9yaWdpbkNhbGxiYWNrID0gZnVuY3Rpb24gKG9yaWdpbiwgY2IpIHtcbiAgICAgICAgICAgICAgY2IobnVsbCwgY29yc09wdGlvbnMub3JpZ2luKTtcbiAgICAgICAgICAgIH07XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKG9yaWdpbkNhbGxiYWNrKSB7XG4gICAgICAgICAgICBvcmlnaW5DYWxsYmFjayhyZXEuaGVhZGVycy5vcmlnaW4sIGZ1bmN0aW9uIChlcnIyLCBvcmlnaW4pIHtcbiAgICAgICAgICAgICAgaWYgKGVycjIgfHwgIW9yaWdpbikge1xuICAgICAgICAgICAgICAgIG5leHQoZXJyMik7XG4gICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgY29yc09wdGlvbnMub3JpZ2luID0gb3JpZ2luO1xuICAgICAgICAgICAgICAgIGNvcnMoY29yc09wdGlvbnMsIHJlcSwgcmVzLCBuZXh0KTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIG5leHQoKTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH07XG4gIH1cblxuICAvLyBjYW4gcGFzcyBlaXRoZXIgYW4gb3B0aW9ucyBoYXNoLCBhbiBvcHRpb25zIGRlbGVnYXRlLCBvciBub3RoaW5nXG4gIG1vZHVsZS5leHBvcnRzID0gbWlkZGxld2FyZVdyYXBwZXI7XG5cbn0oKSk7XG4iLCIvKlxub2JqZWN0LWFzc2lnblxuKGMpIFNpbmRyZSBTb3JodXNcbkBsaWNlbnNlIE1JVFxuKi9cblxuJ3VzZSBzdHJpY3QnO1xuLyogZXNsaW50LWRpc2FibGUgbm8tdW51c2VkLXZhcnMgKi9cbnZhciBnZXRPd25Qcm9wZXJ0eVN5bWJvbHMgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlTeW1ib2xzO1xudmFyIGhhc093blByb3BlcnR5ID0gT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eTtcbnZhciBwcm9wSXNFbnVtZXJhYmxlID0gT2JqZWN0LnByb3RvdHlwZS5wcm9wZXJ0eUlzRW51bWVyYWJsZTtcblxuZnVuY3Rpb24gdG9PYmplY3QodmFsKSB7XG5cdGlmICh2YWwgPT09IG51bGwgfHwgdmFsID09PSB1bmRlZmluZWQpIHtcblx0XHR0aHJvdyBuZXcgVHlwZUVycm9yKCdPYmplY3QuYXNzaWduIGNhbm5vdCBiZSBjYWxsZWQgd2l0aCBudWxsIG9yIHVuZGVmaW5lZCcpO1xuXHR9XG5cblx0cmV0dXJuIE9iamVjdCh2YWwpO1xufVxuXG5mdW5jdGlvbiBzaG91bGRVc2VOYXRpdmUoKSB7XG5cdHRyeSB7XG5cdFx0aWYgKCFPYmplY3QuYXNzaWduKSB7XG5cdFx0XHRyZXR1cm4gZmFsc2U7XG5cdFx0fVxuXG5cdFx0Ly8gRGV0ZWN0IGJ1Z2d5IHByb3BlcnR5IGVudW1lcmF0aW9uIG9yZGVyIGluIG9sZGVyIFY4IHZlcnNpb25zLlxuXG5cdFx0Ly8gaHR0cHM6Ly9idWdzLmNocm9taXVtLm9yZy9wL3Y4L2lzc3Vlcy9kZXRhaWw/aWQ9NDExOFxuXHRcdHZhciB0ZXN0MSA9IG5ldyBTdHJpbmcoJ2FiYycpOyAgLy8gZXNsaW50LWRpc2FibGUtbGluZSBuby1uZXctd3JhcHBlcnNcblx0XHR0ZXN0MVs1XSA9ICdkZSc7XG5cdFx0aWYgKE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHRlc3QxKVswXSA9PT0gJzUnKSB7XG5cdFx0XHRyZXR1cm4gZmFsc2U7XG5cdFx0fVxuXG5cdFx0Ly8gaHR0cHM6Ly9idWdzLmNocm9taXVtLm9yZy9wL3Y4L2lzc3Vlcy9kZXRhaWw/aWQ9MzA1NlxuXHRcdHZhciB0ZXN0MiA9IHt9O1xuXHRcdGZvciAodmFyIGkgPSAwOyBpIDwgMTA7IGkrKykge1xuXHRcdFx0dGVzdDJbJ18nICsgU3RyaW5nLmZyb21DaGFyQ29kZShpKV0gPSBpO1xuXHRcdH1cblx0XHR2YXIgb3JkZXIyID0gT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGVzdDIpLm1hcChmdW5jdGlvbiAobikge1xuXHRcdFx0cmV0dXJuIHRlc3QyW25dO1xuXHRcdH0pO1xuXHRcdGlmIChvcmRlcjIuam9pbignJykgIT09ICcwMTIzNDU2Nzg5Jykge1xuXHRcdFx0cmV0dXJuIGZhbHNlO1xuXHRcdH1cblxuXHRcdC8vIGh0dHBzOi8vYnVncy5jaHJvbWl1bS5vcmcvcC92OC9pc3N1ZXMvZGV0YWlsP2lkPTMwNTZcblx0XHR2YXIgdGVzdDMgPSB7fTtcblx0XHQnYWJjZGVmZ2hpamtsbW5vcHFyc3QnLnNwbGl0KCcnKS5mb3JFYWNoKGZ1bmN0aW9uIChsZXR0ZXIpIHtcblx0XHRcdHRlc3QzW2xldHRlcl0gPSBsZXR0ZXI7XG5cdFx0fSk7XG5cdFx0aWYgKE9iamVjdC5rZXlzKE9iamVjdC5hc3NpZ24oe30sIHRlc3QzKSkuam9pbignJykgIT09XG5cdFx0XHRcdCdhYmNkZWZnaGlqa2xtbm9wcXJzdCcpIHtcblx0XHRcdHJldHVybiBmYWxzZTtcblx0XHR9XG5cblx0XHRyZXR1cm4gdHJ1ZTtcblx0fSBjYXRjaCAoZXJyKSB7XG5cdFx0Ly8gV2UgZG9uJ3QgZXhwZWN0IGFueSBvZiB0aGUgYWJvdmUgdG8gdGhyb3csIGJ1dCBiZXR0ZXIgdG8gYmUgc2FmZS5cblx0XHRyZXR1cm4gZmFsc2U7XG5cdH1cbn1cblxubW9kdWxlLmV4cG9ydHMgPSBzaG91bGRVc2VOYXRpdmUoKSA/IE9iamVjdC5hc3NpZ24gOiBmdW5jdGlvbiAodGFyZ2V0LCBzb3VyY2UpIHtcblx0dmFyIGZyb207XG5cdHZhciB0byA9IHRvT2JqZWN0KHRhcmdldCk7XG5cdHZhciBzeW1ib2xzO1xuXG5cdGZvciAodmFyIHMgPSAxOyBzIDwgYXJndW1lbnRzLmxlbmd0aDsgcysrKSB7XG5cdFx0ZnJvbSA9IE9iamVjdChhcmd1bWVudHNbc10pO1xuXG5cdFx0Zm9yICh2YXIga2V5IGluIGZyb20pIHtcblx0XHRcdGlmIChoYXNPd25Qcm9wZXJ0eS5jYWxsKGZyb20sIGtleSkpIHtcblx0XHRcdFx0dG9ba2V5XSA9IGZyb21ba2V5XTtcblx0XHRcdH1cblx0XHR9XG5cblx0XHRpZiAoZ2V0T3duUHJvcGVydHlTeW1ib2xzKSB7XG5cdFx0XHRzeW1ib2xzID0gZ2V0T3duUHJvcGVydHlTeW1ib2xzKGZyb20pO1xuXHRcdFx0Zm9yICh2YXIgaSA9IDA7IGkgPCBzeW1ib2xzLmxlbmd0aDsgaSsrKSB7XG5cdFx0XHRcdGlmIChwcm9wSXNFbnVtZXJhYmxlLmNhbGwoZnJvbSwgc3ltYm9sc1tpXSkpIHtcblx0XHRcdFx0XHR0b1tzeW1ib2xzW2ldXSA9IGZyb21bc3ltYm9sc1tpXV07XG5cdFx0XHRcdH1cblx0XHRcdH1cblx0XHR9XG5cdH1cblxuXHRyZXR1cm4gdG87XG59O1xuIiwiLyohXG4gKiB2YXJ5XG4gKiBDb3B5cmlnaHQoYykgMjAxNC0yMDE3IERvdWdsYXMgQ2hyaXN0b3BoZXIgV2lsc29uXG4gKiBNSVQgTGljZW5zZWRcbiAqL1xuXG4ndXNlIHN0cmljdCdcblxuLyoqXG4gKiBNb2R1bGUgZXhwb3J0cy5cbiAqL1xuXG5tb2R1bGUuZXhwb3J0cyA9IHZhcnlcbm1vZHVsZS5leHBvcnRzLmFwcGVuZCA9IGFwcGVuZFxuXG4vKipcbiAqIFJlZ0V4cCB0byBtYXRjaCBmaWVsZC1uYW1lIGluIFJGQyA3MjMwIHNlYyAzLjJcbiAqXG4gKiBmaWVsZC1uYW1lICAgID0gdG9rZW5cbiAqIHRva2VuICAgICAgICAgPSAxKnRjaGFyXG4gKiB0Y2hhciAgICAgICAgID0gXCIhXCIgLyBcIiNcIiAvIFwiJFwiIC8gXCIlXCIgLyBcIiZcIiAvIFwiJ1wiIC8gXCIqXCJcbiAqICAgICAgICAgICAgICAgLyBcIitcIiAvIFwiLVwiIC8gXCIuXCIgLyBcIl5cIiAvIFwiX1wiIC8gXCJgXCIgLyBcInxcIiAvIFwiflwiXG4gKiAgICAgICAgICAgICAgIC8gRElHSVQgLyBBTFBIQVxuICogICAgICAgICAgICAgICA7IGFueSBWQ0hBUiwgZXhjZXB0IGRlbGltaXRlcnNcbiAqL1xuXG52YXIgRklFTERfTkFNRV9SRUdFWFAgPSAvXlshIyQlJicqK1xcLS5eX2B8fjAtOUEtWmEtel0rJC9cblxuLyoqXG4gKiBBcHBlbmQgYSBmaWVsZCB0byBhIHZhcnkgaGVhZGVyLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSBoZWFkZXJcbiAqIEBwYXJhbSB7U3RyaW5nfEFycmF5fSBmaWVsZFxuICogQHJldHVybiB7U3RyaW5nfVxuICogQHB1YmxpY1xuICovXG5cbmZ1bmN0aW9uIGFwcGVuZCAoaGVhZGVyLCBmaWVsZCkge1xuICBpZiAodHlwZW9mIGhlYWRlciAhPT0gJ3N0cmluZycpIHtcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdoZWFkZXIgYXJndW1lbnQgaXMgcmVxdWlyZWQnKVxuICB9XG5cbiAgaWYgKCFmaWVsZCkge1xuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ2ZpZWxkIGFyZ3VtZW50IGlzIHJlcXVpcmVkJylcbiAgfVxuXG4gIC8vIGdldCBmaWVsZHMgYXJyYXlcbiAgdmFyIGZpZWxkcyA9ICFBcnJheS5pc0FycmF5KGZpZWxkKVxuICAgID8gcGFyc2UoU3RyaW5nKGZpZWxkKSlcbiAgICA6IGZpZWxkXG5cbiAgLy8gYXNzZXJ0IG9uIGludmFsaWQgZmllbGQgbmFtZXNcbiAgZm9yICh2YXIgaiA9IDA7IGogPCBmaWVsZHMubGVuZ3RoOyBqKyspIHtcbiAgICBpZiAoIUZJRUxEX05BTUVfUkVHRVhQLnRlc3QoZmllbGRzW2pdKSkge1xuICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignZmllbGQgYXJndW1lbnQgY29udGFpbnMgYW4gaW52YWxpZCBoZWFkZXIgbmFtZScpXG4gICAgfVxuICB9XG5cbiAgLy8gZXhpc3RpbmcsIHVuc3BlY2lmaWVkIHZhcnlcbiAgaWYgKGhlYWRlciA9PT0gJyonKSB7XG4gICAgcmV0dXJuIGhlYWRlclxuICB9XG5cbiAgLy8gZW51bWVyYXRlIGN1cnJlbnQgdmFsdWVzXG4gIHZhciB2YWwgPSBoZWFkZXJcbiAgdmFyIHZhbHMgPSBwYXJzZShoZWFkZXIudG9Mb3dlckNhc2UoKSlcblxuICAvLyB1bnNwZWNpZmllZCB2YXJ5XG4gIGlmIChmaWVsZHMuaW5kZXhPZignKicpICE9PSAtMSB8fCB2YWxzLmluZGV4T2YoJyonKSAhPT0gLTEpIHtcbiAgICByZXR1cm4gJyonXG4gIH1cblxuICBmb3IgKHZhciBpID0gMDsgaSA8IGZpZWxkcy5sZW5ndGg7IGkrKykge1xuICAgIHZhciBmbGQgPSBmaWVsZHNbaV0udG9Mb3dlckNhc2UoKVxuXG4gICAgLy8gYXBwZW5kIHZhbHVlIChjYXNlLXByZXNlcnZpbmcpXG4gICAgaWYgKHZhbHMuaW5kZXhPZihmbGQpID09PSAtMSkge1xuICAgICAgdmFscy5wdXNoKGZsZClcbiAgICAgIHZhbCA9IHZhbFxuICAgICAgICA/IHZhbCArICcsICcgKyBmaWVsZHNbaV1cbiAgICAgICAgOiBmaWVsZHNbaV1cbiAgICB9XG4gIH1cblxuICByZXR1cm4gdmFsXG59XG5cbi8qKlxuICogUGFyc2UgYSB2YXJ5IGhlYWRlciBpbnRvIGFuIGFycmF5LlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSBoZWFkZXJcbiAqIEByZXR1cm4ge0FycmF5fVxuICogQHByaXZhdGVcbiAqL1xuXG5mdW5jdGlvbiBwYXJzZSAoaGVhZGVyKSB7XG4gIHZhciBlbmQgPSAwXG4gIHZhciBsaXN0ID0gW11cbiAgdmFyIHN0YXJ0ID0gMFxuXG4gIC8vIGdhdGhlciB0b2tlbnNcbiAgZm9yICh2YXIgaSA9IDAsIGxlbiA9IGhlYWRlci5sZW5ndGg7IGkgPCBsZW47IGkrKykge1xuICAgIHN3aXRjaCAoaGVhZGVyLmNoYXJDb2RlQXQoaSkpIHtcbiAgICAgIGNhc2UgMHgyMDogLyogICAqL1xuICAgICAgICBpZiAoc3RhcnQgPT09IGVuZCkge1xuICAgICAgICAgIHN0YXJ0ID0gZW5kID0gaSArIDFcbiAgICAgICAgfVxuICAgICAgICBicmVha1xuICAgICAgY2FzZSAweDJjOiAvKiAsICovXG4gICAgICAgIGxpc3QucHVzaChoZWFkZXIuc3Vic3RyaW5nKHN0YXJ0LCBlbmQpKVxuICAgICAgICBzdGFydCA9IGVuZCA9IGkgKyAxXG4gICAgICAgIGJyZWFrXG4gICAgICBkZWZhdWx0OlxuICAgICAgICBlbmQgPSBpICsgMVxuICAgICAgICBicmVha1xuICAgIH1cbiAgfVxuXG4gIC8vIGZpbmFsIHRva2VuXG4gIGxpc3QucHVzaChoZWFkZXIuc3Vic3RyaW5nKHN0YXJ0LCBlbmQpKVxuXG4gIHJldHVybiBsaXN0XG59XG5cbi8qKlxuICogTWFyayB0aGF0IGEgcmVxdWVzdCBpcyB2YXJpZWQgb24gYSBoZWFkZXIgZmllbGQuXG4gKlxuICogQHBhcmFtIHtPYmplY3R9IHJlc1xuICogQHBhcmFtIHtTdHJpbmd8QXJyYXl9IGZpZWxkXG4gKiBAcHVibGljXG4gKi9cblxuZnVuY3Rpb24gdmFyeSAocmVzLCBmaWVsZCkge1xuICBpZiAoIXJlcyB8fCAhcmVzLmdldEhlYWRlciB8fCAhcmVzLnNldEhlYWRlcikge1xuICAgIC8vIHF1YWNrIHF1YWNrXG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcigncmVzIGFyZ3VtZW50IGlzIHJlcXVpcmVkJylcbiAgfVxuXG4gIC8vIGdldCBleGlzdGluZyBoZWFkZXJcbiAgdmFyIHZhbCA9IHJlcy5nZXRIZWFkZXIoJ1ZhcnknKSB8fCAnJ1xuICB2YXIgaGVhZGVyID0gQXJyYXkuaXNBcnJheSh2YWwpXG4gICAgPyB2YWwuam9pbignLCAnKVxuICAgIDogU3RyaW5nKHZhbClcblxuICAvLyBzZXQgbmV3IGhlYWRlclxuICBpZiAoKHZhbCA9IGFwcGVuZChoZWFkZXIsIGZpZWxkKSkpIHtcbiAgICByZXMuc2V0SGVhZGVyKCdWYXJ5JywgdmFsKVxuICB9XG59XG4iLCJleHBvcnQgY29uc3QgUFJPSkVDVF9JRCA9ICc5ODd6eXgnO1xuZXhwb3J0IGNvbnN0IExPR18xX0lEID0gJ2FiYzEyMyc7XG5leHBvcnQgY29uc3QgTE9HXzJfSUQgPSAnZGVmNDU2JztcbiIsImV4cG9ydCAqIGZyb20gJy4vY29uc3RhbnRzJztcbmV4cG9ydCAqIGZyb20gJy4vdHlwZXMnO1xuIiwiZXhwb3J0IHR5cGUgRGF0ZUxpa2UgPSBEYXRlIHwgc3RyaW5nO1xuXG5leHBvcnQgdHlwZSBMb2dFbnRyeVJlc3BvbnNlID0ge1xuXHRpZDogc3RyaW5nO1xuXHRsb2dJZDogc3RyaW5nO1xuXHRsb2dEYXRlOiBEYXRlTGlrZTtcblx0bG9nVmFsdWU6IG51bWJlcjtcbn07XG5cbmV4cG9ydCB0eXBlIExvZ0VudHJ5UmVxdWVzdCA9IHtcblx0bG9nRGF0ZTogRGF0ZUxpa2U7XG5cdGxvZ1ZhbHVlOiBudW1iZXI7XG59O1xuXG5leHBvcnQgdHlwZSBFZGl0TG9nRW50cnlSZXF1ZXN0ID0gTG9nRW50cnlSZXF1ZXN0ICYge1xuXHRpZDogc3RyaW5nO1xuXHRsb2dJZDogc3RyaW5nO1xufTtcblxuZXhwb3J0IGVudW0gSHR0cFN0YXR1c0NvZGUge1xuXHRPSyA9IDIwMCxcblx0Q1JFQVRFRCA9IDIwMSxcblx0VEVNUE9SQVJZX1JFRElSRUNUID0gMzAyLFxuXHRJTlZBTElEX1JFUVVFU1QgPSA0MDAsXG5cdElOVkFMSURfQ1JFREVOVElBTFMgPSA0MDEsXG5cdFVOQVVUSE9SSVpFRF9SRVFVRVNUID0gNDAzLFxuXHROT1RfRk9VTkQgPSA0MDQsXG5cdENPTkZMSUNUID0gNDA5LFxuXHRNSVNTSU5HX1FVRVJZX1BBUkFNID0gNDIyLFxuXHRNSVNTSU5HX0RBVEEgPSA0MjIsXG5cdElOVkFMSURfREFUQSA9IDQyMixcblx0U0VSVkVSX0VSUk9SID0gNTAwLFxuXHRVTklNUExFTUVOVEVEX0VSUk9SID0gNTAxLFxufVxuIiwiaW1wb3J0IHtcblx0TG9nRW50cnlSZXF1ZXN0LFxuXHRMb2dFbnRyeVJlc3BvbnNlLFxuXHRFZGl0TG9nRW50cnlSZXF1ZXN0LFxufSBmcm9tICdAbWFwaXN0cnkvdGFrZS1ob21lLWNoYWxsZW5nZS1zaGFyZWQnO1xuaW1wb3J0IHsgTG9nRW50cnkgfSBmcm9tICcuLi8uLi9kb21haW4vZW50aXRpZXMvTG9nRW50cnknO1xuXG5leHBvcnQgY2xhc3MgTG9nRW50cmllc0FwaU1hcHBlciB7XG5cdHB1YmxpYyB0b1Jlc3BvbnNlKGxvZ0VudHJ5OiBMb2dFbnRyeSk6IExvZ0VudHJ5UmVzcG9uc2Uge1xuXHRcdHJldHVybiB7XG5cdFx0XHRpZDogbG9nRW50cnkuaWQudG9TdHJpbmcoKSxcblx0XHRcdGxvZ0lkOiBsb2dFbnRyeS5sb2dJZCxcblx0XHRcdGxvZ0RhdGU6IGxvZ0VudHJ5LmxvZ0RhdGUsXG5cdFx0XHRsb2dWYWx1ZTogbG9nRW50cnkubG9nVmFsdWUsXG5cdFx0fTtcblx0fVxuXG5cdHB1YmxpYyBmcm9tQ3JlYXRlUmVxdWVzdChcblx0XHRsb2dJZDogc3RyaW5nLFxuXHRcdGNyZWF0ZUxvZ0VudHJ5OiBMb2dFbnRyeVJlcXVlc3Rcblx0KTogTG9nRW50cnkge1xuXHRcdHJldHVybiBMb2dFbnRyeS5jcmVhdGUoe1xuXHRcdFx0bG9nSWQsXG5cdFx0XHRsb2dEYXRlOiBuZXcgRGF0ZShjcmVhdGVMb2dFbnRyeS5sb2dEYXRlKSxcblx0XHRcdGxvZ1ZhbHVlOiBjcmVhdGVMb2dFbnRyeS5sb2dWYWx1ZSxcblx0XHR9KTtcblx0fVxuXG5cdHB1YmxpYyBmcm9tVXBkYXRlUmVxdWVzdCh1cGRhdGVMb2dFbnRyeTogRWRpdExvZ0VudHJ5UmVxdWVzdCk6IExvZ0VudHJ5IHtcblx0XHRyZXR1cm4gTG9nRW50cnkudXBkYXRlKHtcblx0XHRcdGlkOiB1cGRhdGVMb2dFbnRyeS5pZCxcblx0XHRcdGxvZ0lkOiB1cGRhdGVMb2dFbnRyeS5sb2dJZCxcblx0XHRcdGxvZ0RhdGU6IG5ldyBEYXRlKHVwZGF0ZUxvZ0VudHJ5LmxvZ0RhdGUpLFxuXHRcdFx0bG9nVmFsdWU6IHVwZGF0ZUxvZ0VudHJ5LmxvZ1ZhbHVlLFxuXHRcdH0pO1xuXHR9XG59XG4iLCJpbXBvcnQge1xuXHRMb2dFbnRyeVJlcXVlc3QsXG5cdExvZ0VudHJ5UmVzcG9uc2UsXG5cdEVkaXRMb2dFbnRyeVJlcXVlc3QsXG59IGZyb20gJ0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNoYXJlZCc7XG5pbXBvcnQgeyBMb2dFbnRyaWVzUXVlcnlSZXBvc2l0b3J5IH0gZnJvbSAnLi4vLi4vcGVyc2lzdGVuY2UvcmVwb3NpdG9yaWVzL0xvZ0VudHJpZXNRdWVyeVJlcG9zaXRvcnknO1xuaW1wb3J0IHsgTG9nRW50cmllc1JlcG9zaXRvcnkgfSBmcm9tICcuLi8uLi9wZXJzaXN0ZW5jZS9yZXBvc2l0b3JpZXMvTG9nRW50cmllc1JlcG9zaXRvcnknO1xuaW1wb3J0IHsgTG9nRW50cmllc0FwaU1hcHBlciB9IGZyb20gJy4uL21hcHBlcnMvTG9nRW50cmllc0FwaU1hcHBlcic7XG5cbmV4cG9ydCBjbGFzcyBMb2dFbnRyaWVzU2VydmljZSB7XG5cdGdldExvZ0VudHJpZXMobG9nSWQ6IHN0cmluZyk6IFByb21pc2U8TG9nRW50cnlSZXNwb25zZVtdPiB7XG5cdFx0Y29uc3QgbG9nRW50cnlSZXBvc2l0b3J5ID0gbmV3IExvZ0VudHJpZXNRdWVyeVJlcG9zaXRvcnkoKTtcblx0XHRyZXR1cm4gbG9nRW50cnlSZXBvc2l0b3J5LmZpbmRMb2dFbnRyaWVzKGxvZ0lkKTtcblx0fVxuXG5cdGFzeW5jIGNyZWF0ZUxvZ0VudHJ5KFxuXHRcdGxvZ0lkOiBzdHJpbmcsXG5cdFx0Y3JlYXRlTG9nRW50cnk6IExvZ0VudHJ5UmVxdWVzdFxuXHQpOiBQcm9taXNlPExvZ0VudHJ5UmVzcG9uc2U+IHtcblx0XHRjb25zdCBtYXBwZXIgPSBuZXcgTG9nRW50cmllc0FwaU1hcHBlcigpO1xuXHRcdGNvbnN0IGxvZ0VudHJ5ID0gbWFwcGVyLmZyb21DcmVhdGVSZXF1ZXN0KGxvZ0lkLCBjcmVhdGVMb2dFbnRyeSk7XG5cdFx0Y29uc3QgcmVwb3NpdG9yeSA9IG5ldyBMb2dFbnRyaWVzUmVwb3NpdG9yeShsb2dJZCk7XG5cdFx0Y29uc3QgbmV3RW50cnkgPSBhd2FpdCByZXBvc2l0b3J5LmNyZWF0ZUxvZ0VudHJ5KGxvZ0VudHJ5KTtcblx0XHRyZXR1cm4gbWFwcGVyLnRvUmVzcG9uc2UobmV3RW50cnkpO1xuXHR9XG5cblx0YXN5bmMgZGVsZXRlTG9nRW50cnkobG9nSWQ6IHN0cmluZywgbG9nRW50cnlJZDogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+IHtcblx0XHRjb25zdCBsb2dFbnRyeVJlcG9zaXRvcnkgPSBuZXcgTG9nRW50cmllc1JlcG9zaXRvcnkobG9nSWQpO1xuXHRcdGNvbnN0IGxvZ0VudHJ5ID0gYXdhaXQgbG9nRW50cnlSZXBvc2l0b3J5LmZpbmRCeUlkKGxvZ0VudHJ5SWQpO1xuXHRcdHJldHVybiBsb2dFbnRyeVJlcG9zaXRvcnkuZGVzdHJveUxvZ0VudHJ5KGxvZ0VudHJ5KTtcblx0fVxuXG5cdGFzeW5jIHVwZGF0ZUxvZ0VudHJ5KFxuXHRcdHVwZGF0ZUxvZ0VudHJ5OiBFZGl0TG9nRW50cnlSZXF1ZXN0XG5cdCk6IFByb21pc2U8TG9nRW50cnlSZXNwb25zZT4ge1xuXHRcdGNvbnN0IG1hcHBlciA9IG5ldyBMb2dFbnRyaWVzQXBpTWFwcGVyKCk7XG5cdFx0Y29uc3QgbG9nRW50cnkgPSBtYXBwZXIuZnJvbVVwZGF0ZVJlcXVlc3QodXBkYXRlTG9nRW50cnkpO1xuXHRcdGNvbnN0IHJlcG9zaXRvcnkgPSBuZXcgTG9nRW50cmllc1JlcG9zaXRvcnkodXBkYXRlTG9nRW50cnkubG9nSWQpO1xuXHRcdGNvbnN0IHVwZGF0ZWRFbnRyeSA9IGF3YWl0IHJlcG9zaXRvcnkudXBkYXRlTG9nRW50cnkobG9nRW50cnkpO1xuXHRcdHJldHVybiBtYXBwZXIudG9SZXNwb25zZSh1cGRhdGVkRW50cnkpO1xuXHR9XG59XG4iLCJpbXBvcnQgeyBVdWlkIH0gZnJvbSAnLi9VdWlkJztcblxuZXhwb3J0IGNsYXNzIEVudGl0eTxUPiB7XG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuby11bmRlcnNjb3JlLWRhbmdsZVxuICBwcm90ZWN0ZWQgcmVhZG9ubHkgX2lkOiBVdWlkO1xuXG4gIHByb3RlY3RlZCBjb25zdHJ1Y3Rvcihwcm90ZWN0ZWQgcHJvcHM6IFQsIGlkPzogVXVpZCkge1xuICAgIHRoaXMuX2lkID0gaWQgfHwgVXVpZC5jcmVhdGUoKTtcbiAgfVxuXG4gIGdldCBpZCgpOiBVdWlkIHtcbiAgICByZXR1cm4gdGhpcy5faWQ7XG4gIH1cbn1cbiIsImltcG9ydCB7IFZhbGlkYXRpb25FcnJvciB9IGZyb20gJy4uLy4uL3NoYXJlZC9lcnJvcnMnO1xuaW1wb3J0IHsgRW50aXR5IH0gZnJvbSAnLi9FbnRpdHknO1xuaW1wb3J0IHsgVXVpZCB9IGZyb20gJy4vVXVpZCc7XG5cbmludGVyZmFjZSBMb2dFbnRyeVByb3BzIHtcblx0bG9nRGF0ZTogRGF0ZTtcblx0bG9nVmFsdWU6IG51bWJlcjtcblx0bG9nSWQ6IHN0cmluZztcbn1cblxudHlwZSBDcmVhdGVMb2dFbnRyeVByb3BzID0gTG9nRW50cnlQcm9wcztcbnR5cGUgVXBkYXRlTG9nRW50cnlQcm9wcyA9IExvZ0VudHJ5UHJvcHMgJiB7IGlkOiBzdHJpbmcgfTtcblxuZXhwb3J0IGNsYXNzIExvZ0VudHJ5IGV4dGVuZHMgRW50aXR5PExvZ0VudHJ5UHJvcHM+IHtcblx0c3RhdGljIGNyZWF0ZUZyb21QZXJzaXN0ZW5jZShwcm9wczogTG9nRW50cnlQcm9wcywgaWQ6IHN0cmluZykge1xuXHRcdHJldHVybiBuZXcgTG9nRW50cnkocHJvcHMsIFV1aWQuY3JlYXRlKGlkKSk7XG5cdH1cblxuXHRzdGF0aWMgY3JlYXRlKGNyZWF0ZUxvZ0VudHJ5UHJvcHM6IENyZWF0ZUxvZ0VudHJ5UHJvcHMpIHtcblx0XHRpZiAoIXRoaXMuaXNWYWxpZChjcmVhdGVMb2dFbnRyeVByb3BzKSkge1xuXHRcdFx0dGhyb3cgbmV3IFZhbGlkYXRpb25FcnJvcihcblx0XHRcdFx0J0Nhbm5vdCBjcmVhdGUgbG9nIGVudHJ5LiBQcm9wcyBhcmUgbm90IHZhbGlkLidcblx0XHRcdCk7XG5cdFx0fVxuXHRcdHJldHVybiBuZXcgTG9nRW50cnkoY3JlYXRlTG9nRW50cnlQcm9wcyk7XG5cdH1cblxuXHRzdGF0aWMgdXBkYXRlKHVwZGF0ZUxvZ0VudHJ5UHJvcHM6IFVwZGF0ZUxvZ0VudHJ5UHJvcHMpIHtcblx0XHRpZiAoIXRoaXMuaXNWYWxpZCh1cGRhdGVMb2dFbnRyeVByb3BzKSkge1xuXHRcdFx0dGhyb3cgbmV3IFZhbGlkYXRpb25FcnJvcihcblx0XHRcdFx0J0Nhbm5vdCB1cGRhdGUgbG9nIGVudHJ5LiBQcm9wcyBhcmUgbm90IHZhbGlkLidcblx0XHRcdCk7XG5cdFx0fVxuXHRcdHJldHVybiBuZXcgTG9nRW50cnkodXBkYXRlTG9nRW50cnlQcm9wcyk7XG5cdH1cblxuXHRwcml2YXRlIHN0YXRpYyBpc1ZhbGlkKGNyZWF0ZUxvZ0VudHJ5UHJvcHM6IENyZWF0ZUxvZ0VudHJ5UHJvcHMpOiBib29sZWFuIHtcblx0XHRyZXR1cm4gdHlwZW9mIGNyZWF0ZUxvZ0VudHJ5UHJvcHMubG9nVmFsdWUgPT09ICdudW1iZXInO1xuXHR9XG5cblx0Z2V0IGxvZ0RhdGUoKSB7XG5cdFx0cmV0dXJuIHRoaXMucHJvcHMubG9nRGF0ZTtcblx0fVxuXG5cdGdldCBsb2dWYWx1ZSgpIHtcblx0XHRyZXR1cm4gdGhpcy5wcm9wcy5sb2dWYWx1ZTtcblx0fVxuXG5cdGdldCBsb2dJZCgpIHtcblx0XHRyZXR1cm4gdGhpcy5wcm9wcy5sb2dJZDtcblx0fVxufVxuIiwiaW1wb3J0IGNyeXB0byBmcm9tICdjcnlwdG8nO1xuXG5leHBvcnQgY2xhc3MgVXVpZCB7XG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuby11bmRlcnNjb3JlLWRhbmdsZVxuICBwcml2YXRlIHJlYWRvbmx5IF9pZDogc3RyaW5nO1xuXG4gIHByb3RlY3RlZCBjb25zdHJ1Y3RvcihpZDogc3RyaW5nKSB7XG4gICAgdGhpcy5faWQgPSBpZDtcbiAgfVxuXG4gIHB1YmxpYyBnZXQgdmFsdWUoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gdGhpcy5faWQ7XG4gIH1cblxuICBwdWJsaWMgdG9TdHJpbmcoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gdGhpcy52YWx1ZTtcbiAgfVxuXG4gIHB1YmxpYyBlcXVhbHMoaWQ/OiBVdWlkIHwgc3RyaW5nKTogYm9vbGVhbiB7XG4gICAgaWYgKGlkIGluc3RhbmNlb2YgVXVpZCkge1xuICAgICAgcmV0dXJuIGlkLnZhbHVlID09PSB0aGlzLnZhbHVlO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIGlkID09PSAnc3RyaW5nJykge1xuICAgICAgcmV0dXJuIGlkID09PSB0aGlzLl9pZDtcbiAgICB9XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgcHVibGljIHN0YXRpYyBjcmVhdGUoZ2l2ZW5JZD86IHN0cmluZyB8IG51bGwpOiBVdWlkIHtcbiAgICBpZiAoIWdpdmVuSWQpIHJldHVybiBuZXcgVXVpZChjcnlwdG8ucmFuZG9tVVVJRCgpKTtcbiAgICAvLyB3ZSBkb24ndCB2YWxpZGF0ZSB0aGF0IGl0J3MgYSBwcm9wZXIgdXVpZCBzbyB3ZSBjYW4gc3VwcG9ydCBjb21wb3NpdGUgSURzXG4gICAgcmV0dXJuIG5ldyBVdWlkKGdpdmVuSWQpO1xuICB9XG5cbiAgcHVibGljIHN0YXRpYyBpc1ZhbGlkKGdpdmVuSWQ6IHN0cmluZyk6IGJvb2xlYW4ge1xuICAgIHJldHVybiAvXlswLTlhLWZdezh9LVswLTlhLWZdezR9LVsxLTVdWzAtOWEtZl17M30tWzg5YWJdWzAtOWEtZl17M30tWzAtOWEtZl17MTJ9JC9pLnRlc3QoXG4gICAgICBnaXZlbklkLFxuICAgICk7XG4gIH1cbn1cbiIsImltcG9ydCB7IExvZ0VudHJ5IH0gZnJvbSAnLi4vLi4vZG9tYWluL2VudGl0aWVzL0xvZ0VudHJ5JztcbmltcG9ydCB7IExvZ0VudHJpZXNSZWNvcmQgfSBmcm9tICcuLi8uLi9zaGFyZWQvZGF0YWJhc2UnO1xuXG5leHBvcnQgY2xhc3MgTG9nRW50cmllc1BlcnNpc3RlbmNlTWFwcGVyIHtcbiAgc3RhdGljIHRvUGVyc2lzdGVuY2UobG9nRW50cnk6IExvZ0VudHJ5KTogTG9nRW50cmllc1JlY29yZCB7XG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiBsb2dFbnRyeS5pZC50b1N0cmluZygpLFxuICAgICAgbG9nSWQ6IGxvZ0VudHJ5LmxvZ0lkLFxuICAgICAgbG9nRGF0ZTogbG9nRW50cnkubG9nRGF0ZSxcbiAgICAgIGxvZ1ZhbHVlOiBsb2dFbnRyeS5sb2dWYWx1ZSxcbiAgICB9O1xuICB9XG5cbiAgc3RhdGljIGZyb21QZXJzaXN0ZW5jZShsb2dFbnRyaWVzUmVjb3JkOiBMb2dFbnRyaWVzUmVjb3JkKTogTG9nRW50cnkge1xuICAgIHJldHVybiBMb2dFbnRyeS5jcmVhdGVGcm9tUGVyc2lzdGVuY2UoXG4gICAgICBsb2dFbnRyaWVzUmVjb3JkLFxuICAgICAgbG9nRW50cmllc1JlY29yZC5pZCxcbiAgICApO1xuICB9XG59XG4iLCJpbXBvcnQgeyBEYXRhYmFzZSwgTG9nRW50cmllc1JlY29yZCB9IGZyb20gJy4uLy4uL3NoYXJlZC9kYXRhYmFzZSc7XG5cbmV4cG9ydCBjbGFzcyBMb2dFbnRyaWVzUXVlcnlSZXBvc2l0b3J5IHtcbiAgYXN5bmMgZmluZExvZ0VudHJpZXMobG9nSWQ6IHN0cmluZyk6IFByb21pc2U8TG9nRW50cmllc1JlY29yZFtdPiB7XG4gICAgcmV0dXJuIERhdGFiYXNlLmdldEFsbExvZ0VudHJpZXMobG9nSWQpO1xuICB9XG59XG4iLCJpbXBvcnQgeyBMb2dFbnRyeSB9IGZyb20gJy4uLy4uL2RvbWFpbi9lbnRpdGllcy9Mb2dFbnRyeSc7XG5pbXBvcnQgeyBEYXRhYmFzZSB9IGZyb20gJy4uLy4uL3NoYXJlZC9kYXRhYmFzZSc7XG5pbXBvcnQgeyBSZWNvcmROb3RGb3VuZEVycm9yIH0gZnJvbSAnLi4vLi4vc2hhcmVkL2Vycm9ycyc7XG5pbXBvcnQgeyBMb2dFbnRyaWVzUGVyc2lzdGVuY2VNYXBwZXIgfSBmcm9tICcuLi9tYXBwZXJzL0xvZ0VudHJpZXNQZXJzaXN0ZW5jZU1hcHBlcic7XG5cbmV4cG9ydCBjbGFzcyBMb2dFbnRyaWVzUmVwb3NpdG9yeSB7XG5cdGNvbnN0cnVjdG9yKHByb3RlY3RlZCBsb2dJZDogc3RyaW5nKSB7fVxuXG5cdGFzeW5jIGNyZWF0ZUxvZ0VudHJ5KGxvZ0VudHJ5OiBMb2dFbnRyeSk6IFByb21pc2U8TG9nRW50cnk+IHtcblx0XHRjb25zdCBkdG8gPSBMb2dFbnRyaWVzUGVyc2lzdGVuY2VNYXBwZXIudG9QZXJzaXN0ZW5jZShsb2dFbnRyeSk7XG5cdFx0YXdhaXQgRGF0YWJhc2UuY3JlYXRlTG9nRW50cnkoZHRvKTtcblx0XHRyZXR1cm4gbG9nRW50cnk7XG5cdH1cblxuXHRhc3luYyBmaW5kQnlJZChsb2dFbnRyeUlkOiBzdHJpbmcpOiBQcm9taXNlPExvZ0VudHJ5PiB7XG5cdFx0Y29uc3QgcmVjb3JkID0gYXdhaXQgRGF0YWJhc2UuZmluZEJ5SWQobG9nRW50cnlJZCk7XG5cdFx0aWYgKCFyZWNvcmQpIHtcblx0XHRcdHRocm93IG5ldyBSZWNvcmROb3RGb3VuZEVycm9yKFxuXHRcdFx0XHRgbG9nIGVudHJ5IG5vdCBmb3VuZCBmb3IgaWQ6ICR7bG9nRW50cnlJZH1gXG5cdFx0XHQpO1xuXHRcdH1cblx0XHRyZXR1cm4gTG9nRW50cmllc1BlcnNpc3RlbmNlTWFwcGVyLmZyb21QZXJzaXN0ZW5jZShyZWNvcmQpO1xuXHR9XG5cblx0YXN5bmMgZGVzdHJveUxvZ0VudHJ5KGxvZ0VudHJ5OiBMb2dFbnRyeSk6IFByb21pc2U8c3RyaW5nPiB7XG5cdFx0YXdhaXQgRGF0YWJhc2UuZGVsZXRlTG9nRW50cnkobG9nRW50cnkuaWQudmFsdWUpO1xuXHRcdHJldHVybiBsb2dFbnRyeS5pZC52YWx1ZTtcblx0fVxuXG5cdGFzeW5jIHVwZGF0ZUxvZ0VudHJ5KGxvZ0VudHJ5OiBMb2dFbnRyeSk6IFByb21pc2U8TG9nRW50cnk+IHtcblx0XHRjb25zdCBkdG8gPSBMb2dFbnRyaWVzUGVyc2lzdGVuY2VNYXBwZXIudG9QZXJzaXN0ZW5jZShsb2dFbnRyeSk7XG5cdFx0Y29uc3QgdXBkYXRlZEVudHJ5ID0gYXdhaXQgRGF0YWJhc2UudXBkYXRlTG9nRW50cnkoZHRvKTtcblx0XHRyZXR1cm4gTG9nRW50cmllc1BlcnNpc3RlbmNlTWFwcGVyLmZyb21QZXJzaXN0ZW5jZSh1cGRhdGVkRW50cnkpO1xuXHR9XG59XG4iLCJpbXBvcnQgeyBIdHRwU3RhdHVzQ29kZSB9IGZyb20gJ0BtYXBpc3RyeS90YWtlLWhvbWUtY2hhbGxlbmdlLXNoYXJlZCc7XG5pbXBvcnQgeyBSb3V0ZXIgfSBmcm9tICdleHByZXNzJztcbmltcG9ydCB7IExvZ0VudHJpZXNTZXJ2aWNlIH0gZnJvbSAnLi4vLi4vYXBwbGljYXRpb24vc2VydmljZXMvTG9nRW50cmllc1NlcnZpY2UnO1xuaW1wb3J0IHsgUmVjb3JkTm90Rm91bmRFcnJvciwgVmFsaWRhdGlvbkVycm9yIH0gZnJvbSAnLi4vLi4vc2hhcmVkL2Vycm9ycyc7XG5cbmV4cG9ydCBjb25zdCBsb2dFbnRyaWVzQ29udHJvbGxlciA9IFJvdXRlcigpO1xuXG5sb2dFbnRyaWVzQ29udHJvbGxlci5nZXQoJy9sb2dzLzpsb2dJZC9sb2ctZW50cmllcycsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuXHRjb25zdCB7IGxvZ0lkIH0gPSByZXEucGFyYW1zO1xuXHRjb25zdCBsb2dFbnRyeVNlcnZpY2UgPSBuZXcgTG9nRW50cmllc1NlcnZpY2UoKTtcblx0Y29uc3QgbG9nRW50cmllcyA9IGF3YWl0IGxvZ0VudHJ5U2VydmljZS5nZXRMb2dFbnRyaWVzKGxvZ0lkKTtcblx0cmVzLmpzb24obG9nRW50cmllcyk7XG59KTtcblxubG9nRW50cmllc0NvbnRyb2xsZXIucG9zdCgnL2xvZ3MvOmxvZ0lkL2xvZy1lbnRyaWVzJywgYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG5cdGNvbnN0IHsgbG9nSWQgfSA9IHJlcS5wYXJhbXM7XG5cdGNvbnN0IHsgbG9nRW50cnkgfSA9IHJlcS5ib2R5O1xuXHRjb25zdCBsb2dFbnRyeVNlcnZpY2UgPSBuZXcgTG9nRW50cmllc1NlcnZpY2UoKTtcblx0dHJ5IHtcblx0XHRjb25zdCBsb2dFbnRyaWVzID0gYXdhaXQgbG9nRW50cnlTZXJ2aWNlLmNyZWF0ZUxvZ0VudHJ5KFxuXHRcdFx0bG9nSWQsXG5cdFx0XHRsb2dFbnRyeVxuXHRcdCk7XG5cdFx0cmVzLmpzb24obG9nRW50cmllcyk7XG5cdH0gY2F0Y2ggKGU6IHVua25vd24pIHtcblx0XHRpZiAoZSBpbnN0YW5jZW9mIFZhbGlkYXRpb25FcnJvcikge1xuXHRcdFx0cmVzLnN0YXR1cyhIdHRwU3RhdHVzQ29kZS5JTlZBTElEX0RBVEEpO1xuXHRcdFx0cmVzLnNlbmQoZS50b1N0cmluZygpKTtcblx0XHR9IGVsc2Uge1xuXHRcdFx0cmVzLnN0YXR1cyhIdHRwU3RhdHVzQ29kZS5TRVJWRVJfRVJST1IpO1xuXHRcdFx0cmVzLnNlbmQoKTtcblx0XHR9XG5cdH1cbn0pO1xuXG5sb2dFbnRyaWVzQ29udHJvbGxlci5kZWxldGUoXG5cdCcvbG9ncy86bG9nSWQvbG9nLWVudHJpZXMvOmxvZ0VudHJ5SWQnLFxuXHRhc3luYyAocmVxLCByZXMpID0+IHtcblx0XHRjb25zdCB7IGxvZ0lkLCBsb2dFbnRyeUlkIH0gPSByZXEucGFyYW1zO1xuXHRcdGNvbnN0IGxvZ0VudHJ5U2VydmljZSA9IG5ldyBMb2dFbnRyaWVzU2VydmljZSgpO1xuXHRcdHRyeSB7XG5cdFx0XHRjb25zdCBsb2dFbnRyaWVzID0gYXdhaXQgbG9nRW50cnlTZXJ2aWNlLmRlbGV0ZUxvZ0VudHJ5KFxuXHRcdFx0XHRsb2dJZCxcblx0XHRcdFx0bG9nRW50cnlJZFxuXHRcdFx0KTtcblx0XHRcdHJlcy5qc29uKGxvZ0VudHJpZXMpO1xuXHRcdH0gY2F0Y2ggKGU6IHVua25vd24pIHtcblx0XHRcdGlmIChlIGluc3RhbmNlb2YgUmVjb3JkTm90Rm91bmRFcnJvcikge1xuXHRcdFx0XHRyZXMuc3RhdHVzKEh0dHBTdGF0dXNDb2RlLklOVkFMSURfREFUQSk7XG5cdFx0XHRcdHJlcy5zZW5kKGUudG9TdHJpbmcoKSk7XG5cdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHRyZXMuc3RhdHVzKEh0dHBTdGF0dXNDb2RlLlNFUlZFUl9FUlJPUik7XG5cdFx0XHRcdHJlcy5zZW5kKCk7XG5cdFx0XHR9XG5cdFx0XHRyZXMuanNvbigpO1xuXHRcdH1cblx0fVxuKTtcblxubG9nRW50cmllc0NvbnRyb2xsZXIucHV0KCcvbG9ncy9sb2ctZW50cmllcycsIGFzeW5jIChyZXEsIHJlcykgPT4ge1xuXHRjb25zdCB7IGxvZ0VudHJ5IH0gPSByZXEuYm9keTtcblx0Y29uc3QgbG9nRW50cnlTZXJ2aWNlID0gbmV3IExvZ0VudHJpZXNTZXJ2aWNlKCk7XG5cdHRyeSB7XG5cdFx0Y29uc3QgbG9nRW50cmllcyA9IGF3YWl0IGxvZ0VudHJ5U2VydmljZS51cGRhdGVMb2dFbnRyeShsb2dFbnRyeSk7XG5cdFx0cmVzLmpzb24obG9nRW50cmllcyk7XG5cdH0gY2F0Y2ggKGU6IHVua25vd24pIHtcblx0XHRpZiAoZSBpbnN0YW5jZW9mIFZhbGlkYXRpb25FcnJvcikge1xuXHRcdFx0cmVzLnN0YXR1cyhIdHRwU3RhdHVzQ29kZS5JTlZBTElEX0RBVEEpO1xuXHRcdFx0cmVzLnNlbmQoZS50b1N0cmluZygpKTtcblx0XHR9IGVsc2Uge1xuXHRcdFx0cmVzLnN0YXR1cyhIdHRwU3RhdHVzQ29kZS5TRVJWRVJfRVJST1IpO1xuXHRcdFx0cmVzLnNlbmQoKTtcblx0XHR9XG5cdH1cbn0pO1xuIiwiaW1wb3J0IHsgTE9HXzFfSUQsIExPR18yX0lEIH0gZnJvbSAnQG1hcGlzdHJ5L3Rha2UtaG9tZS1jaGFsbGVuZ2Utc2hhcmVkJztcbmltcG9ydCBjcnlwdG8gZnJvbSAnY3J5cHRvJztcbmltcG9ydCBmcyBmcm9tICdmcyc7XG5cbmV4cG9ydCB0eXBlIExvZ0VudHJpZXNSZWNvcmQgPSB7XG5cdGlkOiBzdHJpbmc7XG5cdGxvZ0lkOiBzdHJpbmc7XG5cdGxvZ0RhdGU6IERhdGU7XG5cdGxvZ1ZhbHVlOiBudW1iZXI7XG59O1xuXG5jb25zdCBMT0dfRU5UUklFU19UQUJMRV9TRUVEOiBMb2dFbnRyaWVzUmVjb3JkW10gPSBbXG5cdHtcblx0XHRpZDogY3J5cHRvLnJhbmRvbVVVSUQoKS50b1N0cmluZygpLFxuXHRcdGxvZ0lkOiBMT0dfMV9JRCxcblx0XHRsb2dEYXRlOiBuZXcgRGF0ZSgnMjAyNC0wMS0wMScpLFxuXHRcdGxvZ1ZhbHVlOiA1LFxuXHR9LFxuXHR7XG5cdFx0aWQ6IGNyeXB0by5yYW5kb21VVUlEKCkudG9TdHJpbmcoKSxcblx0XHRsb2dJZDogTE9HXzFfSUQsXG5cdFx0bG9nRGF0ZTogbmV3IERhdGUoJzIwMjQtMDEtMDInKSxcblx0XHRsb2dWYWx1ZTogMTUsXG5cdH0sXG5cdHtcblx0XHRpZDogY3J5cHRvLnJhbmRvbVVVSUQoKS50b1N0cmluZygpLFxuXHRcdGxvZ0lkOiBMT0dfMV9JRCxcblx0XHRsb2dEYXRlOiBuZXcgRGF0ZSgnMjAyNC0wMS0wMycpLFxuXHRcdGxvZ1ZhbHVlOiAyMyxcblx0fSxcblx0e1xuXHRcdGlkOiBjcnlwdG8ucmFuZG9tVVVJRCgpLnRvU3RyaW5nKCksXG5cdFx0bG9nSWQ6IExPR18yX0lELFxuXHRcdGxvZ0RhdGU6IG5ldyBEYXRlKCcyMDI0LTAxLTAxJyksXG5cdFx0bG9nVmFsdWU6IDE1LFxuXHR9LFxuXTtcblxuY29uc3QgRklMRV9OQU1FID0gJ2RhdGFiYXNlJztcblxuZXhwb3J0IGNsYXNzIERhdGFiYXNlIHtcblx0cHVibGljIHN0YXRpYyBhc3luYyBnZXRBbGxMb2dFbnRyaWVzKGxvZ0lkOiBzdHJpbmcpIHtcblx0XHRsZXQgYWxsRW50cmllcztcblx0XHR0cnkge1xuXHRcdFx0YXdhaXQgdGhpcy5zaW11bGF0ZURiU2xvd25lc3MoKTtcblx0XHRcdGNvbnN0IGRiID0gYXdhaXQgZnMucmVhZEZpbGVTeW5jKEZJTEVfTkFNRSwgJ3V0ZjgnKTtcblx0XHRcdGFsbEVudHJpZXMgPSBKU09OLnBhcnNlKGRiKSBhcyBMb2dFbnRyaWVzUmVjb3JkW107XG5cdFx0fSBjYXRjaCAoZSkge1xuXHRcdFx0YXdhaXQgZnMud3JpdGVGaWxlU3luYyhcblx0XHRcdFx0RklMRV9OQU1FLFxuXHRcdFx0XHRKU09OLnN0cmluZ2lmeShMT0dfRU5UUklFU19UQUJMRV9TRUVEKVxuXHRcdFx0KTtcblx0XHRcdGFsbEVudHJpZXMgPSBMT0dfRU5UUklFU19UQUJMRV9TRUVEO1xuXHRcdH1cblx0XHRyZXR1cm4gYWxsRW50cmllcy5maWx0ZXIoKGxlKSA9PiBsZS5sb2dJZCA9PT0gbG9nSWQpO1xuXHR9XG5cblx0cHVibGljIHN0YXRpYyBhc3luYyBjcmVhdGVMb2dFbnRyeShlbnRyeTogTG9nRW50cmllc1JlY29yZCkge1xuXHRcdGF3YWl0IHRoaXMuc2ltdWxhdGVEYlNsb3duZXNzKCk7XG5cdFx0Y29uc3QgZGIgPSBhd2FpdCBmcy5yZWFkRmlsZVN5bmMoRklMRV9OQU1FLCAndXRmOCcpO1xuXHRcdGNvbnN0IGFsbEVudHJpZXMgPSBKU09OLnBhcnNlKGRiKTtcblx0XHRhbGxFbnRyaWVzLnB1c2goZW50cnkpO1xuXHRcdGF3YWl0IGZzLndyaXRlRmlsZVN5bmMoRklMRV9OQU1FLCBKU09OLnN0cmluZ2lmeShhbGxFbnRyaWVzKSk7XG5cdFx0cmV0dXJuIGVudHJ5O1xuXHR9XG5cblx0cHVibGljIHN0YXRpYyBhc3luYyBmaW5kQnlJZChcblx0XHRsb2dFbnRyeUlkOiBzdHJpbmdcblx0KTogUHJvbWlzZTxMb2dFbnRyaWVzUmVjb3JkIHwgbnVsbD4ge1xuXHRcdGF3YWl0IHRoaXMuc2ltdWxhdGVEYlNsb3duZXNzKCk7XG5cdFx0Y29uc3QgZGIgPSBhd2FpdCBmcy5yZWFkRmlsZVN5bmMoRklMRV9OQU1FLCAndXRmOCcpO1xuXHRcdGNvbnN0IGFsbEVudHJpZXMgPSBKU09OLnBhcnNlKGRiKSBhcyBMb2dFbnRyaWVzUmVjb3JkW107XG5cdFx0cmV0dXJuIGFsbEVudHJpZXMuZmluZCgobGUpID0+IGxlLmlkID09PSBsb2dFbnRyeUlkKSB8fCBudWxsO1xuXHR9XG5cblx0cHVibGljIHN0YXRpYyBhc3luYyBkZWxldGVMb2dFbnRyeShsb2dFbnRyeUlkOiBzdHJpbmcpIHtcblx0XHRhd2FpdCB0aGlzLnNpbXVsYXRlRGJTbG93bmVzcygpO1xuXHRcdGNvbnN0IGRiID0gYXdhaXQgZnMucmVhZEZpbGVTeW5jKEZJTEVfTkFNRSwgJ3V0ZjgnKTtcblx0XHRjb25zdCBhbGxFbnRyaWVzID0gSlNPTi5wYXJzZShkYikgYXMgTG9nRW50cmllc1JlY29yZFtdO1xuXHRcdGNvbnN0IGluZGV4ID0gYWxsRW50cmllcy5maW5kSW5kZXgoKGxlKSA9PiBsZS5pZCA9PT0gbG9nRW50cnlJZCk7XG5cdFx0YWxsRW50cmllcy5zcGxpY2UoaW5kZXgsIDEpO1xuXHRcdGF3YWl0IGZzLndyaXRlRmlsZVN5bmMoRklMRV9OQU1FLCBKU09OLnN0cmluZ2lmeShhbGxFbnRyaWVzKSk7XG5cdFx0cmV0dXJuIGxvZ0VudHJ5SWQ7XG5cdH1cblxuXHRwdWJsaWMgc3RhdGljIGFzeW5jIHVwZGF0ZUxvZ0VudHJ5KGVudHJ5OiBMb2dFbnRyaWVzUmVjb3JkKSB7XG5cdFx0YXdhaXQgdGhpcy5zaW11bGF0ZURiU2xvd25lc3MoKTtcblx0XHRjb25zdCBkYiA9IGF3YWl0IGZzLnJlYWRGaWxlU3luYyhGSUxFX05BTUUsICd1dGY4Jyk7XG5cdFx0Y29uc3QgYWxsRW50cmllcyA9IEpTT04ucGFyc2UoZGIpIGFzIExvZ0VudHJpZXNSZWNvcmRbXTtcblx0XHRjb25zdCBpbmRleCA9IGFsbEVudHJpZXMuZmluZEluZGV4KChsZSkgPT4gbGUuaWQgPT09IGVudHJ5LmlkKTtcblx0XHRpZiAoaW5kZXggIT09IC0xKSB7XG5cdFx0XHRhbGxFbnRyaWVzW2luZGV4XSA9IGVudHJ5O1xuXHRcdFx0YXdhaXQgZnMud3JpdGVGaWxlU3luYyhGSUxFX05BTUUsIEpTT04uc3RyaW5naWZ5KGFsbEVudHJpZXMpKTtcblx0XHRcdHJldHVybiBlbnRyeTtcblx0XHR9XG5cdFx0dGhyb3cgbmV3IEVycm9yKGBMb2cgZW50cnkgd2l0aCBpZCAke2VudHJ5LmlkfSBub3QgZm91bmRgKTtcblx0fVxuXG5cdHByaXZhdGUgc3RhdGljIHNpbXVsYXRlRGJTbG93bmVzcyhtcyA9IDEwMDApIHtcblx0XHRyZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUpID0+IHtcblx0XHRcdHNldFRpbWVvdXQocmVzb2x2ZSwgbXMpO1xuXHRcdH0pO1xuXHR9XG59XG4iLCIvKiBlc2xpbnQtZGlzYWJsZSBtYXgtY2xhc3Nlcy1wZXItZmlsZSAqL1xuXG5leHBvcnQgY2xhc3MgUmVjb3JkTm90Rm91bmRFcnJvciBleHRlbmRzIEVycm9yIHt9XG5cbmV4cG9ydCBjbGFzcyBWYWxpZGF0aW9uRXJyb3IgZXh0ZW5kcyBFcnJvciB7fVxuIiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiY3J5cHRvXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcImV4cHJlc3NcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiZnNcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiaHR0cFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJtb3JnYW5cIik7IiwiLy8gVGhlIG1vZHVsZSBjYWNoZVxudmFyIF9fd2VicGFja19tb2R1bGVfY2FjaGVfXyA9IHt9O1xuXG4vLyBUaGUgcmVxdWlyZSBmdW5jdGlvblxuZnVuY3Rpb24gX193ZWJwYWNrX3JlcXVpcmVfXyhtb2R1bGVJZCkge1xuXHQvLyBDaGVjayBpZiBtb2R1bGUgaXMgaW4gY2FjaGVcblx0dmFyIGNhY2hlZE1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF07XG5cdGlmIChjYWNoZWRNb2R1bGUgIT09IHVuZGVmaW5lZCkge1xuXHRcdHJldHVybiBjYWNoZWRNb2R1bGUuZXhwb3J0cztcblx0fVxuXHQvLyBDcmVhdGUgYSBuZXcgbW9kdWxlIChhbmQgcHV0IGl0IGludG8gdGhlIGNhY2hlKVxuXHR2YXIgbW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXSA9IHtcblx0XHQvLyBubyBtb2R1bGUuaWQgbmVlZGVkXG5cdFx0Ly8gbm8gbW9kdWxlLmxvYWRlZCBuZWVkZWRcblx0XHRleHBvcnRzOiB7fVxuXHR9O1xuXG5cdC8vIEV4ZWN1dGUgdGhlIG1vZHVsZSBmdW5jdGlvblxuXHRfX3dlYnBhY2tfbW9kdWxlc19fW21vZHVsZUlkXShtb2R1bGUsIG1vZHVsZS5leHBvcnRzLCBfX3dlYnBhY2tfcmVxdWlyZV9fKTtcblxuXHQvLyBSZXR1cm4gdGhlIGV4cG9ydHMgb2YgdGhlIG1vZHVsZVxuXHRyZXR1cm4gbW9kdWxlLmV4cG9ydHM7XG59XG5cbiIsIi8vIGdldERlZmF1bHRFeHBvcnQgZnVuY3Rpb24gZm9yIGNvbXBhdGliaWxpdHkgd2l0aCBub24taGFybW9ueSBtb2R1bGVzXG5fX3dlYnBhY2tfcmVxdWlyZV9fLm4gPSAobW9kdWxlKSA9PiB7XG5cdHZhciBnZXR0ZXIgPSBtb2R1bGUgJiYgbW9kdWxlLl9fZXNNb2R1bGUgP1xuXHRcdCgpID0+IChtb2R1bGVbJ2RlZmF1bHQnXSkgOlxuXHRcdCgpID0+IChtb2R1bGUpO1xuXHRfX3dlYnBhY2tfcmVxdWlyZV9fLmQoZ2V0dGVyLCB7IGE6IGdldHRlciB9KTtcblx0cmV0dXJuIGdldHRlcjtcbn07IiwiLy8gZGVmaW5lIGdldHRlciBmdW5jdGlvbnMgZm9yIGhhcm1vbnkgZXhwb3J0c1xuX193ZWJwYWNrX3JlcXVpcmVfXy5kID0gKGV4cG9ydHMsIGRlZmluaXRpb24pID0+IHtcblx0Zm9yKHZhciBrZXkgaW4gZGVmaW5pdGlvbikge1xuXHRcdGlmKF9fd2VicGFja19yZXF1aXJlX18ubyhkZWZpbml0aW9uLCBrZXkpICYmICFfX3dlYnBhY2tfcmVxdWlyZV9fLm8oZXhwb3J0cywga2V5KSkge1xuXHRcdFx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIGtleSwgeyBlbnVtZXJhYmxlOiB0cnVlLCBnZXQ6IGRlZmluaXRpb25ba2V5XSB9KTtcblx0XHR9XG5cdH1cbn07IiwiX193ZWJwYWNrX3JlcXVpcmVfXy5vID0gKG9iaiwgcHJvcCkgPT4gKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChvYmosIHByb3ApKSIsIi8vIGRlZmluZSBfX2VzTW9kdWxlIG9uIGV4cG9ydHNcbl9fd2VicGFja19yZXF1aXJlX18uciA9IChleHBvcnRzKSA9PiB7XG5cdGlmKHR5cGVvZiBTeW1ib2wgIT09ICd1bmRlZmluZWQnICYmIFN5bWJvbC50b1N0cmluZ1RhZykge1xuXHRcdE9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBTeW1ib2wudG9TdHJpbmdUYWcsIHsgdmFsdWU6ICdNb2R1bGUnIH0pO1xuXHR9XG5cdE9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCAnX19lc01vZHVsZScsIHsgdmFsdWU6IHRydWUgfSk7XG59OyIsImltcG9ydCBjb29raWVQYXJzZXIgZnJvbSAnY29va2llLXBhcnNlcic7XG5pbXBvcnQgY29ycyBmcm9tICdjb3JzJztcbmltcG9ydCBleHByZXNzIGZyb20gJ2V4cHJlc3MnO1xuaW1wb3J0IGh0dHAgZnJvbSAnaHR0cCc7XG5pbXBvcnQgbG9nZ2VyIGZyb20gJ21vcmdhbic7XG5pbXBvcnQgeyBsb2dFbnRyaWVzQ29udHJvbGxlciB9IGZyb20gJy4vcHJlc2VudGF0aW9uL2NvbnRyb2xsZXJzL2xvZ0VudHJpZXNDb250cm9sbGVyJztcblxuZXhwb3J0IGNvbnN0IGFwcCA9IGV4cHJlc3MoKTtcblxuYXBwLnVzZShsb2dnZXIoJ2RldicpKTtcbmFwcC51c2UoZXhwcmVzcy5qc29uKCkpO1xuYXBwLnVzZShleHByZXNzLnVybGVuY29kZWQoeyBleHRlbmRlZDogZmFsc2UgfSkpO1xuYXBwLnVzZShjb29raWVQYXJzZXIoKSk7XG5hcHAudXNlKGNvcnMoeyBvcmlnaW46ICdodHRwOi8vbG9jYWxob3N0OjMwMDEnIH0pKTtcbmFwcC51c2UoJy9hcGknLCBsb2dFbnRyaWVzQ29udHJvbGxlcik7XG5cbi8qKlxuICogTm9ybWFsaXplIGEgcG9ydCBpbnRvIGEgbnVtYmVyLCBzdHJpbmcsIG9yIGZhbHNlLlxuICovXG5cbmZ1bmN0aW9uIG5vcm1hbGl6ZVBvcnQodmFsOiBzdHJpbmcpIHtcbiAgY29uc3QgcG9ydCA9IHBhcnNlSW50KHZhbCwgMTApO1xuXG4gIGlmIChOdW1iZXIuaXNOYU4ocG9ydCkpIHtcbiAgICAvLyBuYW1lZCBwaXBlXG4gICAgcmV0dXJuIHZhbDtcbiAgfVxuXG4gIGlmIChwb3J0ID49IDApIHtcbiAgICAvLyBwb3J0IG51bWJlclxuICAgIHJldHVybiBwb3J0O1xuICB9XG5cbiAgcmV0dXJuIGZhbHNlO1xufVxuXG4vKipcbiAqIEdldCBwb3J0IGZyb20gZW52aXJvbm1lbnQgYW5kIHN0b3JlIGluIEV4cHJlc3MuXG4gKi9cblxuY29uc3QgcG9ydCA9IG5vcm1hbGl6ZVBvcnQocHJvY2Vzcy5lbnYuUE9SVCB8fCAnMzAwMCcpO1xuYXBwLnNldCgncG9ydCcsIHBvcnQpO1xuXG4vKipcbiAqIENyZWF0ZSBIVFRQIHNlcnZlci5cbiAqL1xuXG5jb25zdCBzZXJ2ZXIgPSBodHRwLmNyZWF0ZVNlcnZlcihhcHApO1xuXG4vKipcbiAqIEV2ZW50IGxpc3RlbmVyIGZvciBIVFRQIHNlcnZlciBcImVycm9yXCIgZXZlbnQuXG4gKi9cblxuZnVuY3Rpb24gb25FcnJvcihlcnJvcjogTm9kZUpTLkVycm5vRXhjZXB0aW9uKSB7XG4gIGlmIChlcnJvci5zeXNjYWxsICE9PSAnbGlzdGVuJykge1xuICAgIHRocm93IGVycm9yO1xuICB9XG5cbiAgY29uc3QgYmluZCA9IHR5cGVvZiBwb3J0ID09PSAnc3RyaW5nJyA/IGBQaXBlICR7cG9ydH1gIDogYFBvcnQgJHtwb3J0fWA7XG5cbiAgLy8gaGFuZGxlIHNwZWNpZmljIGxpc3RlbiBlcnJvcnMgd2l0aCBmcmllbmRseSBtZXNzYWdlc1xuICBzd2l0Y2ggKGVycm9yLmNvZGUpIHtcbiAgICBjYXNlICdFQUNDRVMnOlxuICAgICAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG5vLWNvbnNvbGVcbiAgICAgIGNvbnNvbGUuZXJyb3IoYCR7YmluZH0gcmVxdWlyZXMgZWxldmF0ZWQgcHJpdmlsZWdlc2ApO1xuICAgICAgcHJvY2Vzcy5leGl0KDEpO1xuICAgICAgYnJlYWs7XG4gICAgY2FzZSAnRUFERFJJTlVTRSc6XG4gICAgICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbm8tY29uc29sZVxuICAgICAgY29uc29sZS5lcnJvcihgJHtiaW5kfSBpcyBhbHJlYWR5IGluIHVzZWApO1xuICAgICAgcHJvY2Vzcy5leGl0KDEpO1xuICAgICAgYnJlYWs7XG4gICAgZGVmYXVsdDpcbiAgICAgIHRocm93IGVycm9yO1xuICB9XG59XG5cbi8qKlxuICogRXZlbnQgbGlzdGVuZXIgZm9yIEhUVFAgc2VydmVyIFwibGlzdGVuaW5nXCIgZXZlbnQuXG4gKi9cblxuZnVuY3Rpb24gb25MaXN0ZW5pbmcoKSB7XG4gIGNvbnN0IGFkZHIgPSBzZXJ2ZXIuYWRkcmVzcygpO1xuICBjb25zdCBiaW5kID0gdHlwZW9mIGFkZHIgPT09ICdzdHJpbmcnID8gYHBpcGUgJHthZGRyfWAgOiBgcG9ydCAke2FkZHI/LnBvcnR9YDtcbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG5vLWNvbnNvbGVcbiAgY29uc29sZS5sb2coYExpc3RlbmluZyBvbiAke2JpbmR9YCk7XG59XG5cbi8qKlxuICogTGlzdGVuIG9uIHByb3ZpZGVkIHBvcnQsIG9uIGFsbCBuZXR3b3JrIGludGVyZmFjZXMuXG4gKi9cblxuc2VydmVyLmxpc3Rlbihwb3J0KTtcbnNlcnZlci5vbignZXJyb3InLCBvbkVycm9yKTtcbnNlcnZlci5vbignbGlzdGVuaW5nJywgb25MaXN0ZW5pbmcpO1xuIl0sIm5hbWVzIjpbXSwic291cmNlUm9vdCI6IiJ9