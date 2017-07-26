/**
 * Module dependencies.
 */
var passport = require('passport-strategy');
var util = require('util');
var request = require('request');


/**
 * `SmartNSFStrategy` constructor.
 *
 * The SmartNSF authentication strategy authenticates requests based on
 * userid and password credentials extracted from the request.
 *
 * Applications must supply a `verify` callback which accepts `userdetails` and then calls the 
 * `done` callback supplying a `user`.
 * - userdetails is an object with the following informations:
 * {
 *      username: 'Hans Muster/ACME',
 *      email: 'hans.muster@acme.com',
 *      roles: ['[dbmanager]','[signer]'],
 *      groups: ['*','_ServerAccess'],
 *      accesslevel: 3,
 *      cookies: [{ name: 'ltpaToken', value:'token'}, ...]
 * } 
 * If an exception occured, `err` should be set.
 * 
 * The Application must supply a 'extractor' call back which accepts 'req' and 'credentials'
 * The credentials.useername and credentials.password must befilled with the values from the
 * request.
 *
 * Options:
 *   - `smartNSFPath`  path to the smartNSF enabled notes application like /apps/app.nsf
 *   - `smartNSFHost`  hostname (inkl protocol) like https://example.org
 * Examples:
 *
 *     passport.use(new SmartNSFStrategy( {
 *          smartNSFHost: 'https://example.org',
 *          smartNSFPath: '/apps/somewhere.nsf'
 *       },
 *       function(userdetails, done) {
 *         User.findOne({ username: userdetails.username }, function (err, user) {
 *           done(err, user);
 *         });
 *       },
 *       function(req, credentials) {
 *          credentials.username= req.body.username,
            credentials.password= req.body.password
 *       }
 *     ));
 *
 *
 * @param {Object} options
 * @param {Function} verify
 * @param {Function} extractor
 * @api public
 */
function SmartNSFStrategy(options, verify, extractor) {
    if (!verify || !extractor || !(options && options.smartNSFPath) || !(options && options.smartNSFHost)) {
        throw new Error('SmartNSF authentication strategy requires a verify, extractor, options.smartNSFPath and options.smartNSFHost to work correct');
    }
    passport.Strategy.call(this);
    this.name = 'smartnsf';
    this._verify = verify;
    this._smartnsfpath = options.smartNSFPath;
    this._smartnsfhost = options.smartNSFHost;
    this._extractor = extractor;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(SmartNSFStrategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a HTTP Basic authorization
 * header.
 *
 * @param {Object} req
 * @api protected
 */
SmartNSFStrategy.prototype.authenticate = function(req) {
    var credentials = {};
    this._extractor(req, credentials);
    if (!credentials.username || !credentials.password) {
        return this.error(new Error('Expect username && password as part of credentials!'));
    }
    credentials.redirectto = this._smartnsfpath + '/xsp/.xrest/?login';

    var strategy = this;
    var j = request.jar();
    request.post({ url: this._smartnsfhost + "/names.nsf?login", form: credentials, jar: j, followAllRedirects: true }, function(err, httpResponse, body) {
        var cookies = j.getCookies(strategy._smartnsfhost);
        if (err) {
            return strategy.error(err);
        }
        if (httpResponse.statusCode != 200) {
            return strategy.error(httpResponse.statusCode + ": call to SmartNSF failed.");
        }


        function verified(err, user) {
            if (err) { return strategy.error(err); }
            if (!user) {
                return strategy.error('No user defined!');
            }
            strategy.success(user);
        }

        try {
            var resp = JSON.parse(body);
            if (resp && resp.username) {
                resp.cookies = cookies;
                strategy._verify(resp, verified);
            } else {
                return strategy.fail("Authentication failed", 401);
            }
        } catch (e) {
            console.log(e);
            return strategy.fail("Authentication failed", 401);
        }
    })
}

/**
 * Expose `BasicStrategy`.
 */
module.exports = SmartNSFStrategy;