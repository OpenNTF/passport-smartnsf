# Passport-SmartNSF #

[Passport](https://github.com/jaredhanson/passport) strategy to use with SmartNSF enabled notes applications.
Passport-SmartNSF let you authenticate against a domino server, using username and passwort. The returning userobject contains the Notes UserName, e-mail address, groups and roles of the user. Additionally, all cookies are also returned.

## Install

    $ npm install passport-smartnsf

## Usage of Passport-SmartNSF ##

The SmartNSF authentication strategy authenticates requests based on
userid and password credentials extracted from the request.

Applications must supply a `verify` callback which accepts `userdetails` and then calls the 
`done` callback supplying a `user`.

Userdetails is an object with the following informations:

    {
      username: 'Hans Muster/ACME',
      email: 'hans.muster@acme.com',
      roles: ['[dbmanager]','[signer]'],
      groups: ['*','_ServerAccess'],
      accesslevel: 3,
      cookies: [{ key: 'ltpaToken', value:'token'}, ...]
    }

If an exception occured, `err` should be set.

 The Application must supply a 'extractor' call back which accepts 'req' and 'credentials'
 The credentials.useername and credentials.password must befilled with the values from the
 request.

Options:
- `smartNSFPath`:  path to the smartNSF enabled notes application like /apps/app.nsf
- `smartNSFHost`:  hostname (inkl protocol) like https://example.org

### Examples ###

    passport.use(new SmartNSFStrategy( {
        smartNSFHost: 'https://example.org'
        smartNSFPath: '/apps/somewhere.nsf'
       },
       function(userdetails, done) {
         User.findOne({ username: userdetails.username }, function (err, user) {
           done(err, user);
         });
       },
       function(req, credentials) {
          credentials.username: req.body.username,
          credentials.password: req.body.password
       }
    ));

### Authenticate Requests ###

Use `passport.authenticate()`, specifying the `'smartnsf'` strategy, to
authenticate requests.  Requests containing the username and password in the request body do not
require session support, so the `session` option can be set to `false`.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/private',
      passport.authenticate('smartnsf', { session: false }),
      function(req, res) {
        res.json(req.user);
      });

## OPENNTF ##

    This project is an OpenNTF project, and is available under the Apache License V2.0.  
    All other aspects of the project, including contributions, defect reports, discussions, 
    feature requests and reviews are subject to the OpenNTF Terms of Use - available at 
    http://openntf.org/Internal/home.nsf/dx/Terms_of_Use.