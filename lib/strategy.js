const Corbado = require('corbado');
const corbado = new Corbado('pro-4817998336279299095', 'corbado1_iXVHYmlpoKMpkpEcR8gw8gFnmWwcwu');

const axios = require('axios');

// Module dependencies.
var passport = require('passport-strategy')
  , url = require('url')
  , crypto = require('crypto')
  , cose2jwk = require('cose-to-jwk')
  , jwk2pem = require('jwk-to-pem')
  , base64url = require('base64url')
  , util = require('util')
  , utils = require('./utils')
  , Attestation = require('./fido2/attestation')
  , AuthenticatorData = require('./fido2/authenticatordata')
  , SessionStore = require('./store/session');

// Constants for authenticator data flags.
var USER_PRESENT = 0x01;
var USER_VERIFIED = 0x04;


const username = 'pro-4817998336279299095';
const password = 'corbado1_iXVHYmlpoKMpkpEcR8gw8gFnmWwcwu';

/**
 * Create a new `Strategy` object.
 *
 */
function Strategy(options, verify, verifySignCount, register) {
  console.log('FIDO2 STRATEGY CALLED');
  options = options || {};
  if (typeof options == 'function') {
    register = verifySignCount;
    verifySignCount = verify;
    verify = options;
    options = {};
  }
  if (typeof register == 'undefined') {
    register = verifySignCount;
    verifySignCount = undefined;
  }

  console.log("options: " + JSON.stringify(options));
  console.log("CALLING PARENT STRATEGY")
  
  passport.Strategy.call(this);
  this.name = 'webauthn';
  this._attestationFormats = options.attestationFormats || require('./fido2/formats');
  this._verify = verify;
  this._verifySignCount = verifySignCount;
  this._register = register;
  this._store = options.store || new SessionStore();
}

// Inherit from `passport.Strategy`.
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, options) {
  console.log("authenticate called");
  console.log("req.body: ", req.body);
  var response = req.body.response;
  var method = req.body.method;
  
  var self = this;

  console.log("METHOD: ", method);

  // Verify that the origin contained in client data matches the origin of this
  // app (which is the relying party).

  if (method === 'webauthn.get') {

    
  } else if (method === 'webauthn.create') {
    console.log("Webauthn create verify");
    console.log("BODY: ", JSON.stringify(req.body.credential));

    const body = {
      publicKeyCredential: JSON.stringify(req.body.credential),
      clientInfo: {
        remoteAddress: req.ip,
        userAgent: req.get('user-agent'),
      },
    };

    console.log("BODY: ");
    console.log(body);

    axios.post('https://backendapi.corbado.io/v1/webauthn/register/finish', body, {
      auth: {
        username,
        password,
      },
    }).then((response) => {
      console.log('Response from the server:', response);
      console.log('parsed:', response.data);
      var user = {
        id: response.data.userID,
        name: response.data.username,
        displayName: response.data.userFullName
      };

      self.success(user);
    }).catch((error) => {
      console.log('Error making POST request:', error.message);
      self.fail({ message: error.message }, 500);
    });
  }
};

module.exports = Strategy;
