/**
 * Copyright 2014 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

var request = require('request');
var google = require('googleapis');
var async = require('async');
var gitkit = google.identitytoolkit('v3');

GitkitClient.GITKIT_CERT_URL =
    'https://www.googleapis.com/identitytoolkit/v3/relyingparty/publicKeys';
GitkitClient.GITKIT_ISSUER = 'https://identitytoolkit.google.com/';
GitkitClient.GITKIT_SCOPE = 'https://www.googleapis.com/auth/identitytoolkit';
GitkitClient.RESET_PASSWORD_ACTION = 'resetPassword';
GitkitClient.CHANGE_EMAIL_ACTION = 'changeEmail';

/**
 * Gitkit client constructor.
 *
 * @param {object} options Options to be passed in
 * @constructor
 */
function GitkitClient(options) {
  this.widgetUrl = options.widgetUrl;
  this.maxTokenExpiration = 86400 * 30; // 30 days
  this.audiences = [];
  if (options.projectId !== undefined) {
    this.audiences.push(options.projectId);
  }
  if (options.clientId !== undefined) {
    this.audiences.push(options.clientId);
  }
  if (this.audiences.length == 0) {
    throw new Error("Missing projectId or clientId in server configuration.");
  }
  this.authClient = new google.auth.JWT(
      options.serviceAccountEmail,
      options.serviceAccountPrivateKeyFile,
      options.serviceAccountPrivateKey,
      [GitkitClient.GITKIT_SCOPE],
      '');
  this.certificateCache = null;
  this.certificateExpiry = null;
}

/**
 * Verifies a Google Identity Toolkit token.
 *
 * @param {string} token The token string
 * @param {function} callback The callback to receive verification result
 */
GitkitClient.prototype.verifyGitkitToken = function(token, callback) {
  if (!token || !callback) {
    throw new Error('The verifyIdToken method requires both ' +
        'the token string and a callback method');
  }

  var self = this;
  this.getGitkitCerts_(function(err, certs) {
    if (err) {
      callback(err, null);
      return;
    }
    try {
      var parsedToken = undefined;
      for (var idx in self.audiences) {
        try {
          parsedToken = self.authClient.verifySignedJwtWithCerts(token, certs,
              self.audiences[idx], GitkitClient.GITKIT_ISSUER, self.maxTokenExpiration);
          break;
        } catch (err) {
          if (err.message.indexOf('Wrong recipient') === -1) {
            throw err;
          }
        }
      }
      if (!parsedToken) {
        callback('Unable to verify the ID Token', null);
      }
      callback(null, parsedToken.getPayload());
    } catch (err) {
      callback('Unable to verify the ID Token: ' + err.message, null);
    }
  });
};

/**
 * Retrieves the account info from Gitkit service, using email.
 *
 * @param {string} email User's email
 * @param {function} cb Callback function to receive result
 */
GitkitClient.prototype.getAccountByEmail = function(email, cb) {
  this.getAccountInfo_({'email': [email]}, cb);
};

/**
 * Retrieves the account info from Gitkit service, using user id.
 *
 * @param {string} id User's local_id
 * @param {function} cb Callback function to receive result
 */
GitkitClient.prototype.getAccountById = function(id, cb) {
  this.getAccountInfo_({'localId': [id]}, cb);
};

/**
 * Downloads the whole account info from Gitkit service.
 *
 * @param {number} paginationSize Number of accounts to download per request
 * @param {function} cb Callback to receive results
 */
GitkitClient.prototype.downloadAccount = function(paginationSize, cb) {
  var self = this;
  this.authClient.authorize(function(err, tokens) {
    if (err) {
      cb(err, null);
      return;
    }
    var resource = paginationSize ? {'maxResults': paginationSize} : {};
    async.doWhilst(
      function(callback){
        gitkit.relyingparty.downloadAccount({
          resource: resource,
          auth: self.authClient
        }, function (err, resp) {
          if (err) {
            callback(err);
            return;
          }
          resource['nextPageToken'] = resp['nextPageToken'];
          var users = resp['users'];
          if (users && users.length > 0) {
            cb(null, users);
          }
          callback();
        })
      },
      function() {
        return resource['nextPageToken'];
      },
      function(err) {
        cb(err, null);
      }
    );
  });
};

/**
 * Uploads existing user accounts to Gitkit service.
 *
 * @param {Array.<object>} accounts Local user accounts
 * @param {Object} hashOptions Options for the hash algorithm
 *    {'hashAlgorithm': Supported values are HMAC_SHA256, HMAC_SHA1, HMAC_MD5,
  *       PBKDF_SHA1, MD5, SHA1 and SCRYPT,
  *    'hashKey': key for the hash algorithm}
 * @param {function} cb The callback function
 */
GitkitClient.prototype.uploadAccount = function(accounts, hashOptions, cb) {
  var self = this;
  this.authClient.authorize(function(err, tokens) {
    if (err) {
      cb(err, null);
      return;
    }
    var resource = {
      'users': accounts.map(function(account) {
        account['passwordHash'] =
            self.toWebSafeBase64_(account['passwordHash']);
        account['salt'] = self.toWebSafeBase64_(account['salt']);
        return account;
      })
    };
    if (hashOptions['hashAlgorithm']) {
      resource['hashAlgorithm'] = hashOptions['hashAlgorithm'];
    }
    if (hashOptions['hashKey']) {
      resource['signerKey'] = hashOptions['hashKey'].toString('base64').
          replace(/\//g, '_').replace(/\+/g, '-');
    }
    gitkit.relyingparty.uploadAccount({
      resource: resource,
      auth: self.authClient
    }, function(err, resp) {
      cb(err, resp);
    });
  });
};

/**
 * Gets out-of-band response for resetting password and changing email
 * operations.
 *
 * @param {Object} param Http request param from Gitkit javascript/mobile client
 * @param {string} userIp End user's IP address, used to verify captcha input
 * @param {string} gitkitToken Gitkit id_token for the login user
 * @param {function} callback The callback fn
 */
GitkitClient.prototype.getOobResult = function(param, userIp, gitkitToken, callback) {
  if (param['action']) {
    if (param['action'] == GitkitClient.RESET_PASSWORD_ACTION) {
      var request = {
        email: param['email'],
        userIp: userIp,
        challenge: param['challenge'],
        captchaResp: param['response'],
        requestType: 'PASSWORD_RESET'
      };
    } else if (param['action'] == GitkitClient.CHANGE_EMAIL_ACTION) {
      if (!gitkitToken) {
        callback(this._failureOobResponse('login is required'));
        return;
      }
      request = {
        email: param['oldEmail'],
        newEmail: param['newEmail'],
        userIp: userIp,
        idToken: gitkitToken,
        requestType: 'NEW_EMAIL_ACCEPT'
      };
    } else {
      callback(this._failureOobResponse('unknown oob action'));
      return;
    }
    this._callOobApi(request, param['action'], callback);
    return;
  }
  callback(this._failureOobResponse('missing oob action'));
};


/**
 * Gets verification url to verify user's email.
 *
 * @param {string} email user's email to be verified
 * @param {function} callback The callback fn
 */
GitkitClient.prototype.getEmailVerificationLink = function(email, callback) {
  if (email) {
    var request = {
      email: email,
      requestType: 'VERIFY_EMAIL'
    };
    this._callOobApi(request, 'verifyEmail', function(err, resp) {
      if (err) {
        callback(err, null);
      } else {
        callback(null, resp.oobLink);
      }
    });
    return;
  }
  callback('missing email', null);
};

/**
 * Deletes an account from Gitkit service.
 *
 * @param {string} userId Local id of the account to be deleted
 * @param {function} cb The callback fn to receive response
 */
GitkitClient.prototype.deleteAccount = function(userId, cb) {
  var self = this;
  this.authClient.authorize(function(err, tokens) {
    if (err) {
      cb(err, null);
      return;
    }
    gitkit.relyingparty.deleteAccount({
      resource: {'localId': userId},
      auth: self.authClient
    }, function(err, resp) {
      cb(err, resp);
    });
  });
};

/**
 * Encodes data using web-safe-base64.
 *
 * @param {string} data Raw input data
 * @returns {string} base64-encoded result
 * @private
 */
GitkitClient.prototype.toWebSafeBase64_ = function(data) {
  return data.toString('base64').replace(/\//g, '_').replace(/\+/g, '-');
};

/**
 * Gets account info from Gitkit service.
 *
 * @param {Object} resource The request
 * @param {function} cb The callback function to receive the acccount info
 * @private
 */
GitkitClient.prototype.getAccountInfo_ = function(resource, cb) {
  var self = this;
  this.authClient.authorize(function(err, tokens) {
    if (err) {
      cb(err, null);
      return;
    }
    gitkit.relyingparty.getAccountInfo({
      resource: resource,
      auth: self.authClient
    }, function(err, resp) {
      cb(err, resp);
    });
  });
};

/**
 * Gets Google Identity Toolkit certificates to use for verifying identity tokens.
 * Returns certs as array structure, where keys are key ids, and values
 * are PEM encoded certificates.
 *
 * @param {function} callback Callback supplying the certificates
 * @private
 */
GitkitClient.prototype.getGitkitCerts_ = function(callback) {
  var nowTime = (new Date()).getTime();
  if (this.certificateExpiry && (nowTime < this.certificateExpiry.getTime())) {
    callback(null, this.certificateCache);
    return;
  }

  var self = this;
  request({
    url: GitkitClient.GITKIT_CERT_URL,
    method: 'GET'
  }, function(err, res, body) {
    body = JSON.parse(body);
    var error = err || body['error'];
    if (error) {
      callback(error , null);
    } else {
      self.cacheCerts_(body, res, callback);
    }
  });
};

/**
 * Store certs in cache.
 *
 * @param {Object} body The body of request
 * @param {Object} res The response of request
 * @param {function} callback Callback supplying the certificates
 * @private
 */
GitkitClient.prototype.cacheCerts_ = function(body, res, callback) {
  var self = this;
  var cacheControl = res.headers['cache-control'];
  var cacheAge = -1;
  if (cacheControl) {
    var pattern = new RegExp('max-age=([0-9]*)');
    var regexResult = pattern.exec(cacheControl);
    if (regexResult.length === 2) {
      // Cache results with max-age (in seconds)
      cacheAge = regexResult[1] * 1000; // milliseconds
    }
  }

  var now = new Date();
  self.certificateExpiry = cacheAge === -1 ? null : new Date(now.getTime() + cacheAge);
  self.certificateCache = body;
  callback(null, body);
};

/**
 * Generates failed response for out-of-band operation
 *
 * @param {string} error_msg The error message
 * @returns {Object} response body
 * @private
 */
GitkitClient.prototype._failureOobResponse = function (error_msg) {
  return {'responseBody': JSON.stringify({'error': error_msg})}
};

/**
 * Builds out-of-band URL. Gitkit API GetOobCode() is called and the returning
 * code is combined with Gitkit widget URL to building the out-of-band url.
 *
 * @param request request object
 * @param mode string, Gitkit widget mode to handle the oob action after user
 *     clicks the oob url in the email.
 * @param cb callback function
 * @return {string} oob url
 * @private
 */
GitkitClient.prototype._callOobApi = function(request, mode, cb) {
  var self = this;
  this.authClient.authorize(function(err, tokens) {
    if (err) {
      cb(err, self._failureOobResponse(err));
      return;
    }
    gitkit.relyingparty.getOobConfirmationCode({
      resource: request,
      auth: self.authClient
    }, function(err, resp) {
      if (err) {
        cb(err, self._failureOobResponse(err));
        return;
      }
      var oobCode = resp['oobCode'];
      var separator = self.widgetUrl.indexOf('?') != -1 ? '&' : '?';
      var oobLink = self.widgetUrl + separator + 'mode=' + mode +
          '&oobCode=' + oobCode;
      var result = {
        email: request['email'],
        oobLink: oobLink,
        oobCode: oobCode,
        responseBody: JSON.stringify({'success': true})
      };
      if (mode == GitkitClient.RESET_PASSWORD_ACTION) {
        result.action = GitkitClient.RESET_PASSWORD_ACTION;
      } else if (mode == GitkitClient.CHANGE_EMAIL_ACTION) {
        result.newEmail = request['newEmail'];
        result.action = GitkitClient.CHANGE_EMAIL_ACTION;
      }
      cb(null, result);
    });
  });
};

module.exports = GitkitClient;
