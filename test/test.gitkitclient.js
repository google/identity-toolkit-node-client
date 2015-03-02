/**
 * Copyright 2014 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

var tk = require('timekeeper');
var assert = require('assert');
var fs = require('fs');
var GitkitClient = require('../lib/gitkitclient.js');
var nock = require('nock');

nock.disableNetConnect();

describe('Gitkit client library', function() {

  it('should verify a Gitkit Idtoken', function (done) {
    GitkitClient.prototype.getGitkitCerts_ = function(callback) {
      callback(null, JSON.parse(fs.readFileSync(__dirname + '/fixtures/gitkitcerts.json')));
    };

    var gitkitClient = new GitkitClient({
      'clientId' : 'testaudience',
      'serviceAccountEmail' : 'SERVICE_ACCOUNT_EMAIL@developer.gserviceaccount.com',
      'serviceAccountPrivateKeyFile' : __dirname + '/fixtures/' + 'privatekey.pem',
      'widgetUrl' : 'http://localhost:8000/widget',
      'cookieName' : 'gtoken'
    });
    var tokenString = fs.readFileSync(__dirname + '/fixtures/gitkittoken.txt', 'utf8');
    tk.freeze(new Date(1400040000000));
    gitkitClient.verifyGitkitToken(tokenString, function (err, parsedToken) {
      tk.reset();
      assert.equal(err, null);
      assert.equal(parsedToken['email'], 'test@test.com');
      done();
    });
  });

  it('should get sendemail response', function() {
    var jwtScope = nock('https://accounts.google.com')
        .filteringRequestBody(function(path) {
          return 'ABC';
        })
        .post('/o/oauth2/token', 'ABC')
        .reply(200, {
          'access_token': 'access token'
        });
    var userEmail = 'test@test.com';
    var oobCode = 'random-oob-code';
    var userIp = '1.1.1.1';
    var challenge = 'captcha-challenge';
    var captchaResponse = 'captcha-response';
    var httpParam = {
      'action': 'resetPassword',
      'email': userEmail,
      'challenge': challenge,
      'response': captchaResponse
    };
    var scope = nock('https://www.googleapis.com')
        .post('/identitytoolkit/v3/relyingparty/getOobConfirmationCode', {
          'email': userEmail,
          'userIp': userIp,
          'challenge': challenge,
          'captchaResp': captchaResponse,
          'requestType': 'PASSWORD_RESET'
        })
        .reply(200, {
          oobCode: oobCode
        });

    var gitkitClient = new GitkitClient({
      'clientId' : 'testaudience',
      'serviceAccountEmail' : 'SERVICE_ACCOUNT_EMAIL@developer.gserviceaccount.com',
      'serviceAccountPrivateKeyFile' : __dirname + '/fixtures/' + 'privatekey.pem',
      'widgetUrl' : 'http://localhost:8000/widget',
      'cookieName' : 'gtoken'
    });
    gitkitClient.getOobResult(httpParam, userIp, undefined, function(error, result) {
      console.log(error);
      console.log(result);
      assert.equal(error,  null);
      assert.equal(result['oobLink'],
          'http://localhost:8000/widget?mode=resetPassword&oobCode=random-oob-code');
      assert.equal(result['responseBody'], '{"success":true}');
      jwtScope.done();
      scope.done();
      done();
    });
  });

  it('should get email verification link', function() {
    var jwtScope = nock('https://accounts.google.com')
        .filteringRequestBody(function(path) {
          return 'ABC';
        })
        .post('/o/oauth2/token', 'ABC')
        .reply(200, {
          'access_token': 'access token'
        });
    var userEmail = 'test@test.com';
    var oobCode = 'random-oob-code';

    var scope = nock('https://www.googleapis.com')
        .post('/identitytoolkit/v3/relyingparty/getOobConfirmationCode', {
          'email': userEmail,
          'requestType': 'VERIFY_EMAIL'
        })
        .reply(200, {
          oobCode: oobCode
        });

    var gitkitClient = new GitkitClient({
      'clientId' : 'testaudience',
      'serviceAccountEmail' : 'SERVICE_ACCOUNT_EMAIL@developer.gserviceaccount.com',
      'serviceAccountPrivateKeyFile' : __dirname + '/fixtures/' + 'privatekey.pem',
      'widgetUrl' : 'http://localhost:8000/widget',
      'cookieName' : 'gtoken'
    });
    gitkitClient.getEmailVerificationLink(userEmail, function(error, result) {
      assert.equal(error,  null);
      assert.equal(result,
          'http://localhost:8000/widget?mode=resetPassword&oobCode=random-oob-code');
      jwtScope.done();
      scope.done();
      done();
    });
  });
});
