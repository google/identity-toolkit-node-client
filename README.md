Google Identity Toolkit client library for Node.js

Sample usage
=====================

Initialize Gitkit client instance
--------------

```javascript
  var GitkitClient = require('gitkitclient');
  var gitkitClient = new GitkitClient({
    'clientId' : GOOGLE_OAUTH2_WEB_CLIENT_ID,
    'serviceAccountEmail' : SERVICE_ACCOUNT_EMAIL@developer.gserviceaccount.com,
    'serviceAccountPrivateKeyFile' : PRIVATE_KEY_IN_PEM_FORMAT.pem,
    'widgetUrl' : 'http://localhost:8000/gitkit',
    'cookieName' : 'gtoken'
  });
```

Verify Gitkit Token string
--------------

```javascript
  gitkitClient.verifyGitkitToken(tokenString, function (err, parsedToken) {
    console.log('login user is', parsedToken);
  });
```
  
Upload Multiple Accounts
--------------

```javascript
  var hashKey = new Buffer('key123');
  var hashOptions = {
    'hashAlgorithm': 'HMAC_SHA1',
    'hashKey': hashKey
  };
  function createNewUsers(hashKey) {
    var crypto = require('crypto');
    var user1 = {
      localId: '1234',
      email: '1234@example.com',
      salt: new Buffer('salt-1'),
      passwordHash: crypto.createHmac('SHA1', hashKey).update('1111' + 'salt-1').digest()
    };
    return [user1];
  }
  gitkitClient.uploadAccount(createNewUsers(hashKey), hashOptions, function (err, resp){
    if (err) {
      console.log('error: ', err);
    } else {
      console.log(resp);
    }
  });
```

Download Accounts
--------------

```javascript
  gitkitClient.downloadAccount(10, function(err, accounts){
    if (err) {
      console.log('error: ', err);
    } else {
      if (accounts != null) {
        console.log(accounts);
      } else {
        console.log('finished');
      }
    }
  });
```

Get Account Info
--------------

```javascript
  gitkitClient.getAccountByEmail("1234@example.com", function(err, resp) {
    console.log('getAccountByEmail: ', err, resp);
  });
  gitkitClient.getAccountById("1234", function(err, resp) {
    console.log('getAccountById: ', err, resp);
  });
```

Get the URL to verify user's email
--------------

```javascript
  gitkitClient.getEmailVerificationLink("1234@example.com", function(err, resp) {
    console.log('email verification link: ' + resp);
  });
```

Delete Account
--------------

```javascript
  gitkitClient.deleteAccount('1234', function(err, response){
    if (err) {
      console.log("error: ", err);
    } else {
      console.log(response);
    }
  });
```
