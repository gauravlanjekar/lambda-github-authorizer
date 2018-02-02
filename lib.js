'use strict';


// Lambda now supports environment variables - http://docs.aws.amazon.com/lambda/latest/dg/tutorial-env_cli.html
// a .env file can be used as a development convenience. Real environment variables can be used in deployment and
// will override anything loaded by dotenv.
require('dotenv').config();
const rp = require('request-promise');
const fs = require('fs');
const Promise = require('bluebird');

Promise.longStackTraces();
const clientId = process.env.clientId;
const clientSecret = process.env.clientSecret;



var policyDocumentFilename = 'policyDocument.json';
var policyDocument;
try {
  policyDocument = JSON.parse(fs.readFileSync(__dirname + '/' + policyDocumentFilename, 'utf8'));
} catch (e) {
  if (e.code === 'ENOENT') {
    console.error('Expected ' + policyDocumentFilename + ' to be included in Lambda deployment package');
    // fallthrough
  }
  throw e;
}



// extract and return the Bearer Token from the Lambda event parameters
var getToken = function (params) {
  var token;

  if (!params.type || params.type !== 'TOKEN') {
    throw new Error("Expected 'event.type' parameter to have value TOKEN");
  }

  var tokenString = params.authorizationToken;
  if (!tokenString) {
    throw new Error("Expected 'event.authorizationToken' parameter to be set");
  }

  var match = tokenString.match(/^Bearer (.*)$/);
  if (!match || match.length < 2) {
    throw new Error("Invalid Authorization token - '" + tokenString + "' does not match 'Bearer .*'");
  }
  return match[1];
}

var returnUserInfo = function (data) {
  console.log("inside user info", data)
  if (!data) throw new Error('data empty return');
  if (data === 'Unauthorized') {
    throw new Error('Unauthorized')
  } else {
    const user = data.user;
    return user
  }
}


// extract user_id from the autho0 userInfo and return it for AWS principalId
var getPrincipalId = function (userInfo) {
  if (!userInfo || (!userInfo.email && !userInfo.preferred_username)) {
    throw new Error("No email returned from authentication service");
  }
  console.log('authentication successful for user ' + (userInfo.email || userInfo.preferred_username));

  return userInfo.email || preferred_username;
}

// return the expected Custom Authorizaer JSON object
var getAuthentication = function (userInfo) {
  return {
    principalId: userInfo.principalId,
    policyDocument: policyDocument,
    context: userInfo
  }
}

//verify the signature on the token
var verifyToken = function (token) {

console.log("inside verify");
  //Call the github endpoint to verify token

var options = {
    uri: `https://api.github.com/applications/${clientId}/tokens/${token}`,    
    headers: {
        'User-Agent': 'Request-Promise'
    },
    json: true // Automatically parses the JSON string in the response
};  

return rp(options)
    .auth(clientId, clientSecret, true)
    .then(function (data) {
        return (data);
    })
    .catch(function (err) {
        // API call failed...
        // Token is not valid
        console.log("error Occoured",err);
        reject("invalid token");
    });


};

module.exports.authenticate = function (params) {
  var token = getToken(params);

  return verifyToken(token)
    .then(returnUserInfo)
    .then(getAuthentication);
}
