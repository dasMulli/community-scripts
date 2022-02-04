/*
* This script is intended to be used along with  httpsender/AddBearerTokenHeader.js  to
* handle an OAUTH2 resource ownder credentials flow.
*
* authentication/OAuthResourceOwnerCredentialsFlow.js will automatically fetch the new access token for every unauthorized
* request determined by the "Logged Out" or "Logged In" indicator previously set in Context -> Authentication.
*
*  httpsender/AddBearerTokenHeader.js  will add the new access token to all requests in scope
* made by ZAP (except the authentication ones) as an "Authorization: Bearer [access_token]" HTTP Header.
*
* @author Martin Ullrich <martin.andreas.ullrich at gmail.com> (based on authentication/OfflineTokenRefresher.js)
* @author Laura Pardo <lpardo at redhat.com>
*/

var HttpRequestHeader = Java.type("org.parosproxy.paros.network.HttpRequestHeader");
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var URI = Java.type("org.apache.commons.httpclient.URI");
var ScriptVars = Java.type('org.zaproxy.zap.extension.script.ScriptVars');


function authenticate(helper, paramsValues, credentials) {

  var token_endpoint = paramsValues.get("token_endpoint");
  var client_id = paramsValues.get("client_id");
  var client_secret = paramsValues.get("client_secret");
  var username = credentials.getParam("username");
  var password = credentials.getParam("password");

  // Build body
  var refreshTokenBody = "grant_type=password";
  refreshTokenBody+= "&client_id=" + client_id;
  if (client_secret) {
    refreshTokenBody+= "&client_secret=client_secret";
  }
  refreshTokenBody+= "&username=" + username;
  refreshTokenBody+= "&password=" + password;

  // Build header
  var tokenRequestURI = new URI(token_endpoint, false);
  var tokenRequestMethod = HttpRequestHeader.POST;
  var tokenRequestMainHeader = new HttpRequestHeader(tokenRequestMethod, tokenRequestURI, HttpHeader.HTTP11);

  // Build message
  var tokenMsg = helper.prepareMessage();
  tokenMsg.setRequestBody(refreshTokenBody);
  tokenMsg.setRequestHeader(tokenRequestMainHeader);
  tokenMsg.getRequestHeader().setContentLength(tokenMsg.getRequestBody().length());

  // Make the request and receive the response
  helper.sendAndReceive(tokenMsg, false);

  // Parse the JSON response and save the new access_token in a global var
  // we will replace the Authentication header in AddBearerTokenHeader.js
  var json = JSON.parse(tokenMsg.getResponseBody().toString());
  var access_token = json['access_token'];

  if (access_token){
    ScriptVars.setGlobalVar("access_token", access_token);
  }else{
    print("Error getting access token");
  }

  return tokenMsg;
}


function getRequiredParamsNames(){
  return ["token_endpoint", "client_id"];
}


function getOptionalParamsNames(){
  return ["client_secret"];
}


function getCredentialsParamsNames(){
  return ["username", "password"];
}
