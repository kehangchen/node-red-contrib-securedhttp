node-red-contrib-securedhttp
=========================
[Node-RED](http://nodered.org) nodes similar to http in and http out
from the default installation but with security built into it.  If 
secured field is set to false, it has the same features as http in
in the default installation.  It uses a predefined OAuth endpoint 
to validate the token in authorization header in a request and to check 
if the user with the token has privilege to access this node.

Install
-------
Install from [npm](http://npmjs.org)
```
npm install node-red-contrib-securedhttp
```

Usage
-----
This package contains two nodes similar to the default http in and
http out nodes but securedhttp in node must be authenticated with a 
token in Authorization header or access_token query string for 
privileged user to access it if the "Secured" field is set to true.
When "Secured" field is set to true, user will need to have the
privilege specified in "Privileges" field.  If the "Privileges" is not
set but "Secured" field is set to true, an access token will need to 
be validated.  The OAuth user endpoint will need to specify in the 
settting.js file with "oauth2UserUrl" key.  For example,

  oauth2UserUrl: "https://localhost:8080/oauth/user",


SecuredHttp In node usage:
-----------------

You will need to fill in the following fields:

-- Ignore the "Start" field.

-- Secured field set to true to enable security.  False to disable.

-- User will need to have privilege to access this endpoint even the token is valid.


Authors
-------
* Kehang Chen
