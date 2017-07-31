/**
 * Copyright JS Foundation and other contributors, http://js.foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

module.exports = function(RED) {
    "use strict";
    var bodyParser = require("body-parser");
    var cookieParser = require("cookie-parser");
    var getBody = require('raw-body');
    var cors = require('cors');
    var jsonParser = bodyParser.json();
    var urlencParser = bodyParser.urlencoded({extended:true});
    var onHeaders = require('on-headers');
    var typer = require('media-typer');
    var isUtf8 = require('is-utf8');
    //kchen - modification
    var util = require("util");
    var request = require('request');
    //var jwt_decode = require('jwt-decode');

    function rawBodyParser(req, res, next) {
        if (req.skipRawBodyParser) { next(); } // don't parse this if told to skip
        if (req._body) { return next(); }
        req.body = "";
        req._body = true;

        var isText = true;
        var checkUTF = false;

        if (req.headers['content-type']) {
            var parsedType = typer.parse(req.headers['content-type'])
            if (parsedType.type === "text") {
                isText = true;
            } else if (parsedType.subtype === "xml" || parsedType.suffix === "xml") {
                isText = true;
            } else if (parsedType.type !== "application") {
                isText = false;
            } else if (parsedType.subtype !== "octet-stream") {
                checkUTF = true;
            } else {
                // applicatino/octet-stream
                isText = false;
            }
        }

        getBody(req, {
            length: req.headers['content-length'],
            encoding: isText ? "utf8" : null
        }, function (err, buf) {
            if (err) { return next(err); }
            if (!isText && checkUTF && isUtf8(buf)) {
                buf = buf.toString()
            }
            req.body = buf;
            next();
        });
    }

    var corsSetup = false;

    function createRequestWrapper(node,req) {
        // This misses a bunch of properties (eg headers). Before we use this function
        // need to ensure it captures everything documented by Express and HTTP modules.
        var wrapper = {
            _req: req
        };
        var toWrap = [
            "param",
            "get",
            "is",
            "acceptsCharset",
            "acceptsLanguage",
            "app",
            "baseUrl",
            "body",
            "cookies",
            "fresh",
            "hostname",
            "ip",
            "ips",
            "originalUrl",
            "params",
            "path",
            "protocol",
            "query",
            "route",
            "secure",
            "signedCookies",
            "stale",
            "subdomains",
            "xhr",
            "socket" // TODO: tidy this up
        ];
        toWrap.forEach(function(f) {
            if (typeof req[f] === "function") {
                wrapper[f] = function() {
                    node.warn(RED._("httpin.errors.deprecated-call",{method:"msg.req."+f}));
                    var result = req[f].apply(req,arguments);
                    if (result === req) {
                        return wrapper;
                    } else {
                        return result;
                    }
                }
            } else {
                wrapper[f] = req[f];
            }
        });


        return wrapper;
    }
    function createResponseWrapper(node,res) {
        var wrapper = {
            _res: res
        };
        var toWrap = [
            "append",
            "attachment",
            "cookie",
            "clearCookie",
            "download",
            "end",
            "format",
            "get",
            "json",
            "jsonp",
            "links",
            "location",
            "redirect",
            "render",
            "send",
            "sendfile",
            "sendFile",
            "sendStatus",
            "set",
            "status",
            "type",
            "vary"
        ];
        toWrap.forEach(function(f) {
            wrapper[f] = function() {
                node.warn(RED._("httpin.errors.deprecated-call",{method:"msg.res."+f}));
                var result = res[f].apply(res,arguments);
                if (result === res) {
                    return wrapper;
                } else {
                    return result;
                }
            }
        });
        return wrapper;
    }

    var corsHandler = function(req,res,next) { next(); }

    if (RED.settings.httpNodeCors) {
        corsHandler = cors(RED.settings.httpNodeCors);
        RED.httpNode.options("*",corsHandler);
    }

    function HTTPIn(n) {
        RED.nodes.createNode(this,n);
        if (RED.settings.httpNodeRoot !== false) {

            if (!n.url) {
                this.warn(RED._("httpin.errors.missing-path"));
                return;
            }
            this.url = n.url;
            this.method = n.method;
            //kchen - modification
            this.secured = n.secured;
            this.privilege = n.privilege;
            this.swaggerDoc = n.swaggerDoc;

            // kchen - modification 7/5/2017
            this.userDetails = {};

            var node = this;

            this.errorHandler = function(err,req,res,next) {
                node.warn(err);
                res.sendStatus(500);
            };

            this.callback = function(req,res) {
                var msgid = RED.util.generateId();
                res._msgid = msgid;
                if (node.method.match(/^(post|delete|put|options|patch)$/)) {
                    node.send({_msgid:msgid,req:req,res:createResponseWrapper(node,res),payload:req.body,"userDetails":node.userDetails});
                } else if (node.method == "get") {
                    node.send({_msgid:msgid,req:req,res:createResponseWrapper(node,res),payload:req.query,"userDetails":node.userDetails});
                } else {
                    node.send({_msgid:msgid,req:req,res:createResponseWrapper(node,res),"userDetails":node.userDetails});
                }
            };

            var httpMiddleware = function(req,res,next) { 
                if (node.secured === "true") {
                    var encrypted = "";
                    if (req.get("authorization") && req.get("authorization").trim() !== "") {
                        encrypted = req.get("authorization");
                    }
                    if (!encrypted || encrypted.trim() === "") {
                        if (req.query.access_token && req.query.access_token.trim() !== "")
                            encrypted = req.query.access_token
                    }
                    var hasRight = false;
                    if (encrypted && encrypted.trim() !== "") {
                        if (encrypted.substring(0, 7).trim().toLowerCase() === "bearer")
                            encrypted = encrypted.substring(7);
                        //util.debug(encrypted.substring(7));
                        request({
                            url: RED.settings.oauth2UserUrl,
                            auth: {
                                'bearer': encrypted
                            }
                        }, 
                        function(err, response) {
                            var decoded = {};
                            if (!response || !response.body) {
                                node.error(err, err);
                                return res.status(500).end();
                            }
                            else {
                                decoded = JSON.parse(response.body);
                                if (err || decoded.error || decoded.length == 0) {
                                    var errorMessage = "";
                                    if (err)
                                        errorMessage = err;
                                    else if (decoded.error)
                                        errorMessage = decoded.error + " - " + decoded.error_description;
                                    else
                                        errorMessage = "System error - try again later";
                                    util.log(errorMessage);
                                    node.error(errorMessage, errorMessage);
                                    return res.status(401).end();
                                }
                                else {
                                    var privileges = [];
                                    if (node.privilege && node.privilege.trim() != "") {
                                        privileges = node.privilege.trim().split(",");
                                    }
                                    if (!privileges || privileges.length == 0) {
                                        util.log("user " + decoded.userAuthentication.name + " has authenticated right to access this flow");
                                        hasRight = true;
                                    }
                                    else {
                                        for (var i in decoded.authorities) {
                                            for (var j in privileges) {
                                                if (decoded.authorities[i].authority.indexOf(privileges[j].toUpperCase()) !== -1) {
                                                    util.log("user " + decoded.userAuthentication.name + " has " + privileges[j] + " right to access this flow");
                                                    hasRight = true;
                                                    break;
                                                }
                                            }
                                            if (hasRight)
                                                break;
                                        }
                                    }
                                    // kchen - modification 7/5/2017
                                    node.userDetails.name = decoded.userAuthentication.name;
                                    node.userDetails.email = decoded.details.decodedDetails.userEmail;
                                    node.userDetails.userLastName = decoded.details.decodedDetails.userLastName;
                                    node.userDetails.userFirstName = decoded.details.decodedDetails.userFirstName;
                                    node.userDetails.entityName = decoded.details.decodedDetails.entityName;
                                    node.userDetails.entityId = decoded.details.decodedDetails.entityId;
                                    node.userDetails.userId = decoded.details.decodedDetails.userId;
                                    node.userDetails.authorities = decoded.authorities;
                                    node.userDetails.token = "bearer " + encrypted;
                                    if (hasRight)         
                                        next();
                                    else {
                                        var errorMessage = "user " + decoded.userAuthentication.name + " has no right to access this flow";
                                        util.log(errorMessage);
                                        node.error(errorMessage, errorMessage);
                                        return res.status(401).end();
                                    }
                                }
                            }
                        })
                    }
                    else {
                        var errorMessage = "No access token received";
                        util.log(errorMessage);
                        node.error(errorMessage, errorMessage);
                        return res.status(401).end();
                    }                 
                }
                else
                    next();
            }
            if (RED.settings.httpNodeMiddleware && this.secured === "true") {
                if (typeof RED.settings.httpNodeMiddleware === "function") {
                    httpMiddleware = RED.settings.httpNodeMiddleware;
                }
            }

            var metricsHandler = function(req,res,next) { next(); }
            if (this.metric()) {
                metricsHandler = function(req, res, next) {
                    var startAt = process.hrtime();
                    onHeaders(res, function() {
                        if (res._msgid) {
                            var diff = process.hrtime(startAt);
                            var ms = diff[0] * 1e3 + diff[1] * 1e-6;
                            var metricResponseTime = ms.toFixed(3);
                            var metricContentLength = res._headers["content-length"];
                            //assuming that _id has been set for res._metrics in HttpOut node!
                            node.metric("response.time.millis", {_msgid:res._msgid} , metricResponseTime);
                            node.metric("response.content-length.bytes", {_msgid:res._msgid} , metricContentLength);
                        }
                    });
                    next();
                };
            }

            if (this.method == "get") {
                RED.httpNode.get(this.url,cookieParser(),httpMiddleware,corsHandler,metricsHandler,this.callback,this.errorHandler);
            } else if (this.method == "post") {
                RED.httpNode.post(this.url,cookieParser(),httpMiddleware,corsHandler,metricsHandler,jsonParser,urlencParser,rawBodyParser,this.callback,this.errorHandler);
            } else if (this.method == "put") {
                RED.httpNode.put(this.url,cookieParser(),httpMiddleware,corsHandler,metricsHandler,jsonParser,urlencParser,rawBodyParser,this.callback,this.errorHandler);
            } else if (this.method == "patch") {
                RED.httpNode.patch(this.url,cookieParser(),httpMiddleware,corsHandler,metricsHandler,jsonParser,urlencParser,rawBodyParser,this.callback,this.errorHandler);
            } else if (this.method == "delete") {
                RED.httpNode.delete(this.url,cookieParser(),httpMiddleware,corsHandler,metricsHandler,jsonParser,urlencParser,rawBodyParser,this.callback,this.errorHandler);
            }

            this.on("close",function() {
                var node = this;
                RED.httpNode._router.stack.forEach(function(route,i,routes) {
                    if (route.route && route.route.path === node.url && route.route.methods[node.method]) {
                        routes.splice(i,1);
                    }
                });
            });
        } else {
            this.warn(RED._("httpin.errors.not-created"));
        }
    }
    RED.nodes.registerType("secured http in",HTTPIn);


    function HTTPOut(n) {
        RED.nodes.createNode(this,n);
        var node = this;
        this.on("input",function(msg) {
            if (msg.res) {
                if (msg.headers) {
                    msg.res._res.set(msg.headers);
                }
                if (msg.cookies) {
                    for (var name in msg.cookies) {
                        if (msg.cookies.hasOwnProperty(name)) {
                            if (msg.cookies[name] === null || msg.cookies[name].value === null) {
                                if (msg.cookies[name]!==null) {
                                    msg.res._res.clearCookie(name,msg.cookies[name]);
                                } else {
                                    msg.res._res.clearCookie(name);
                                }
                            } else if (typeof msg.cookies[name] === 'object') {
                                msg.res._res.cookie(name,msg.cookies[name].value,msg.cookies[name]);
                            } else {
                                msg.res._res.cookie(name,msg.cookies[name]);
                            }
                        }
                    }
                }
                var statusCode = msg.statusCode || 200;
                if (typeof msg.payload == "object" && !Buffer.isBuffer(msg.payload)) {
                    msg.res._res.status(statusCode).jsonp(msg.payload);
                } else {
                    if (msg.res._res.get('content-length') == null) {
                        var len;
                        if (msg.payload == null) {
                            len = 0;
                        } else if (Buffer.isBuffer(msg.payload)) {
                            len = msg.payload.length;
                        } else if (typeof msg.payload == "number") {
                            len = Buffer.byteLength(""+msg.payload);
                        } else {
                            len = Buffer.byteLength(msg.payload);
                        }
                        msg.res._res.set('content-length', len);
                    }

                    if (typeof msg.payload === "number") {
                        msg.payload = ""+msg.payload;
                    }
                    msg.res._res.status(statusCode).send(msg.payload);
                }
            } else {
                node.warn(RED._("httpin.errors.no-response"));
            }
        });
    }
    RED.nodes.registerType("secured http out",HTTPOut);
}

