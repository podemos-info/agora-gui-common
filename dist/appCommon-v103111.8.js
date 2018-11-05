angular.module("avRegistration", [ "ui.bootstrap", "ui.utils", "ui.router" ]), angular.module("avRegistration").config(function() {}), 
angular.module("avRegistration").factory("Authmethod", [ "$http", "$cookies", "ConfigService", "$interval", "$location", function($http, $cookies, ConfigService, $interval, $location) {
    var backendUrl = ConfigService.authAPI, authId = ConfigService.freeAuthId, authmethod = {};
    return authmethod.captcha_code = null, authmethod.captcha_image_url = "", authmethod.captcha_status = "", 
    authmethod.admin = !1, authmethod.getAuthevent = function() {
        var adminId = ConfigService.freeAuthId + "", href = $location.path(), authevent = "", adminMatch = href.match(/^\/admin\//), boothMatch = href.match(/^\/booth\/([0-9]+)\//), electionsMatch = href.match(/^\/(elections|election)\/([0-9]+)\//);
        return _.isArray(adminMatch) ? authevent = adminId : _.isArray(boothMatch) && 2 === boothMatch.length ? authevent = boothMatch[1] : _.isArray(electionsMatch) && 3 === electionsMatch.length && (authevent = electionsMatch[2]), 
        authevent;
    }, authmethod.isAdmin = function() {
        return authmethod.isLoggedIn() && authmethod.admin;
    }, authmethod.isLoggedIn = function() {
        var auth = $http.defaults.headers.common.Authorization;
        return auth && auth.length > 0;
    }, authmethod.signup = function(data, authevent) {
        var eid = authevent || authId;
        return $http.post(backendUrl + "auth-event/" + eid + "/register/", data);
    }, authmethod.getUserInfoExtra = function() {
        if (!authmethod.isLoggedIn()) {
            var data = {
                success: function() {
                    return data;
                },
                error: function(func) {
                    return setTimeout(function() {
                        func({
                            message: "not-logged-in"
                        });
                    }, 0), data;
                }
            };
            return data;
        }
        return $http.get(backendUrl + "user/extra/", {});
    }, authmethod.getActivity = function(eid, page, size, filterOptions, filterStr, receiver_id) {
        var params = {}, url = backendUrl + "auth-event/" + eid + "/activity/";
        return "max" === size ? params.size = 500 : angular.isNumber(size) && size > 0 && 500 > size ? params.size = parseInt(size) : params.size = 10, 
        angular.isNumber(page) ? params.page = parseInt(page) : params.page = 1, angular.isNumber(receiver_id) && (params.receiver_id = receiver_id), 
        _.extend(params, filterOptions), filterStr && filterStr.length > 0 && (params.filter = filterStr), 
        $http.get(url, {
            params: params
        });
    }, authmethod.getBallotBoxes = function(eid, page, size, filterOptions, filterStr) {
        var params = {}, url = backendUrl + "auth-event/" + eid + "/ballot-box/";
        return "max" === size ? params.size = 500 : angular.isNumber(size) && size > 0 && 500 > size ? params.size = parseInt(size) : params.size = 10, 
        angular.isNumber(page) ? params.page = parseInt(page) : params.page = 1, _.extend(params, filterOptions), 
        filterStr && filterStr.length > 0 && (params.filter = filterStr), $http.get(url, {
            params: params
        });
    }, authmethod.createBallotBox = function(eid, name) {
        var params = {
            name: name
        }, url = backendUrl + "auth-event/" + eid + "/ballot-box/";
        return $http.post(url, params);
    }, authmethod.postTallySheet = function(eid, ballot_box_id, data) {
        var url = backendUrl + "auth-event/" + eid + "/ballot-box/" + ballot_box_id + "/tally-sheet/";
        return $http.post(url, data);
    }, authmethod.getTallySheet = function(eid, ballot_box_id, tally_sheet_id) {
        var url = null;
        return url = tally_sheet_id ? backendUrl + "auth-event/" + eid + "/ballot-box/" + ballot_box_id + "/tally-sheet/" + tally_sheet_id + "/" : backendUrl + "auth-event/" + eid + "/ballot-box/" + ballot_box_id + "/tally-sheet/", 
        $http.get(url);
    }, authmethod.deleteTallySheet = function(eid, ballot_box_id, tally_sheet_id) {
        var url = backendUrl + "auth-event/" + eid + "/ballot-box/" + ballot_box_id + "/tally-sheet/" + tally_sheet_id + "/";
        return $http["delete"](url, {});
    }, authmethod.deleteBallotBox = function(eid, ballot_box_id) {
        var url = backendUrl + "auth-event/" + eid + "/ballot-box/" + ballot_box_id + "/delete/";
        return $http["delete"](url, {});
    }, authmethod.updateUserExtra = function(extra) {
        if (!authmethod.isLoggedIn()) {
            var data = {
                success: function() {
                    return data;
                },
                error: function(func) {
                    return setTimeout(function() {
                        func({
                            message: "not-logged-in"
                        });
                    }, 0), data;
                }
            };
            return data;
        }
        return $http.post(backendUrl + "user/extra/", extra);
    }, authmethod.getUserInfo = function(userid) {
        if (!authmethod.isLoggedIn()) {
            var data = {
                success: function() {
                    return data;
                },
                error: function(func) {
                    return setTimeout(function() {
                        func({
                            message: "not-logged-in"
                        });
                    }, 0), data;
                }
            };
            return data;
        }
        return "undefined" == typeof userid ? $http.get(backendUrl + "user/", {}) : $http.get(backendUrl + "user/%d" % userid, {});
    }, authmethod.ping = function() {
        if (!authmethod.isLoggedIn()) {
            var data = {
                success: function() {
                    return data;
                },
                error: function(func) {
                    return setTimeout(function() {
                        func({
                            message: "not-logged-in"
                        });
                    }, 0), data;
                }
            };
            return data;
        }
        return $http.get(backendUrl + "auth-event/" + authId + "/ping/");
    }, authmethod.getImage = function(ev, uid) {
        return $http.get(backendUrl + "auth-event/" + ev + "/census/img/" + uid + "/");
    }, authmethod.login = function(data, authevent) {
        var eid = authevent || authId;
        return delete data.authevent, $http.post(backendUrl + "auth-event/" + eid + "/authenticate/", data);
    }, authmethod.censusQuery = function(data, authevent) {
        var eid = authevent || authId;
        return delete data.authevent, $http.post(backendUrl + "auth-event/" + eid + "/census/public-query/", data);
    }, authmethod.resendAuthCode = function(data, eid) {
        return $http.post(backendUrl + "auth-event/" + eid + "/resend_auth_code/", data);
    }, authmethod.getPerm = function(perm, object_type, object_id) {
        var data = {
            permission: perm,
            object_type: object_type,
            object_id: object_id + ""
        };
        return $http.post(backendUrl + "get-perms/", data);
    }, authmethod.viewEvent = function(id) {
        return $http.get(backendUrl + "auth-event/" + id + "/");
    }, authmethod.viewEvents = function() {
        return $http.get(backendUrl + "auth-event/");
    }, authmethod.createEvent = function(data) {
        return $http.post(backendUrl + "auth-event/", data);
    }, authmethod.editEvent = function(id, data) {
        return $http.post(backendUrl + "auth-event/" + id + "/", data);
    }, authmethod.addCensus = function(id, data, validation) {
        angular.isDefined(validation) || (validation = "enabled");
        var d = {
            "field-validation": validation,
            census: data
        };
        return $http.post(backendUrl + "auth-event/" + id + "/census/", d);
    }, authmethod.getCensus = function(id, params) {
        return angular.isObject(params) ? $http.get(backendUrl + "auth-event/" + id + "/census/", {
            params: params
        }) : $http.get(backendUrl + "auth-event/" + id + "/census/");
    }, authmethod.getRegisterFields = function(viewEventData) {
        var fields = _.filter(angular.copy(viewEventData.extra_fields), function(item) {
            return !0 === item.required_when_registered ? !1 : !0;
        });
        fields || (fields = []);
        var found = !1;
        _.each(fields, function(field) {
            "sms" === viewEventData.auth_method && "tlf" === field.name ? ("text" === field.type && (field.type = "tlf"), 
            found = !0) : "email" === viewEventData.auth_method && "email" === field.name && (found = !0);
        }), "sms" !== viewEventData.auth_method && "sms-otp" !== viewEventData.auth_method || found ? "email" !== viewEventData.auth_method || found ? "user-and-password" === viewEventData.auth_method ? (fields.push({
            name: "username",
            type: "text",
            required: !0,
            required_on_authentication: !0
        }), fields.push({
            name: "password",
            type: "password",
            required: !0,
            required_on_authentication: !0
        })) : "email-and-password" === viewEventData.auth_method && (fields.push({
            name: "email",
            type: "email",
            required: !0,
            required_on_authentication: !0
        }), fields.push({
            name: "password",
            type: "password",
            required: !0,
            required_on_authentication: !0
        })) : fields.push({
            name: "email",
            type: "email",
            required: !0,
            required_on_authentication: !0
        }) : fields.push({
            name: "tlf",
            type: "tlf",
            required: !0,
            required_on_authentication: !0
        });
        for (var i = 0; i < fields.length; i++) if ("captcha" === fields[i].type) {
            var captcha = fields.splice(i, 1);
            fields.push(captcha[0]);
            break;
        }
        return fields;
    }, authmethod.getCensusQueryFields = function(viewEventData) {
        var fields = angular.copy(viewEventData.extra_fields);
        return fields = _.filter(fields, function(field) {
            return field.required_on_authentication;
        });
    }, authmethod.getLoginFields = function(viewEventData) {
        var fields = authmethod.getRegisterFields(viewEventData);
        "sms" === viewEventData.auth_method || "email" === viewEventData.auth_method ? fields.push({
            name: "code",
            type: "code",
            required: !0,
            required_on_authentication: !0
        }) : "sms-otp" === viewEventData.auth_method && fields.push({
            name: "code",
            type: "code",
            required: !0,
            steps: [ 1 ],
            required_on_authentication: !0
        }), fields = _.filter(fields, function(field) {
            return field.required_on_authentication;
        });
        for (var i = 0; i < fields.length; i++) if ("captcha" === fields[i].type) {
            var captcha = fields.splice(i, 1);
            fields.push(captcha[0]);
            break;
        }
        return fields;
    }, authmethod.newCaptcha = function(message) {
        return authmethod.captcha_status = message, $http.get(backendUrl + "captcha/new/", {}).success(function(data) {
            console.log(data), null !== data.captcha_code ? (authmethod.captcha_code = data.captcha_code, 
            authmethod.captcha_image_url = data.image_url) : authmethod.captcha_status = "Not found";
        });
    }, authmethod.test = function() {
        return $http.get(backendUrl);
    }, authmethod.setAuth = function(auth, isAdmin, autheventid) {
        return authmethod.admin = isAdmin, $http.defaults.headers.common.Authorization = auth, 
        authmethod.pingTimeout || ($interval.cancel(authmethod.pingTimeout), authmethod.launchPingDaemon(autheventid), 
        authmethod.pingTimeout = $interval(function() {
            authmethod.launchPingDaemon(autheventid);
        }, 500 * ConfigService.timeoutSeconds)), !1;
    }, authmethod.electionsIds = function(page) {
        return page || (page = 1), $http.get(backendUrl + "acl/mine/?object_type=AuthEvent&perm=edit|view&order=-pk&page=" + page);
    }, authmethod.sendAuthCodes = function(eid, election, user_ids, auth_method, extra) {
        var url = backendUrl + "auth-event/" + eid + "/census/send_auth/", data = {};
        return angular.isDefined(election) && (data.msg = election.census.config.msg, "email" === auth_method && (data.subject = election.census.config.subject)), 
        angular.isDefined(user_ids) && (data["user-ids"] = user_ids), angular.isDefined(auth_method) && (data["auth-method"] = auth_method), 
        extra && (data.extra = extra), $http.post(url, data);
    }, authmethod.removeUsersIds = function(eid, election, user_ids) {
        var url = backendUrl + "auth-event/" + eid + "/census/delete/", data = {
            "user-ids": user_ids
        };
        return $http.post(url, data);
    }, authmethod.activateUsersIds = function(eid, election, user_ids, comment) {
        var url = backendUrl + "auth-event/" + eid + "/census/activate/", data = {
            "user-ids": user_ids,
            comment: comment
        };
        return $http.post(url, data);
    }, authmethod.deactivateUsersIds = function(eid, election, user_ids, comment) {
        var url = backendUrl + "auth-event/" + eid + "/census/deactivate/", data = {
            "user-ids": user_ids,
            comment: comment
        };
        return $http.post(url, data);
    }, authmethod.changeAuthEvent = function(eid, st) {
        var url = backendUrl + "auth-event/" + eid + "/" + st + "/", data = {};
        return $http.post(url, data);
    }, authmethod.launchPingDaemon = function(autheventid) {
        var postfix = "_authevent_" + autheventid;
        $cookies["isAdmin" + postfix] && authmethod.ping().success(function(data) {
            $cookies["auth" + postfix] = data["auth-token"], authmethod.setAuth($cookies["auth" + postfix], $cookies["isAdmin" + postfix], autheventid);
        });
    }, authmethod.getUserDraft = function() {
        if (!authmethod.isLoggedIn()) {
            var data = {
                success: function() {
                    return data;
                },
                error: function(func) {
                    return setTimeout(function() {
                        func({
                            message: "not-logged-in"
                        });
                    }, 0), data;
                }
            };
            return data;
        }
        return $http.get(backendUrl + "user/draft/", {});
    }, authmethod.uploadUserDraft = function(draft) {
        if (!authmethod.isLoggedIn()) {
            var data = {
                success: function() {
                    return data;
                },
                error: function(func) {
                    return setTimeout(function() {
                        func({
                            message: "not-logged-in"
                        });
                    }, 0), data;
                }
            };
            return data;
        }
        var draft_data = {
            draft_election: draft
        };
        return $http.post(backendUrl + "user/draft/", draft_data);
    }, authmethod;
} ]), angular.module("avRegistration").controller("LoginController", [ "$scope", "$stateParams", "$filter", "$i18next", "$cookies", "$window", "ConfigService", "Authmethod", function($scope, $stateParams, $filter, $i18next, $cookies, $window, ConfigService, Authmethod) {
    $scope.event_id = $stateParams.id, $scope.code = $stateParams.code, $scope.email = $stateParams.email, 
    $scope.isOpenId = $stateParams.isOpenId;
} ]), angular.module("avRegistration").directive("avLogin", [ "Authmethod", "StateDataService", "$parse", "$state", "$location", "$cookies", "$i18next", "$window", "$timeout", "ConfigService", "Patterns", function(Authmethod, StateDataService, $parse, $state, $location, $cookies, $i18next, $window, $timeout, ConfigService, Patterns) {
    function link(scope, element, attrs) {
        function isValidTel(inputName) {
            if (!document.getElementById(inputName)) return !1;
            var telInput = angular.element(document.getElementById(inputName));
            return telInput.intlTelInput("isValidNumber");
        }
        function isValidEmail(email) {
            var pattern = Patterns.get("email");
            return null !== email.match(pattern);
        }
        function randomStr() {
            var random = sjcl.random.randomWords(64, 0);
            return sjcl.codec.hex.fromBits(random);
        }
        scope.isCensusQuery = attrs.isCensusQuery;
        var adminId = ConfigService.freeAuthId + "", autheventid = scope.eventId = attrs.eventId;
        scope.orgName = ConfigService.organization.orgName, scope.openIDConnectProviders = ConfigService.openIDConnectProviders, 
        $cookies["authevent_" + adminId] && $cookies["authevent_" + adminId] === adminId && autheventid === adminId && $cookies["auth_authevent_" + adminId] && ($window.location.href = "/admin/elections"), 
        scope.sendingData = !1, scope.currentFormStep = 0, scope.stateData = StateDataService.getData(), 
        scope.signupLink = ConfigService.signupLink, scope.allowUserResend = !1, scope.censusQuery = "not-sent", 
        scope.code = null, attrs.code && attrs.code.length > 0 && (scope.code = attrs.code), 
        scope.email = null, attrs.email && attrs.email.length > 0 && (scope.email = attrs.email), 
        scope.isAdmin = !1, autheventid === adminId && (scope.isAdmin = !0), scope.resendAuthCode = function(field) {
            if (!scope.sendingData && _.contains([ "email", "sms", "sms-otp" ], scope.method)) {
                var data = {};
                if (_.contains([ "sms", "sms-otp" ], scope.method)) {
                    if (-1 === scope.telIndex) return;
                    if (!isValidTel("input" + scope.telIndex)) return;
                    data.tlf = scope.telField.value;
                } else if ("email" === scope.method) {
                    if (-1 === scope.emailIndex) return;
                    var email = scope.email;
                    if (null === email && (email = scope.login_fields[scope.emailIndex].value), !isValidEmail(email)) return;
                    data.email = email;
                }
                field && (field.value = ""), scope.sendingData = !0, Authmethod.resendAuthCode(data, autheventid).success(function(rcvData) {
                    _.contains([ "sms", "sms-otp" ], scope.method) ? scope.telField.disabled = !0 : "email" === scope.method && (scope.login_fields[scope.emailIndex].disabled = !0), 
                    scope.currentFormStep = 1, $timeout(scope.sendingDataTimeout, 3e3);
                }).error(function(error) {
                    $timeout(scope.sendingDataTimeout, 3e3), scope.error = $i18next("avRegistration.errorSendingAuthCode");
                });
            }
        }, scope.sendingDataTimeout = function() {
            scope.sendingData = !1;
        }, scope.checkCensus = function(valid) {
            if (valid && !scope.sendingData) {
                scope.censusQuery = "querying";
                var data = {
                    captcha_code: Authmethod.captcha_code
                };
                _.each(scope.login_fields, function(field) {
                    data[field.name] = field.value;
                }), scope.sendingData = !0, Authmethod.censusQuery(data, autheventid).success(function(rcvData) {
                    scope.sendingData = !1, scope.censusQueryData = rcvData, scope.censusQuery = "success";
                }).error(function(error) {
                    scope.sendingData = !1, scope.censusQuery = "fail";
                });
            }
        }, scope.loginUser = function(valid) {
            if (valid && !scope.sendingData) {
                if ("sms-otp" === scope.method && 0 === scope.currentFormStep) return void scope.resendAuthCode();
                var data = {
                    captcha_code: Authmethod.captcha_code
                };
                _.each(scope.login_fields, function(field) {
                    "email" === field.name ? scope.email = field.value : "code" === field.name && (field.value = field.value.trim().replace(/ |\n|\t|-|_/g, "").toUpperCase()), 
                    data[field.name] = field.value;
                }), scope.sendingData = !0, Authmethod.login(data, autheventid).success(function(rcvData) {
                    if ("ok" === rcvData.status) {
                        scope.khmac = rcvData.khmac;
                        var postfix = "_authevent_" + autheventid;
                        $cookies["authevent_" + autheventid] = autheventid, $cookies["userid" + postfix] = rcvData.username, 
                        $cookies["user" + postfix] = scope.email, $cookies["auth" + postfix] = rcvData["auth-token"], 
                        $cookies["isAdmin" + postfix] = scope.isAdmin, Authmethod.setAuth($cookies["auth" + postfix], scope.isAdmin, autheventid), 
                        scope.isAdmin ? Authmethod.getUserInfo().success(function(d) {
                            $cookies["user" + postfix] = d.email, $window.location.href = "/admin/elections";
                        }).error(function(error) {
                            $window.location.href = "/admin/elections";
                        }) : angular.isDefined(rcvData["redirect-to-url"]) ? $window.location.href = rcvData["redirect-to-url"] : Authmethod.getPerm("vote", "AuthEvent", autheventid).success(function(rcvData2) {
                            var khmac = rcvData2["permission-token"], path = khmac.split(";")[1], hash = path.split("/")[0], msg = path.split("/")[1];
                            $window.location.href = "/booth/" + autheventid + "/vote/" + hash + "/" + msg;
                        });
                    } else scope.sendingData = !1, scope.status = "Not found", scope.error = $i18next("avRegistration.invalidCredentials", {
                        support: ConfigService.contact.email
                    });
                }).error(function(error) {
                    scope.sendingData = !1, scope.status = "Registration error: " + error.message, scope.error = $i18next("avRegistration.invalidCredentials", {
                        support: ConfigService.contact.email
                    });
                });
            }
        }, scope.apply = function(authevent) {
            scope.method = authevent.auth_method, scope.name = authevent.name, scope.registrationAllowed = "open" === authevent.census, 
            scope.isCensusQuery ? scope.login_fields = Authmethod.getCensusQueryFields(authevent) : scope.login_fields = Authmethod.getLoginFields(authevent), 
            scope.telIndex = -1, scope.emailIndex = -1, scope.telField = null, scope.allowUserResend = function() {
                var ret = !1, href = $location.path(), adminMatch = href.match(/^\/admin\//), electionsMatch = href.match(/^\/(elections|election)\/([0-9]+)\//);
                return _.isArray(adminMatch) ? ret = !0 : _.isArray(electionsMatch) && 3 === electionsMatch.length && (ret = _.isObject(authevent.auth_method_config) && _.isObject(authevent.auth_method_config.config) && !0 === authevent.auth_method_config.config.allow_user_resend), 
                ret;
            }();
            var fields = _.map(scope.login_fields, function(el, index) {
                return scope.stateData[el.name] ? (el.value = scope.stateData[el.name], el.disabled = !0) : (el.value = null, 
                el.disabled = !1), "email" === el.type ? (null !== scope.email && (el.value = scope.email, 
                el.disabled = !0), scope.emailIndex = index) : "code" === el.type && null !== scope.code ? (el.value = scope.code.trim().replace(/ |\n|\t|-|_/g, "").toUpperCase(), 
                el.disabled = !0) : "tlf" === el.type && "sms" === scope.method ? (null !== scope.email && -1 === scope.email.indexOf("@") && (el.value = scope.email, 
                el.disabled = !0), scope.telIndex = index + 1, scope.telField = el) : "tlf" === el.type && "sms-otp" === scope.method && (null !== scope.email && -1 === scope.email.indexOf("@") && (el.value = scope.email, 
                el.disabled = !0, scope.currentFormStep = 1), scope.telIndex = index + 1, scope.telField = el), 
                el;
            }), filled_fields = _.filter(fields, function(el) {
                return null !== el.value;
            });
            filled_fields.length === scope.login_fields.length && "openid-connect" !== scope.method && scope.loginUser(!0);
        }, scope.view = function(id) {
            Authmethod.viewEvent(id).success(function(data) {
                "ok" === data.status ? scope.apply(data.events) : (scope.status = "Not found", document.querySelector(".input-error").style.display = "block");
            }).error(function(error) {
                scope.status = "Scan error: " + error.message, document.querySelector(".input-error").style.display = "block";
            });
        }, scope.view(autheventid), scope.goSignup = function() {
            $state.go("registration.register", {
                id: autheventid
            });
        }, scope.forgotPassword = function() {
            console.log("forgotPassword");
        }, scope.openidConnectAuth = function(provider) {
            var randomState = randomStr(), randomNonce = randomStr();
            if ($cookies["openid-connect-csrf"] = angular.toJson({
                randomState: randomState,
                randomNonce: randomNonce,
                created: Date.now(),
                eventId: scope.eventId,
                providerId: provider.id
            }), !provider) return void (scope.error = $i18next("avRegistration.openidError"));
            var authURI = provider.authorization_endpoint + "?response_type=id_token&client_id=" + encodeURIComponent(provider.client_id) + "&scope=" + encodeURIComponent("openid") + "&redirect_uri=" + encodeURIComponent($window.location.origin + "/election/login-openid-connect-redirect") + "&state=" + randomState + "&nonce=" + randomNonce;
            $window.location.href = authURI;
        };
    }
    return {
        restrict: "AE",
        scope: !0,
        link: link,
        templateUrl: "avRegistration/login-directive/login-directive.html"
    };
} ]), angular.module("avRegistration").directive("avOpenidConnect", [ "$cookies", "$window", "$location", "ConfigService", "Authmethod", function($cookies, $window, $location, ConfigService, Authmethod) {
    function link(scope, element, attrs) {
        function redirectToLogin() {
            var eventId = null;
            scope.csrf && (eventId = scope.csrf.eventId), eventId ? $window.location.href = "/election/" + eventId + "/public/login" : $window.location.href = "/";
        }
        function validateCsrfToken() {
            if (!$cookies["openid-connect-csrf"]) return redirectToLogin(), null;
            var csrf = scope.csrf = angular.fromJson($cookies["openid-connect-csrf"]), uri = "?" + $window.location.hash.substr(1);
            $cookies["openid-connect-csrf"] = null;
            var isCsrfValid = !!csrf && angular.isObject(csrf) && angular.isString(csrf.randomState) && angular.isString(csrf.randomNonce) && angular.isNumber(csrf.created) && getURIParameter("state", uri) === csrf.randomState && csrf.created - Date.now() < maxOAuthLoginTimeout;
            return isCsrfValid ? !0 : (redirectToLogin(), null);
        }
        function getURIParameter(paramName, uri) {
            var paramName2 = paramName.replace(/[\[\]]/g, "\\$&"), rx = new RegExp("[?&]" + paramName2 + "(=([^&#]*)|&|#|$)"), params = rx.exec(uri);
            return params ? params[2] ? decodeURIComponent(params[2].replace(/\+/g, " ")) : "" : null;
        }
        function processOpenIdAuthCallback() {
            validateCsrfToken();
            var uri = "?" + $window.location.hash.substr(1), data = {
                id_token: getURIParameter("id_token", uri),
                provider: scope.csrf.providerId,
                nonce: scope.csrf.randomNonce
            }, postfix = "_authevent_" + scope.csrf.eventId;
            $cookies["id_token_" + postfix] = data.id_token, Authmethod.login(data, scope.csrf.eventId).success(function(rcvData) {
                if ("ok" !== rcvData.status) return void redirectToLogin();
                scope.khmac = rcvData.khmac;
                var postfix = "_authevent_" + scope.csrf.eventId;
                $cookies["authevent_" + scope.csrf.eventId] = scope.csrf.eventId, $cookies["userid" + postfix] = rcvData.username, 
                $cookies["user" + postfix] = rcvData.username, $cookies["auth" + postfix] = rcvData["auth-token"], 
                $cookies["isAdmin" + postfix] = !1, Authmethod.setAuth($cookies["auth" + postfix], scope.isAdmin, scope.csrf.eventId), 
                angular.isDefined(rcvData["redirect-to-url"]) ? $window.location.href = rcvData["redirect-to-url"] : Authmethod.getPerm("vote", "AuthEvent", scope.csrf.eventId).success(function(rcvData2) {
                    var khmac = rcvData2["permission-token"], path = khmac.split(";")[1], hash = path.split("/")[0], msg = path.split("/")[1];
                    $window.location.href = "/booth/" + scope.csrf.eventId + "/vote/" + hash + "/" + msg;
                });
            }).error(function(error) {
                redirectToLogin();
            });
        }
        var maxOAuthLoginTimeout = 3e5;
        scope.csrf = null, processOpenIdAuthCallback();
    }
    return {
        restrict: "AE",
        scope: !0,
        link: link,
        templateUrl: "avRegistration/openid-connect-directive/openid-connect-directive.html"
    };
} ]), angular.module("avRegistration").controller("LogoutController", [ "$scope", "$stateParams", "$filter", "ConfigService", "$i18next", "$state", "$cookies", "Authmethod", function($scope, $stateParams, $filter, ConfigService, $i18next, $state, $cookies, Authmethod) {
    var authevent = (ConfigService.freeAuthId, Authmethod.getAuthevent()), postfix = "_authevent_" + authevent;
    $cookies["user" + postfix] = "", $cookies["auth" + postfix] = "", $cookies["authevent_" + authevent] = "", 
    $cookies["userid" + postfix] = "", $cookies["isAdmin" + postfix] = !1, authevent !== ConfigService.freeAuthId + "" && authevent ? $state.go("registration.login", {
        id: $cookies["authevent_" + authevent]
    }) : $state.go("admin.login");
} ]), angular.module("avRegistration").controller("RegisterController", [ "$scope", "$stateParams", "$filter", "ConfigService", "$i18next", function($scope, $stateParams, $filter, ConfigService, $i18next) {
    $scope.event_id = $stateParams.id, $scope.email = $stateParams.email;
} ]), angular.module("avRegistration").directive("avRegister", [ "Authmethod", "StateDataService", "$parse", "$state", "ConfigService", "$cookies", "$i18next", "$sce", function(Authmethod, StateDataService, $parse, $state, ConfigService, $cookies, $i18next, $sce) {
    function link(scope, element, attrs) {
        var autheventid = attrs.eventId;
        scope.dnieurl = ConfigService.dnieUrl + autheventid + "/", scope.register = {}, 
        scope.sendingData = !1, scope.admin = !1, scope.email = null, attrs.email && attrs.email.length > 0 && (scope.email = attrs.email), 
        "admin" in attrs && (scope.admin = !0), scope.getLoginDetails = function(eventId) {
            return scope.admin ? {
                path: "admin.login_email",
                data: {
                    email: scope.email
                }
            } : {
                path: "election.public.show.login_email",
                data: {
                    id: eventId,
                    email: scope.email
                }
            };
        }, scope.signUp = function(valid) {
            if (valid) {
                scope.sendingData = !0;
                var data = {
                    captcha_code: Authmethod.captcha_code
                };
                _.each(scope.register_fields, function(field) {
                    data[field.name] = field.value, "email" === field.name && "email" === scope.method ? scope.email = field.value : "tlf" === field.name && _.contains([ "sms", "sms-otp" ], scope.method) && (scope.email = field.value);
                });
                var details;
                Authmethod.signup(data, autheventid).success(function(rcvData) {
                    details = scope.getLoginDetails(autheventid), "ok" === rcvData.status ? (scope.user = rcvData.user, 
                    StateDataService.go(details.path, details.data, data), scope.error = rcvData.msg || $sce.trustAsHtml($i18next("avRegistration.invalidRegisterData", {
                        url: $state.href(details.path, details.data)
                    }))) : (scope.sendingData = !1, scope.status = "Not found", scope.error = rcvData.msg || $sce.trustAsHtml($i18next("avRegistration.invalidRegisterData", {
                        url: $state.href(details.path, details.data)
                    })));
                }).error(function(error) {
                    details = scope.getLoginDetails(autheventid), scope.sendingData = !1, scope.status = "Registration error: " + error.message, 
                    error.error_codename && "invalid-dni" === error.error_codename ? scope.error = $sce.trustAsHtml($i18next("avRegistration.invalidRegisterDNI")) : (scope.error = error.msg || $sce.trustAsHtml($i18next("avRegistration.invalidRegisterData", {
                        url: $state.href(details.path, details.data)
                    })), "Invalid captcha" === error.msg && Authmethod.newCaptcha());
                });
            }
        }, scope.goLogin = function(event) {
            console.log("goLogin"), event && (event.preventDefault(), event.stopPropagation()), 
            scope.authevent && (scope.authevent.id === ConfigService.freeAuthId ? $state.go("admin.login") : $state.go("election.public.show.login", {
                id: scope.authevent.id
            }));
        }, scope.apply = function(authevent) {
            scope.method = authevent.auth_method, scope.name = authevent.name, scope.authevent = authevent, 
            ("open" !== authevent.census || "openid-connect" === scope.method) && (authevent.id === ConfigService.freeAuthId ? $state.go("admin.login") : $state.go("election.public.show.login", {
                id: authevent.id
            })), scope.register_fields = Authmethod.getRegisterFields(authevent);
            _.map(scope.register_fields, function(el) {
                return el.value = null, el.disabled = !1, "email" === el.type && null !== scope.email && (el.value = scope.email, 
                el.disabled = !0), el;
            });
        }, scope.view = function(id) {
            Authmethod.viewEvent(id).success(function(data) {
                "ok" === data.status ? scope.apply(data.events) : (scope.status = "Not found", document.querySelector(".input-error").style.display = "block");
            }).error(function(error) {
                scope.status = "Scan error: " + error.message, document.querySelector(".input-error").style.display = "block";
            });
        }, scope.view(autheventid);
    }
    return {
        restrict: "AE",
        scope: !0,
        link: link,
        templateUrl: "avRegistration/register-directive/register-directive.html"
    };
} ]), angular.module("avRegistration").factory("Patterns", function() {
    var patterns = {};
    return patterns.get = function(name) {
        return "dni" === name ? /^\d{7,8}[a-zA-Z]{1}$/i : "mail" === name || "email" === name ? /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/ : /.*/;
    }, patterns;
}), angular.module("avRegistration").directive("avrField", [ "$state", function($state) {
    function link(scope, element, attrs) {
        console.log("type = " + scope.field.type), scope.index = attrs.index;
    }
    return {
        restrict: "AE",
        scope: !0,
        link: link,
        templateUrl: "avRegistration/field-directive/field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrEmailField", [ "$state", "Patterns", function($state, Patterns) {
    function link(scope, element, attrs) {
        scope.patterns = function(name) {
            return Patterns.get(name);
        };
    }
    return {
        restrict: "AE",
        link: link,
        scope: !0,
        templateUrl: "avRegistration/fields/email-field-directive/email-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrDateField", [ "$state", "Patterns", function($state, Patterns) {
    function link(scope, element, attrs) {
        scope.years = [], scope.months = [], scope.field = scope.$parent.field;
        var now = new Date();
        scope.date = {
            year: now.getFullYear(),
            month: now.getMonth() + 1,
            day: now.getDate()
        };
        var initY = new Date().getFullYear(), i = 0;
        for (i = initY; i >= initY - 130; i--) scope.years.push(i);
        for (i = 1; 12 >= i; i++) scope.months.push(i);
        scope.getDays = function() {
            var days = [], ndays = new Date(scope.date.year, scope.date.month, 0).getDate();
            for (i = 1; ndays >= i; i++) days.push(i);
            return days;
        }, scope.onChange = function() {
            scope.ngModel = scope.date.year + "-" + scope.date.month + "-" + scope.date.day;
        };
    }
    return {
        restrict: "AE",
        link: link,
        scope: {
            ngModel: "=",
            label: "="
        },
        templateUrl: "avRegistration/fields/date-field-directive/date-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrPasswordField", [ "$state", function($state) {
    return {
        restrict: "AE",
        scope: !0,
        templateUrl: "avRegistration/fields/password-field-directive/password-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrTextField", [ "$state", function($state) {
    function link(scope, element, attrs) {
        angular.isUndefined(scope.field.regex) ? scope.re = new RegExp("") : scope.re = new RegExp(scope.field.regex), 
        scope.getRe = function(value) {
            return scope.re;
        };
    }
    return {
        restrict: "AE",
        link: link,
        scope: !0,
        templateUrl: "avRegistration/fields/text-field-directive/text-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrDniField", [ "$state", function($state) {
    function link(scope, element, attrs) {
        function normalize_dni(dni) {
            if (!dni) return "";
            for (var allowed_chars = "QWERTYUIOPASDFGHJKLZXCVBNM1234567890", dni2 = dni.toUpperCase(), dni3 = "", i = 0; i < dni2.lenth; i++) {
                var char = dni2[i];
                allowed_chars.indexOf(char) >= 0 && (dni3 += char);
            }
            for (var last_char = "", dni4 = "", i = 0; i < dni3.lenth; i++) {
                var char = dni3[i];
                ("" === last_char || -1 === "1234567890".indexOf(last_char)) && "0" === c, dni4 += char, 
                last_char = char;
            }
            return dni4;
        }
        var dni_re = /^([0-9]{1,8}[A-Z]|[LMXYZ][0-9]{1,7}[A-Z])$/;
        scope.validateDni = function(dni) {
            var norm_dni = normalize_dni(dni);
            if (!norm_dni.match(dni_re)) return !0;
            var prefix = norm_dni.charAt(0), index = "LMXYZ".indexOf(prefix), niePrefix = 0;
            index > -1 && (niePrefix = index, norm_dni = norm_dni.substr(1), "Y" === prefix ? norm_dni = "1" + norm_dni : "Z" === prefix && (norm_dni = "2" + norm_dni));
            var dni_letters = "TRWAGMYFPDXBNJZSQVHLCKE", letter = dni_letters.charAt(parseInt(norm_dni, 10) % 23);
            return letter === norm_dni.charAt(norm_dni.length - 1);
        };
    }
    return {
        restrict: "AE",
        link: link,
        scope: !0,
        templateUrl: "avRegistration/fields/dni-field-directive/dni-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrCodeField", [ "$state", "Plugins", function($state, Plugins) {
    function link(scope, element, attrs) {
        scope.codePattern = /[abcdefghjklmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-]{8,9}/;
        var rand_code = "" + _.random(1e12);
        if (scope.code_id = "input" + scope.index + rand_code, scope.showResendAuthCode = function() {
            var data = {
                showUserSendAuthCode: !0
            };
            return Plugins.hook("hide-user-send-auth-code", data), data.showUserSendAuthCode;
        }, "sms" === scope.method || "sms-otp" === scope.method) {
            var telInput = angular.element(document.getElementById("input" + scope.telIndex));
            scope.isValidTel = telInput.intlTelInput("isValidNumber"), scope.$watch("telField.value", function(newValue, oldValue) {
                scope.isValidTel = telInput.intlTelInput("isValidNumber");
            }, !0);
        }
    }
    return {
        restrict: "AE",
        scope: !0,
        link: link,
        templateUrl: "avRegistration/fields/code-field-directive/code-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrTelField", [ "$state", "$timeout", function($state, $timeout) {
    function link(scope, element, attrs) {
        scope.tlfPattern = /^[+]?\d{9,14}$/, scope.isValidNumber = !0;
        var ipData = null, ipCallbacks = [];
        $.get("https://ipinfo.io", function() {}, "jsonp").always(function(resp) {
            ipData = resp;
            for (var i = 0; i < ipCallbacks.length; i++) ipCallbacks[i]();
        }), $timeout(function() {
            var telInput = angular.element(document.getElementById("input" + scope.index));
            telInput.intlTelInput({
                utilsScript: "election/utils.js",
                separateDialCode: !0,
                initialCountry: "auto",
                preferredCountries: [ "es", "gb", "us" ],
                autoPlaceholder: "aggressive",
                placeholderNumberType: "MOBILE",
                geoIpLookup: function(callback) {
                    var applyCountry = function() {
                        var countryCode = ipData && ipData.country ? ipData.country : "es";
                        callback(countryCode);
                    };
                    ipData ? applyCountry() : ipCallbacks.push(applyCountry);
                }
            }), _.isString(scope.field.value) && 0 < scope.field.value.length && telInput.intlTelInput("setNumber", scope.field.value);
            var validateTel = function() {
                scope.$evalAsync(function() {
                    var intlNumber = telInput.intlTelInput("getNumber");
                    intlNumber && (scope.field.value = intlNumber);
                    var isValid = telInput.intlTelInput("isValidNumber");
                    !isValid && $("#input" + scope.index).val().replace("[ 	\n]", "").length > 0 ? (telInput.toggleClass("error", !0), 
                    scope.isValidNumber = !1) : (telInput.toggleClass("error", !1), scope.isValidNumber = !0);
                });
            };
            telInput.on("keyup change", validateTel);
        });
    }
    return {
        restrict: "AE",
        scope: !0,
        link: link,
        templateUrl: "avRegistration/fields/tel-field-directive/tel-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrBoolField", [ "$state", function($state) {
    return {
        restrict: "AE",
        scope: !0,
        templateUrl: "avRegistration/fields/bool-field-directive/bool-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrIntField", [ "$state", function($state) {
    function link(scope, element, attrs) {
        angular.isUndefined(scope.field.regex) ? scope.re = new RegExp("") : scope.re = new RegExp(scope.field.regex), 
        scope.getRe = function(value) {
            return scope.re;
        };
    }
    return {
        restrict: "AE",
        link: link,
        scope: !0,
        templateUrl: "avRegistration/fields/int-field-directive/int-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrCaptchaField", [ "Authmethod", "$state", "$interval", function(Authmethod, $state, $interval) {
    function link(scope, element, attrs) {
        scope.authMethod = Authmethod, Authmethod.newCaptcha("");
    }
    return {
        restrict: "AE",
        scope: !0,
        link: link,
        templateUrl: "avRegistration/fields/captcha-field-directive/captcha-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrTextareaField", [ "$state", function($state) {
    return {
        restrict: "AE",
        scope: !0,
        templateUrl: "avRegistration/fields/textarea-field-directive/textarea-field-directive.html"
    };
} ]), angular.module("avRegistration").directive("avrImageField", [ "$state", "$timeout", function($state, $timeout) {
    function link(scope, element, attrs) {
        function readImage(input) {
            if (input.files && input.files[0]) {
                var FR = new FileReader();
                FR.onload = function(e) {
                    scope.field.value = e.target.result;
                }, FR.readAsDataURL(input.files[0]);
            }
        }
        $timeout(function() {
            $("#image-field").change(function() {
                readImage(this);
            });
        }, 0);
    }
    return {
        restrict: "AE",
        link: link,
        scope: !0,
        templateUrl: "avRegistration/fields/image-field-directive/image-field-directive.html"
    };
} ]), angular.module("avRegistration").factory("Plugins", function() {
    var plugins = {};
    return plugins.plugins = {
        list: []
    }, plugins.signals = $.Callbacks("unique"), plugins.hooks = [], plugins.add = function(plugin) {
        plugins.plugins.list.push(plugin);
    }, plugins.clear = function() {
        plugins.plugins.list = [];
    }, plugins.remove = function(plugin) {
        var pluginList = plugins.plugins.list;
        plugins.plugins.list = [], pluginList.forEach(function(pluginFromList) {
            plugin.name !== pluginFromList.name && plugins.plugins.list.push(pluginFromList);
        });
    }, plugins.emit = function(signalName, data) {
        plugins.signals.fire(signalName, data);
    }, plugins.hook = function(hookname, data) {
        for (var i = 0; i < plugins.hooks.length; i++) {
            var h = plugins.hooks[i], ret = h(hookname, data);
            if (!ret) return !1;
        }
        return !0;
    }, plugins;
}), angular.module("avRegistration").directive("avPluginHtml", [ "$compile", "$sce", "$parse", function($compile, $sce, $parse) {
    return function(scope, element, attrs) {
        var parsedHtml = $parse(attrs.ngBindHtml);
        scope.$watch(function() {
            return (parsedHtml(scope) || "").toString();
        }, function() {
            $compile(element, null, -9999)(scope);
        });
    };
} ]), angular.module("avUi", []), jQuery.fn.flash = function(duration) {
    var selector = this;
    angular.isNumber(duration) || (duration = 300), "true" !== selector.attr("is-flashing") && (selector.attr("is-flashing", "true"), 
    selector.addClass("flashing").delay(duration).queue(function() {
        selector.removeClass("flashing").addClass("flashing-out").dequeue();
    }).delay(duration).queue(function() {
        selector.removeClass("flashing flashing-out").dequeue(), selector.attr("is-flashing", "false");
    }));
}, angular.module("avUi").directive("avSimpleError", [ "$resource", "$window", function($resource, $window) {
    function link(scope, element, attrs) {
        scope.updateTitle = function() {
            var title = element.find(".av-simple-error-title"), marginTop = -title.height() - 45, marginLeft = -title.width() / 2;
            title.attr("style", "margin-top: " + marginTop + "px; margin-left: " + marginLeft + "px");
        }, scope.$watch(attrs.title, function() {
            scope.updateTitle();
        });
    }
    return {
        restrict: "AE",
        scope: {},
        link: link,
        transclude: !0,
        templateUrl: "avUi/simple-error-directive/simple-error-directive.html"
    };
} ]), angular.module("avUi").directive("avChangeLang", [ "$i18next", "ipCookie", "angularLoad", "amMoment", "ConfigService", function($i18next, ipCookie, angularLoad, amMoment, ConfigService) {
    function link(scope, element, attrs) {
        scope.deflang = window.i18n.lng(), angular.element("#ng-app").attr("lang", scope.deflang), 
        scope.langs = $i18next.options.lngWhitelist, scope.changeLang = function(lang) {
            $i18next.options.lng = lang, console.log("setting cookie");
            var cookieConf = {
                expires: 360,
                path: "/"
            };
            ipCookie("lang", lang, _.extend(cookieConf, ConfigService.i18nextCookieOptions)), 
            scope.deflang = lang, angular.element("#ng-app").attr("lang", scope.deflang), angularLoad.loadScript(ConfigService.base + "/locales/moment/" + lang + ".js").then(function() {
                amMoment.changeLocale(lang);
            });
        };
    }
    return {
        restrict: "AE",
        scope: {},
        link: link,
        templateUrl: "avUi/change-lang-directive/change-lang-directive.html"
    };
} ]), angular.module("avUi").directive("avAffixBottom", [ "$window", "$timeout", "$parse", function($window, $timeout, $parse) {
    var affixBottomClass = "affix-bottom", checkPosition = function(scope, instance, el, options) {
        var affix = !1, elHeight = $(el).actual("height");
        ($("body").height() + elHeight > window.innerHeight || instance.forceAffixWidth && window.innerWidth < instance.forceAffixWidth) && (affix = affixBottomClass), 
        instance.affixed !== affix && (instance.affix = affix, instance.setIsAffix(scope, affix), 
        el.removeClass("hidden"), affix ? (el.addClass(affixBottomClass), $(el).parent().css("margin-bottom", elHeight + "px")) : (el.removeClass(affixBottomClass), 
        $(el).parent().css("margin-bottom", instance.defaultBottomMargin)));
    };
    return {
        restrict: "EAC",
        link: function(scope, iElement, iAttrs) {
            function callCheckPos() {
                timeout = $timeout(function() {
                    $timeout.cancel(timeout), checkPosition(scope, instance, iElement, iAttrs);
                }, 100);
            }
            var instance = {
                affix: !1,
                getIsAffix: null,
                setIsAffix: angular.noop,
                defaultBottomMargin: iElement.css("margin-bottom"),
                forceAffixWidth: parseInt(iAttrs.forceAffixWidth, 10)
            };
            iAttrs.avAffixBottom.length > 0 && (instance.getIsAffix = $parse(iAttrs.avAffixBottom), 
            instance.setIsAffix = instance.getIsAffix.assign);
            var timeout;
            callCheckPos(), angular.element($window).on("resize", callCheckPos), angular.element(document.body).on("resize", callCheckPos), 
            console.log("iElement NOT resize, height = " + iElement.height()), angular.element(iElement).on("resize", callCheckPos);
        }
    };
} ]), angular.module("avUi").directive("avAutoHeight", [ "$window", "$timeout", function($window, $timeout) {
    return {
        link: function(scope, element, attrs) {
            var sibling, recalculate, promise = null;
            sibling = function() {
                return element.closest(attrs.parentSelector).find(attrs.siblingSelector);
            }, recalculate = function() {
                promise && $timeout.cancel(promise), promise = $timeout(function() {
                    var height, additionalHeight = 0;
                    attrs.additionalHeight && (additionalHeight = parseInt(attrs.additionalHeight, 10)), 
                    height = sibling().height(), element.css("max-height", height + additionalHeight + "px");
                }, 100);
            }, scope.$watch(function() {
                return sibling().height();
            }, function(newValue, oldValue) {
                recalculate();
            }), recalculate();
        }
    };
} ]), angular.module("avUi").directive("avAffixTopOffset", [ "$window", "$timeout", "$parse", function($window, $timeout, $parse) {
    var affixClass = "affix-top", checkPosition = function(scope, instance, el, options) {
        var affix = !1, offset = el.offset();
        instance.affix && $window.pageYOffset + 20 >= instance.scrollAffix || (offset.top - $window.pageYOffset < instance.avAffixTopOffset && (affix = !0), 
        instance.affix !== affix && (instance.affix = affix, instance.scrollAffix = $window.pageYOffset, 
        affix ? (el.addClass(affixClass), el.data("page-offset", $window.pageYOffset), el.css("position", "fixed"), 
        el.css("float", "none"), el.css("top", Math.floor(instance.avAffixTopOffset) + "px"), 
        el.css("left", Math.floor(instance.baseOffset.left) + "px"), el.css("width", Math.floor(instance.baseWidth) + "px"), 
        el.css("z-index", "10"), void 0 !== options.affixPlaceholder && $(options.affixPlaceholder).addClass("affixed")) : (el.removeClass(affixClass), 
        el.attr("style", ""), void 0 !== options.affixPlaceholder && $(options.affixPlaceholder).removeClass("affixed"))));
    };
    return {
        restrict: "EAC",
        link: function(scope, iElement, iAttrs) {
            function callCheckPos() {
                checkPosition(scope, instance, iElement, iAttrs);
            }
            function resize() {
                iElement.removeClass(affixClass), iElement.attr("style", ""), instance.affix = !1, 
                instance.scrollAffix = null, $timeout(function() {
                    instance.baseOffset = iElement.offset(), instance.baseWidth = iElement.width(), 
                    callCheckPos();
                }, 100);
            }
            var instance = {
                affix: !1,
                scrollAffix: null,
                baseOffset: iElement.offset(),
                baseWidth: iElement.width(),
                avAffixTopOffset: parseInt(iAttrs.avAffixTopOffset, 10)
            };
            callCheckPos(), angular.element($window).on("scroll", callCheckPos), angular.element($window).on("resize", resize);
        }
    };
} ]), angular.module("avUi").directive("avAffixTop", [ "$window", "$timeout", function($window, $timeout) {
    var updateMargin = function(el, options) {
        var minHeight = parseInt(options.minHeight), height = Math.max($(el).height(), angular.isNumber(minHeight) && !isNaN(minHeight) ? minHeight : 0);
        $(options.avAffixTop).css("padding-top", height + "px");
    };
    return {
        restrict: "EAC",
        link: function(scope, iElement, iAttrs) {
            function updateMarginTimeout() {
                timeout = $timeout(function() {
                    $timeout.cancel(timeout), updateMargin(iElement, iAttrs);
                }, 100);
            }
            updateMargin(iElement, iAttrs), void 0 === iAttrs.minHeight && (iAttrs.minHeight = "20");
            var timeout;
            angular.element(iElement).bind("resize", updateMarginTimeout), angular.element($window).bind("resize", updateMarginTimeout), 
            $(iAttrs.avAffixTop).change(updateMarginTimeout);
        }
    };
} ]), angular.module("avUi").directive("avCollapsing", [ "$window", "$timeout", function($window, $timeout) {
    function collapseEl(instance, el) {
        var val = null;
        return val = instance.collapseSelector ? select(instance, el, instance.collapseSelector) : angular.element(el);
    }
    function select(instance, el, selector) {
        var val;
        return val = instance.parentSelector ? el.closest(instance.parentSelector).find(selector) : angular.element(selector);
    }
    var checkCollapse = function(instance, el, options) {
        var maxHeight = select(instance, el, instance.maxHeightSelector).css("max-height"), height = angular.element(el)[0].scrollHeight;
        if (-1 === maxHeight.indexOf("px")) return void console.log("invalid non-pixels max-height for " + instance.maxHeightSelector);
        if (maxHeight = parseInt(maxHeight.replace("px", "")), height > maxHeight) {
            if (instance.isCollapsed) return;
            instance.isCollapsed = !0, collapseEl(instance, el).addClass("collapsed"), select(instance, el, instance.toggleSelector).removeClass("hidden in");
        } else {
            if (!instance.isCollapsed) return;
            instance.isCollapsed = !1, collapseEl(instance, el).removeClass("collapsed"), select(instance, el, instance.toggleSelector).addClass("hidden");
        }
    }, toggleCollapse = function(instance, el, options) {
        instance.isCollapsed ? (collapseEl(instance, el).removeClass("collapsed"), select(instance, el, instance.toggleSelector).addClass("in")) : (collapseEl(instance, el).addClass("collapsed"), 
        select(instance, el, instance.toggleSelector).removeClass("in")), instance.isCollapsed = !instance.isCollapsed;
    };
    return {
        restrict: "EAC",
        link: function(scope, iElement, iAttrs) {
            function callCheck() {
                timeout = $timeout(function() {
                    $timeout.cancel(timeout), checkCollapse(instance, iElement, iAttrs);
                }, 100);
            }
            function launchToggle() {
                toggleCollapse(instance, iElement, iAttrs);
            }
            var timeout, instance = {
                isCollapsed: !1,
                maxHeightSelector: iAttrs.avCollapsing,
                toggleSelector: iAttrs.toggleSelector,
                parentSelector: iAttrs.parentSelector,
                collapseSelector: iAttrs.collapseSelector
            };
            callCheck(), angular.element($window).bind("resize", callCheck), angular.element(iElement).bind("resize", callCheck), 
            angular.element(instance.toggleSelector).bind("click", launchToggle);
        }
    };
} ]), angular.module("avUi").directive("avRecompile", [ "$compile", "$parse", function($compile, $parse) {
    "use strict";
    function getElementAsHtml(el) {
        return angular.element("<a></a>").append(el.clone()).html();
    }
    return {
        scope: !0,
        compile: function(el) {
            var template = getElementAsHtml(el);
            return function(scope, $el, attrs) {
                var stopWatching = scope.$parent.$watch(attrs.avRecompile, function(_new, _old) {
                    var useBoolean = attrs.hasOwnProperty("useBoolean");
                    if ((!useBoolean || _new && "false" !== _new) && (useBoolean || _new && _new !== _old)) {
                        useBoolean && $parse(attrs.kcdRecompile).assign(scope.$parent, !1);
                        var newEl = $compile(template)(scope.$parent);
                        $el.replaceWith(newEl), stopWatching(), scope.$destroy();
                    }
                });
            };
        }
    };
} ]), angular.module("avUi").directive("avDebounce", [ "$timeout", function($timeout) {
    return {
        restrict: "A",
        require: "ngModel",
        priority: 99,
        link: function(scope, elm, attr, ngModelCtrl) {
            if ("radio" !== attr.type && "checkbox" !== attr.type) {
                elm.unbind("input");
                var debounce;
                elm.bind("input", function() {
                    $timeout.cancel(debounce), debounce = $timeout(function() {
                        scope.$apply(function() {
                            ngModelCtrl.$setViewValue(elm.val());
                        });
                    }, attr.avDebounce || 500);
                }), elm.bind("blur", function() {
                    scope.$apply(function() {
                        ngModelCtrl.$setViewValue(elm.val());
                    });
                });
            }
        }
    };
} ]), angular.module("avUi").service("InsideIframeService", function() {
    return function() {
        try {
            return window.self !== window.top;
        } catch (e) {
            return !0;
        }
    };
}), angular.module("avUi").service("PercentVotesService", function() {
    return function(total_votes, question, over, format) {
        function print(num) {
            return "str" === format ? num.toFixed(2) + "%" : num;
        }
        if (void 0 === format && (format = "str"), 0 === total_votes) return print(0);
        var base = question.totals.valid_votes + question.totals.null_votes + question.totals.blank_votes;
        return (void 0 === over || null === over) && (over = question.answer_total_votes_percentage), 
        "over-valid-votes" === over || "over-total-valid-votes" === over ? base = question.totals.valid_votes : "over-total-valid-points" === over && void 0 !== question.totals.valid_points && (base = question.totals.valid_points), 
        print(100 * total_votes / base);
    };
}), angular.module("avUi").service("CheckerService", function() {
    function checker(d) {
        function evalValue(code, $value) {
            return angular.isString(code) ? eval(code) : code;
        }
        function sumStrs(str1, str2) {
            var ret = "";
            return angular.isString(str1) && (ret = str1), angular.isString(str2) && (ret += str2), 
            ret;
        }
        function error(errorKey, errorData, postfix) {
            angular.extend(errorData, d.errorData), d.onError(_.reduce([ d.prefix, errorKey, postfix ], sumStrs, ""), errorData);
        }
        angular.isUndefined(d.errorData) && (d.errorData = {});
        var ret = _.every(d.checks, function(item) {
            var itemMin, itemMax, max, min, pass = !0;
            if ("is-int" === item.check) pass = angular.isNumber(d.data[item.key], item.postfix), 
            pass || error(item.check, {
                key: item.key
            }, item.postfix); else if ("is-array" === item.check) pass = angular.isArray(d.data[item.key], item.postfix), 
            pass || error(item.check, {
                key: item.key
            }, item.postfix); else if ("lambda" === item.check) {
                if (!item.validator(d.data[item.key])) {
                    var errorData = {
                        key: item.key
                    };
                    angular.isUndefined(item.appendOnErrorLambda) || (errorData = item.appendOnErrorLambda(d.data[item.key])), 
                    _.isObject(item.append) && _.isString(item.append.key) && !_.isUndefined(item.append.value) && (errorData[item.append.key] = evalValue(item.append.value, item)), 
                    error(item.check, errorData, item.postfix);
                }
            } else if ("is-string-if-defined" === item.check) pass = angular.isUndefined(d.data[item.key]) || angular.isString(d.data[item.key], item.postfix), 
            pass || error(item.check, {
                key: item.key
            }, item.postfix); else if ("array-length-if-defined" === item.check) {
                if (angular.isDefined(d.data[item.key]) && (itemMin = evalValue(item.min, d.data), 
                itemMax = evalValue(item.max, d.data), (angular.isArray(d.data[item.key]) || angular.isString(d.data[item.key])) && (min = angular.isUndefined(item.min) || d.data[item.key].length >= itemMin, 
                max = angular.isUndefined(item.max) || d.data[item.key].length <= itemMax, pass = min && max, 
                min || error("array-length-min", {
                    key: item.key,
                    min: itemMin,
                    num: d.data[item.key].length
                }, item.postfix), !max))) {
                    var itemErrorData0 = {
                        key: item.key,
                        max: itemMax,
                        num: d.data[item.key].length
                    };
                    error("array-length-max", itemErrorData0, item.postfix);
                }
            } else if ("is-string" === item.check) pass = angular.isString(d.data[item.key], item.postfix), 
            pass || error(item.check, {
                key: item.key
            }, item.postfix); else if ("array-length" === item.check) {
                if (itemMin = evalValue(item.min, d.data), itemMax = evalValue(item.max, d.data), 
                (angular.isArray(d.data[item.key]) || angular.isString(d.data[item.key])) && (min = angular.isUndefined(item.min) || d.data[item.key].length >= itemMin, 
                max = angular.isUndefined(item.max) || d.data[item.key].length <= itemMax, pass = min && max, 
                min || error("array-length-min", {
                    key: item.key,
                    min: itemMin,
                    num: d.data[item.key].length
                }, item.postfix), !max)) {
                    var itemErrorData = {
                        key: item.key,
                        max: itemMax,
                        num: d.data[item.key].length
                    };
                    error("array-length-max", itemErrorData, item.postfix);
                }
            } else if ("int-size" === item.check) itemMin = evalValue(item.min, d.data), itemMax = evalValue(item.max, d.data), 
            min = angular.isUndefined(item.min) || d.data[item.key] >= itemMin, max = angular.isUndefined(item.max) || d.data[item.key] <= itemMax, 
            pass = min && max, min || error("int-size-min", {
                key: item.key,
                min: itemMin,
                value: d.data[item.key]
            }, item.postfix), max || error("int-size-max", {
                key: item.key,
                max: itemMax,
                value: d.data[item.key]
            }, item.postfix); else if ("group-chain" === item.check) pass = _.all(_.map(item.checks, function(check) {
                return checker({
                    data: d.data,
                    errorData: d.errorData,
                    onError: d.onError,
                    checks: [ check ],
                    prefix: sumStrs(d.prefix, item.prefix)
                });
            })); else if ("array-key-group-chain" === item.check) pass = _.every(d.data[item.key], function(data, index) {
                var extra = {}, prefix = "";
                return angular.isString(d.prefix) && (prefix = d.prefix), angular.isString(item.prefix) && (prefix += item.prefix), 
                extra.prefix = prefix, extra[item.append.key] = evalValue(item.append.value, data), 
                checker({
                    data: data,
                    errorData: angular.extend({}, d.errorData, extra),
                    onError: d.onError,
                    checks: item.checks,
                    prefix: sumStrs(d.prefix, item.prefix)
                });
            }); else if ("array-group-chain" === item.check) pass = _.every(d.data, function(data, index) {
                var extra = {};
                return extra[item.append.key] = evalValue(item.append.value, data), checker({
                    data: data,
                    errorData: angular.extend({}, d.errorData, extra),
                    onError: d.onError,
                    checks: item.checks,
                    prefix: sumStrs(d.prefix, item.prefix)
                });
            }); else if ("array-group" === item.check) pass = _.contains(_.map(d.data, function(data, index) {
                var extra = {};
                return extra[item.append.key] = evalValue(item.append.value, data), checker({
                    data: data,
                    errorData: angular.extend({}, d.errorData, extra),
                    onError: d.onError,
                    checks: item.checks,
                    prefix: sumStrs(d.prefix, item.prefix)
                });
            }), !0); else if ("object-key-chain" === item.check && (pass = _.isString(item.key) && _.isObject(d.data[item.key]))) {
                var data = d.data[item.key], extra = {};
                extra[item.append.key] = evalValue(item.append.value, data);
                var prefix = "";
                angular.isString(d.prefix) && (prefix += d.prefix), angular.isString(item.prefix) && (prefix += item.prefix), 
                pass = _.every(item.checks, function(check, index) {
                    return checker({
                        data: data,
                        errorData: angular.extend({}, d.errorData, extra),
                        onError: d.onError,
                        checks: [ check ],
                        prefix: prefix
                    });
                });
            }
            return pass || "chain" !== d.data.groupType ? !0 : !1;
        });
        return ret;
    }
    return checker;
}), angular.module("avUi").service("AddDotsToIntService", function() {
    return function(number, fixedDigits) {
        angular.isNumber(fixedDigits) && fixedDigits >= 0 && (number = number.toFixed(parseInt(fixedDigits)));
        var number_str = (number + "").replace(".", ","), ret = "", commaPos = number_str.length;
        -1 !== number_str.indexOf(",") && (commaPos = number_str.indexOf(","));
        for (var i = 0; commaPos > i; i++) {
            var reverse = commaPos - i;
            reverse % 3 === 0 && reverse > 0 && i > 0 && (ret += "."), ret += number_str[i];
        }
        return ret + number_str.substr(commaPos, number_str.length);
    };
}), angular.module("avUi").service("EndsWithService", function() {
    return function(originString, searchString) {
        if (!angular.isString(originString) || !angular.isString(searchString)) return !1;
        var lastIndex = originString.indexOf(searchString);
        return -1 !== lastIndex && lastIndex === originString.length - searchString.length;
    };
}), angular.module("avUi").service("StateDataService", [ "$state", function($state) {
    var data = {};
    return {
        go: function(path, stateData, newData) {
            data = angular.copy(newData), $state.go(path, stateData);
        },
        getData: function() {
            return data;
        }
    };
} ]), angular.module("avUi").directive("avScrollToBottom", [ "$timeout", function($timeout) {
    return {
        restrict: "A",
        link: function(scope, element, attrs) {
            scope.$watch(function() {
                return element.children().length;
            }, function() {
                element.animate({
                    scrollTop: element.prop("scrollHeight")
                }, 300);
            });
        }
    };
} ]), angular.module("avUi").filter("addTargetBlank", function() {
    return function(x) {
        var tree = angular.element("<div>" + x + "</div>");
        return tree.find("a").attr("target", "_blank"), angular.element("<div>").append(tree).html();
    };
}), angular.module("avUi").filter("htmlToText", function() {
    return function(text) {
        return angular.element("<div>" + text + "</div>").text();
    };
}), angular.module("avUi").config([ "$provide", function($provide) {
    $provide.decorator("ngModelDirective", [ "$delegate", function($delegate) {
        var ngModel = $delegate[0], controller = ngModel.controller;
        return ngModel.controller = [ "$scope", "$element", "$attrs", "$injector", function(scope, element, attrs, $injector) {
            var $interpolate = $injector.get("$interpolate");
            attrs.$set("name", $interpolate(attrs.name || "")(scope)), $injector.invoke(controller, this, {
                $scope: scope,
                $element: element,
                $attrs: attrs
            });
        } ], $delegate;
    } ]), $provide.decorator("formDirective", [ "$delegate", function($delegate) {
        var form = $delegate[0], controller = form.controller;
        return form.controller = [ "$scope", "$element", "$attrs", "$injector", function(scope, element, attrs, $injector) {
            var $interpolate = $injector.get("$interpolate");
            attrs.$set("name", $interpolate(attrs.name || attrs.ngForm || "")(scope)), $injector.invoke(controller, this, {
                $scope: scope,
                $element: element,
                $attrs: attrs
            });
        } ], $delegate;
    } ]);
} ]), angular.module("avUi").controller("DocumentationUiController", [ "$state", "$stateParams", "$http", "$scope", "$sce", "$i18next", "ConfigService", "InsideIframeService", "Authmethod", function($state, $stateParams, $http, $scope, $sce, $i18next, ConfigService, InsideIframeService, Authmethod) {
    $scope.inside_iframe = InsideIframeService(), $scope.documentation = ConfigService.documentation, 
    $scope.documentation.security_contact = ConfigService.legal.security_contact, $scope.documentation_html_include = $sce.trustAsHtml(ConfigService.documentation_html_include), 
    $scope.auths_url = "/election/" + $stateParams.id + "/public/authorities", $scope.election_id = $stateParams.id + "", 
    Authmethod.viewEvent($stateParams.id).success(function(data) {
        "ok" === data.status && ($scope.authEvent = data.events);
    });
} ]), angular.module("avUi").directive("documentationDirective", function() {
    return {
        restrict: "AE",
        scope: {
            extra: "="
        },
        templateUrl: "avUi/documentation-directive/documentation-directive.html",
        controller: "DocumentationUiController"
    };
}), angular.module("avUi").directive("avFoot", [ "ConfigService", function(ConfigService) {
    function link(scope, element, attrs) {
        scope.contact = ConfigService.contact, scope.social = ConfigService.social, scope.technology = ConfigService.technology, 
        scope.legal = ConfigService.legal, scope.organization = ConfigService.organization;
    }
    return {
        restrict: "AE",
        scope: {},
        link: link,
        templateUrl: "avUi/foot-directive/foot-directive.html"
    };
} ]), angular.module("agora-gui-common", [ "ui.bootstrap", "ui.utils", "ui.router", "ngAnimate", "ngResource", "ngCookies", "ipCookie", "ngSanitize", "infinite-scroll", "angularMoment", "avConfig", "jm.i18next", "avRegistration", "avUi", "avTest", "angularFileUpload", "dndLists", "angularLoad", "angular-date-picker-polyfill", "ng-autofocus" ]), 
angular.module("jm.i18next").config([ "$i18nextProvider", "ConfigServiceProvider", function($i18nextProvider, ConfigServiceProvider) {
    $("#no-js").hide(), $i18nextProvider.options = _.extend({
        useCookie: !0,
        useLocalStorage: !1,
        fallbackLng: "en",
        cookieName: "lang",
        detectLngQS: "lang",
        lngWhitelist: [ "en", "es", "gl", "ca" ],
        resGetPath: "/locales/__lng__.json",
        defaultLoadingValue: ""
    }, ConfigServiceProvider.i18nextInitOptions);
} ]), angular.module("agora-gui-common").run([ "$http", "$rootScope", function($http, $rootScope) {
    $rootScope.safeApply = function(fn) {
        var phase = $rootScope.$$phase;
        "$apply" === phase || "$digest" === phase ? fn && "function" == typeof fn && fn() : this.$apply(fn);
    }, $rootScope.$on("$stateChangeStart", function(event, toState, toParams, fromState, fromParams) {
        console.log("change start from " + fromState.name + " to " + toState.name), $("#angular-preloading").show();
    }), $rootScope.$on("$stateChangeSuccess", function(event, toState, toParams, fromState, fromParams) {
        console.log("change success"), $("#angular-preloading").hide();
    });
} ]), angular.module("agora-gui-common").directive("ngSpaceClick", [ "$timeout", function($timeout) {
    return function(scope, element, attrs) {
        element.bind("keydown", function(event) {
            switch (event.which) {
              case 13:
              case 32:
                $timeout(function() {
                    event.currentTarget.click();
                }, 0), event.stopPropagation();
            }
        });
    };
} ]), angular.module("agora-gui-common").directive("ngEnter", function() {
    return function(scope, element, attrs) {
        element.bind("keydown keypress", function(event) {
            13 === event.which && (scope.$apply(function() {
                scope.$eval(attrs.ngEnter);
            }), event.preventDefault());
        });
    };
}), angular.module("agora-gui-common").filter("truncate", function() {
    return function(text, length, end) {
        return isNaN(length) && (length = 10), void 0 === end && (end = "..."), text.length <= length || text.length - end.length <= length ? text : String(text).substring(0, length - end.length) + end;
    };
}), angular.module("avTest", []), angular.module("avTest").controller("UnitTestE2EController", [ "$scope", "$location", "ConfigService", function($scope, $location, ConfigService) {
    ConfigService.debug && ($scope.html = $location.search().html, console.log($location.search()));
} ]), angular.module("agora-gui-common").run([ "$templateCache", function($templateCache) {
    "use strict";
    $templateCache.put("avRegistration/error.html", '<div av-simple-error><p ng-i18next="avRegistration.errorRegistration"></p></div>'), 
    $templateCache.put("avRegistration/field-directive/field-directive.html", '<div ng-switch="field.type"><div avr-email-field ng-switch-when="email"></div><div avr-password-field ng-switch-when="password"></div><div avr-code-field ng-switch-when="code"></div><div avr-text-field ng-switch-when="text"></div><div avr-dni-field ng-switch-when="dni"></div><div avr-date-field ng-switch-when="date" ng-model="field.value"></div><div avr-tel-field ng-switch-when="tlf"></div><div avr-int-field ng-switch-when="int"></div><div avr-bool-field ng-switch-when="bool"></div><div avr-captcha-field ng-switch-when="captcha"></div><div avr-textarea-field ng-switch-when="textarea"></div><div avr-image-field ng-switch-when="image"></div></div>'), 
    $templateCache.put("avRegistration/fields/bool-field-directive/bool-field-directive.html", '<div class="form-group"><label class="control-label col-sm-4"><input type="checkbox" class="form-control" aria-label="input{{index}}-bool" id="{{index}}Text" ng-model="field.value" ng-disabled="field.disabled" tabindex="{{index}}" ng-required="{{field.required}}"></label><div class="col-sm-8"><label class="text-left" for="{{index}}Text"><span ng-bind-html="field.name | addTargetBlank"></span></label><p class="help-block" ng-if="field.help" ng-bind-html="field.help | addTargetBlank"></p><div class="input-error"></div></div></div>'), 
    $templateCache.put("avRegistration/fields/captcha-field-directive/captcha-field-directive.html", '<div class="form-group"><div class="col-sm-8 col-sm-offset-4"><img ng-src="{{authMethod.captcha_image_url}}" style="width:161px;height:65px"></div><label for="{{index}}Text" class="control-label col-sm-4"><span>{{field.name}}</span></label><div class="col-sm-8"><input type="text" class="form-control" aria-label="input{{index}}-captcha" id="{{index}}Text" minlength="{{field.min}}" maxlength="{{field.max}}" ng-model="field.value" ng-disabled="field.disabled" tabindex="{{index}}" required><p class="help-block" ng-if="field.help">{{field.help}}</p><div class="input-error">{{authMethod.captcha_status}}</div></div></div>'), 
    $templateCache.put("avRegistration/fields/code-field-directive/code-field-directive.html", '<div class="form-group"><label for="{{code_id}}" class="control-label col-sm-4" ng-i18next="avRegistration.codeLabel"></label><div class="col-sm-8"><input type="text" class="form-control" aria-label="{{code_id}}-code" id="{{code_id}}" ng-model="field.value" ng-disabled="field.disabled" tabindex="{{index}}" autocomplete="off" ng-class="{\'filled\': form[code_id].$viewValue.length > 0}" minlength="8" maxlength="9" ng-pattern="codePattern" name="{{code_id}}" ng-i18next="[placeholder]avRegistration.codePlaceholder" required><p class="help-block" ng-i18next="avRegistration.codeHelp"></p><p class="help-block code-help"><span ng-if="allowUserResend && showResendAuthCode() && !sendingData && ((\'sms\' !== method && \'sms-otp\' !== method) || isValidTel)"><b ng-i18next="avRegistration.noCodeReceivedQuestion"></b> <a ng-click="resendAuthCode(field)" ng-i18next="avRegistration.sendCodeAgain"></a> <span></span></span></p><div class="input-error"></div></div></div>'), 
    $templateCache.put("avRegistration/fields/date-field-directive/date-field-directive.html", '<div class="form-group"><label ng-if="!label" class="control-label col-sm-4">{{field.name}}</label><label class="control-label col-sm-4" ng-if="label" ng-bind="label"></label><div class="col-sm-8"><select aria-label="{{field.name}}-year" ng-model="date.year" ng-change="onChange()"><option ng-selected="date.year == item" ng-repeat="item in years" ng-value="item">{{item}}</option></select><select aria-label="{{field.name}}-month" ng-model="date.month" ng-change="onChange()"><option ng-selected="date.month == item" ng-repeat="item in months" ng-value="item">{{item}}</option></select><select aria-label="{{field.name}}-day" ng-model="date.day" ng-change="onChange()"><option ng-selected="date.day == item" ng-repeat="item in getDays()" ng-value="item">{{item}}</option></select><p class="help-block" ng-if="field.help">{{field.help}}</p></div></div>'), 
    $templateCache.put("avRegistration/fields/dni-field-directive/dni-field-directive.html", '<ng-form name="fieldForm"><div class="form-group" ng-class="{\'has-error\': fieldForm.input.$dirty && fieldForm.input.$invalid}"><label for="input{{index}}" class="control-label col-sm-4"><span>{{field.name}}</span></label><div class="col-sm-8"><input type="text" id="input{{index}}" aria-label="input{{index}}-dni" class="form-control" minlength="{{field.min}}" maxlength="{{field.max}}" ng-model="field.value" ng-model-options="{debounce: 500}" ng-disabled="field.disabled" tabindex="{{index}}" ui-validate="{dni: \'validateDni($value)\'}" ng-required="{{field.required}}"><p class="help-block" ng-i18next="avRegistration.dniHelp"></p><div class="input-error"><span class="error text-brand-danger" ng-show="fieldForm.input.$dirty && fieldForm.input.$invalid" ng-i18next="avRegistration.invalidDni"></span></div></div></div></ng-form>'), 
    $templateCache.put("avRegistration/fields/email-field-directive/email-field-directive.html", '<div class="form-group" ng-class="{true: \'has-error\',false: \'is-required\'}[form.emailText.$dirty && form.emailText.$invalid]"><label for="emailText" class="control-label col-sm-4" ng-i18next="avRegistration.emailLabel"></label><div class="col-sm-8"><input type="text" class="form-control" ng-model="field.value" name="emailText" id="emailText" ng-i18next="[placeholder]avRegistration.emailPlaceholder" tabindex="{{index}}" ng-pattern="patterns(\'email\')" required ng-disabled="field.disabled"><div class="input-error"><small class="error text-danger" ng-show="form.emailText.$dirty && form.emailText.$invalid" ng-i18next="avRegistration.emailError"></small></div></div></div>'), 
    $templateCache.put("avRegistration/fields/image-field-directive/image-field-directive.html", '<ng-form name="fieldForm"><div class="form-group" ng-class="{\'has-error\': fieldForm.input.$dirty && fieldForm.input.$invalid}"><label for="image-field" class="control-label col-sm-4"><span>{{field.name}}</span></label><div class="col-sm-8"><input type="file" name="image" id="image-field" aria-label="image-field{{index}}" class="form-control" ng-disabled="field.disabled" tabindex="{{index}}" ng-required="{{field.required}}"><p class="help-block" ng-i18next="avRegistration.imageHelp"></p><div class="input-error"><span class="error text-brand-danger" ng-show="fieldForm.input.$dirty && fieldForm.input.$invalid" ng-i18next="avRegistration.invalidImage"></span></div></div></div></ng-form>'), 
    $templateCache.put("avRegistration/fields/int-field-directive/int-field-directive.html", '<ng-form name="fieldForm"><div class="form-group" ng-class="{\'has-error\': fieldForm.input.$dirty && fieldForm.input.$invalid}"><label for="input{{index}}" class="control-label col-sm-4"><span>{{field.name}}</span></label><div class="col-sm-8"><input type="number" class="form-control" id="input{{index}}" aria-label="input{{index}}-int" name="input" min="{{field.min}}" max="{{field.max}}" ng-model="field.value" ng-model-options="{debounce: 500}" ng-disabled="field.disabled" ng-pattern="getRe()" tabindex="{{index}}" ng-required="{{field.required}}"><p class="help-block" ng-if="field.help">{{field.help}}</p><div class="input-error"><span class="error text-brand-danger" ng-show="fieldForm.input.$dirty && fieldForm.input.$invalid" ng-i18next="avRegistration.invalidDataRegEx"></span></div></div></div></ng-form>'), 
    $templateCache.put("avRegistration/fields/password-field-directive/password-field-directive.html", '<div class="form-group" ng-class="{true: \'has-error\',false: \'is-required\'}[form.passwordText.$dirty && form.passwordText.$invalid]"><label for="passwordText" class="control-label col-sm-4"><span ng-i18next="avRegistration.passwordLabel"></span></label><div class="col-sm-8"><input type="password" class="form-control" ng-model="field.value" id="passwordText" ng-disabled="field.disabled" ng-i18next="[placeholder]avRegistration.passwordPlaceholder" tabindex="{{index}}" required><p class="help-block"><a href="#" ng-i18next="avRegistration.forgotPassword" ng-click="forgotPassword()" tabindex="{{index+1}}"></a></p><div class="input-error"><small class="error text-danger" ng-show="form.$submitted && form.$invalid" ng-i18next="avRegistration.invalidCredentials"></small></div></div></div>'), 
    $templateCache.put("avRegistration/fields/tel-field-directive/tel-field-directive.html", '<div class="form-group"><label for="input{{index}}" class="control-label col-sm-4" ng-i18next="avRegistration.telLabel"></label><div class="col-sm-8"><input type="tel" class="form-control phone-login" aria-label="input{{index}}-tel" id="input{{index}}" ng-disabled="field.disabled" tabindex="{{index}}" name="input{{index}}" required><p class="help-block" ng-i18next="avRegistration.telHelp"></p><p class="text-warning" ng-if="\'sms-otp\' === method" ng-i18next="avRegistration.otpHelp"></p><div class="input-error"><span class="error" ng-show="!isValidNumber" ng-i18next="avRegistration.telInvalid"></span></div></div></div>'), 
    $templateCache.put("avRegistration/fields/text-field-directive/text-field-directive.html", '<ng-form name="fieldForm"><div class="form-group" ng-class="{\'has-error\': fieldForm.input.$dirty && fieldForm.input.$invalid}"><label for="input{{index}}" class="control-label col-sm-4"><span ng-if="field.name == \'username\'" ng-i18next="avRegistration.usernameLabel"></span> <span ng-if="field.name != \'username\'">{{field.name}}</span></label><div class="col-sm-8"><input type="text" name="input" id="input{{index}}" aria-label="input{{index}}-textarea" class="form-control" minlength="{{field.min}}" maxlength="{{field.max}}" ng-model="field.value" ng-model-options="{debounce: 500}" ng-disabled="field.disabled" tabindex="{{index}}" ng-pattern="getRe()" ng-required="{{field.required}}"><p class="help-block" ng-if="field.help">{{field.help}}</p><div class="input-error"><span class="error text-brand-danger" ng-show="fieldForm.input.$dirty && fieldForm.input.$invalid" ng-i18next="avRegistration.invalidDataRegEx"></span></div></div></div></ng-form>'), 
    $templateCache.put("avRegistration/fields/textarea-field-directive/textarea-field-directive.html", '<div class="form-group"><div class="col-sm-offset-2 col-sm-10"><textarea aria-label="{{index}}Text" id="{{index}}Text" rows="5" cols="60" tabindex="{{index}}" readonly>{{field.name}}</textarea><p class="help-block" ng-if="field.help">{{field.help}}</p></div></div>'), 
    $templateCache.put("avRegistration/loading.html", '<div avb-busy><p ng-i18next="avRegistration.loadingRegistration"></p></div>'), 
    $templateCache.put("avRegistration/login-controller/login-controller.html", '<div class="col-xs-12 top-section"><div class="pad"><div av-login event-id="{{event_id}}" code="{{code}}" email="{{email}}" ng-if="!isOpenId"></div><div av-openid-connect ng-if="isOpenId"></div></div></div>'), 
    $templateCache.put("avRegistration/login-directive/login-directive.html", '<div class="container-fluid"><div class="row"><div class="col-sm-12 loginheader"><h2 class="tex-center" ng-if="!isCensusQuery && method !== \'openid-connect\'" ng-i18next="[i18next]({name: orgName})avRegistration.loginHeader"></h2><h2 class="tex-center" ng-if="!isCensusQuery && method === \'openid-connect\'" ng-i18next="[i18next]avRegistration.loginButton"></h2><h2 class="tex-center" ng-if="!!isCensusQuery" ng-i18next="avRegistration.censusQueryHeader"></h2></div><div class="col-sm-6" ng-if="method !== \'openid-connect\'"><form name="form" id="loginForm" role="form" class="form-horizontal"><div ng-repeat="field in login_fields" avr-field index="{{$index+1}}" ng-if="field.steps === undefined || field.steps.indexOf(currentFormStep) !== -1"></div><div class="col-sm-offset-4 col-sm-8 button-group"><div class="input-error" ng-if="!isCensusQuery"><div class="error text-danger" ng-if="error">{{ error }}</div></div><div class="input-warn"><span class="text-warning" ng-if="!form.$valid || sendingData" ng-i18next>avRegistration.fillValidFormText</span></div><button type="submit" class="btn btn-block btn-success" ng-if="!isCensusQuery" ng-i18next="avRegistration.loginButton" ng-click="loginUser(form.$valid)" tabindex="{{login_fields.length+1}}" ng-disabled="!form.$valid || sendingData"></button> <button type="submit" class="btn btn-block btn-success" ng-if="!!isCensusQuery" ng-i18next="avRegistration.checkCensusButton" ng-click="checkCensus(form.$valid)" tabindex="{{login_fields.length+1}}" ng-disabled="!form.$valid || sendingData"></button><div class="census-query" ng-if="isCensusQuery"><div class="input-info census-query" ng-if="censusQuery == \'querying\'"><div class="text-info" ng-i18next="avRegistration.censusQuerying"></div></div><div class="input-success census-query" ng-if="censusQuery == \'success\'"><div class="success text-success" ng-i18next="[html]avRegistration.censusSuccess"></div></div><div class="input-success census-query" ng-if="censusQuery == \'fail\'"><div class="error text-danger" ng-i18next="[html]avRegistration.censusFail"></div></div></div></div></form></div><div class="col-sm-5 col-sm-offset-1 hidden-xs" ng-if="registrationAllowed && !isCensusQuery  && method !== \'openid-connect\'"><h3 class="help-h3" ng-i18next="avRegistration.notRegisteredYet"></h3><p><a ng-if="!isAdmin" href="#/election/{{election.id}}/public/register" ng-i18next="avRegistration.registerHere" ng-click="goSignup()" tabindex="{{login_fields.length+2}}"></a><br><a ng-if="isAdmin" href="{{ signupLink }}" ng-i18next="avRegistration.registerHere" tabindex="{{login_fields.length+2}}"></a><br><span ng-i18next="avRegistration.fewMinutes"></span></p></div><div class="col-sm-12 text-center" ng-if="method === \'openid-connect\'"><span ng-repeat="provider in openIDConnectProviders"><a ng-click="openidConnectAuth(provider)" alt="{{provider.description}}" class="btn btn-primary btn-login"><img ng-if="!!provider.icon" alt="{{provider.description}}" class="logo-img" ng-src="{{provider.icon}}"> {{provider.title}}</a></span></div></div></div>'), 
    $templateCache.put("avRegistration/openid-connect-directive/openid-connect-directive.html", ""), 
    $templateCache.put("avRegistration/register-controller/register-controller.html", '<div class="col-xs-12 top-section"><div class="pad"><div av-register event-id="{{event_id}}" code="{{code}}" email="{{email}}"></div></div></div>'), 
    $templateCache.put("avRegistration/register-directive/register-directive.html", '<div class="container"><div class="row"><div class="col-sm-12"><h2 ng-if="!admin" class="registerheader" ng-i18next="avRegistration.registerHeader"></h2><h2 ng-if="admin" class="registerheader" ng-i18next="avRegistration.registerAdminHeader"></h2></div></div><div class="row"><div class="col-sm-6"><div ng-if="method == \'dnie\'"><a type="submit" class="btn btn-block btn-success" ng-i18next="avRegistration.registerButton" ng-href="{{ dnieurl }}/"></a></div><form ng-if="method != \'dnie\'" name="form" id="registerForm" role="form" class="form-horizontal"><div ng-repeat="field in register_fields" avr-field index="{{$index+1}}"></div><div class="col-sm-offset-4 col-sm-8 button-group"><div class="input-error"><div class="error text-danger" ng-if="error" ng-bind-html="error"></div></div><div class="input-warn"><span class="text-warning" ng-if="!form.$valid || sendingData" ng-i18next>avRegistration.fillValidFormText</span></div><button type="submit" class="btn btn-block btn-success" ng-i18next="avRegistration.registerButton" ng-click="signUp(form.$valid)" tabindex="{{register_fields.length+1}}" ng-disabled="!form.$valid || sendingData"></button></div></form></div><div class="col-sm-5 col-sm-offset-1 help-sidebar hidden-xs"><span><h3 class="help-h3" ng-i18next="avRegistration.registerAdminFormHelpTitle"></h3><p ng-i18next>avRegistration.helpAdminRegisterForm</p></span> <span><p ng-if="!admin" ng-i18next>avRegistration.helpRegisterForm</p><h3 class="help-h3" ng-i18next="avRegistration.alreadyRegistered"></h3><p ng-i18next>[html]avRegistration.helpAlreadyRegisteredForm</p><a href="" ng-click="goLogin($event)" ng-i18next="avRegistration.loginHere"></a><br></span></div></div></div>'), 
    $templateCache.put("avRegistration/success.html", '<div av-success><p ng-i18next="avRegistration.successRegistration"></p></div>'), 
    $templateCache.put("avUi/change-lang-directive/change-lang-directive.html", '<a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-expanded="false">{{ deflang }} <span class="caret"></span></a><ul class="dropdown-menu" role="menu"><li ng-repeat="lang in langs"><a ng-click="changeLang(lang)" ng-space-click tabindex="0">{{lang}}</a></li></ul>'), 
    $templateCache.put("avUi/documentation-directive/documentation-directive.html", '<div><h2 class="text-center text-av-secondary" ng-i18next="avDocumentation.documentation.title"></h2><p ng-i18next="avDocumentation.documentation.first_line"></p><ul class="docu-ul"><li ng-if="!!documentation.faq"><a href="{{documentation.faq}}" target="_blank" ng-i18next="avDocumentation.documentation.faq"></a></li><li ng-if="!!documentation.overview"><a href="{{documentation.overview}}" target="_blank" ng-i18next="avDocumentation.documentation.overview"></a></li><li><a href="{{auths_url}}" target="_blank" ng-i18next="avDocumentation.documentation.authorities"></a></li><li ng-if="!!documentation.technical"><a href="{{documentation.technical}}" target="_blank" ng-i18next="avDocumentation.documentation.technical"></a></li><li ng-if="!!documentation.security_contact"><a href="{{documentation.security_contact}}" target="_blank" ng-i18next="avDocumentation.documentation.security_contact"></a></li></ul><div class="documentation-html-include" av-plugin-html ng-bind-html="documentation_html_include"></div></div>'), 
    $templateCache.put("avUi/foot-directive/foot-directive.html", '<div class="commonfoot"><div class="social" style="text-align: center"><span class="powered-by pull-left" ng-i18next="[html:i18next]({url: organization.orgUrl, name: organization.orgName})avCommon.poweredBy"></span> <a href="{{social.facebook}}" target="_blank" ng-if="!!social.facebook" aria-label="Facebook"><i class="fa fa-fw fa-lg fa-facebook"></i></a> <a href="{{social.twitter}}" target="_blank" ng-if="!!social.twitter" aria-label="Twitter"><i class="fa fa-fw fa-lg fa-twitter"></i></a> <a href="{{social.googleplus}}" target="_blank" ng-if="!!social.googleplus" aria-label="Google Plus"><i class="fa fa-fw fa-lg fa-google-plus"></i></a> <a href="{{social.youtube}}" target="_blank" ng-if="!!social.youtube" aria-label="Youtube"><i class="fa fa-fw fa-lg fa-youtube-play"></i></a> <a href="{{social.github}}" target="_blank" ng-if="!!social.github" aria-label="Github"><i class="fa fa-fw fa-lg fa-github"></i></a></div></div>'), 
    $templateCache.put("avUi/simple-error-directive/simple-error-directive.html", '<div class="av-simple-error-title" ng-transclude></div>'), 
    $templateCache.put("test/test_booth_widget.html", '<!DOCTYPE html><html><head><title>Test frame</title><meta charset="UTF-8"></head><script>function getCastHmac(auth_data, callback) {\n      callback("khmac:///sha-256;5e25a9af28a33d94b8c2c0edbc83d6d87355e45b93021c35a103821557ec7dc5/voter-1110-1dee0c135afeae29e208550e7258dab7b64fb008bc606fc326d41946ab8e773f:1415185712");\n    }</script><body style="overflow-y: hidden; overflow-x: hidden; padding: 0; margin: 0"><div style="width: 100%; display: block; position: absolute; top: 0; bottom: 0; scroll: none; padding: 0; margin: 0"><a class="agoravoting-voting-booth" href="http://agora.dev/#/election/1110/vote" data-authorization-funcname="getCastHmac">Votar con Agora Voting</a><script>!function(d,s,id){var js,fjs=d.getElementsByTagName(s)[0];if(!d.getElementById(id)){js=d.createElement(s);js.id=id;js.src="http://agora.dev/avWidgets.min.js";fjs.parentNode.insertBefore(js,fjs);}}(document,"script","agoravoting-widgets-js");</script></div></body></html>'), 
    $templateCache.put("test/unit_test_e2e.html", '<div dynamic="html" id="dynamic-result"></div>');
} ]);