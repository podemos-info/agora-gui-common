/**
 * This file is part of agora-gui-common.
 * Copyright (C) 2015-2016  Agora Voting SL <agora@agoravoting.com>

 * agora-gui-common is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License.

 * agora-gui-common  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with agora-gui-common.  If not, see <http://www.gnu.org/licenses/>.
**/

angular.module('avRegistration')
  .directive(
    'avOpenidConnect',
    function(
      $cookies,
      $window,
      ConfigService,
      Authmethod
    ) {
      // we use it as something similar to a controller here
      function link(scope, element, attrs)
      {
        // Maximum Oauth Login Timeout is 5 minutes
        var maxOAuthLoginTimeout = 1000 * 60 * 5;

        // Redirects to the login page of the respective event_id
        function redirectToLogin()
        {
            $window.location.href = "/election/" + attrs.eventId + "/public/login";
        }

        // validates the CSRF token
        function validateCsrfToken()
        {
            var postfix = "_authevent_" + attrs.eventId;
            if (!$cookies['openid-connect-csrf' + postfix])
            {
                redirectToLogin();
                return null;
            }

            // validate csrf token format and data
            var csrf = angular.fromJson($cookies['openid-connect-csrf' + postfix]);
            var isCsrfValid = (!csrf ||
              !angular.isObject(csrf) ||
              !angular.isString(csrf.randomState) ||
              !angular.isString(csrf.randomNonce) ||
              !angular.isNumber(csrf.created) ||
              csrf.event_id !== attrs.eventId ||
              csrf.created - Date.now() < maxOAuthLoginTimeout ||
              csrf.randomState === attrs.randomState);

            if (!isCsrfValid)
            {
                redirectToLogin();
                return null;
            }
            return csrf.randomNonce;
        }

        // Process a call to openid authentication
        function processOpenIdAuthRequest()
        {
            // validate csrf token
            var randomnNonce = validateCsrfToken();
            if (!randomnNonce)
            {
                return;
            }

            // get provider from config list
            var provider = _.find(
                ConfigService.openIDConnectProviders,
                function (provider) { return provider.id === attrs.provider; }
            );

            // find provider
            if (!provider)
            {
                // TODO: show error
                redirectToLogin();
                return;
            }

            // Craft the OpenID Connect auth URI
            var authURI = (provider.authorization_endpoint +
                "?response_type=id_token" +
                "&client_id=" + encodeURIComponent(provider.client_id) +
                "&scope=" + encodeURIComponent("openid email") +
                "&redirect_uri=" + encodeURIComponent(
                    $window.location.origin +
                    "/election/" +
                    attrs.eventId +
                    "/home/login-openid-connect-redirect/" +
                    attrs.provider + "/" +
                    attrs.randomState + "/true"

                ) +
                "&state=" + attrs.randomState
            );

            // Redirect to the Auth URI
            $window.location.href = authURI;
        }

        // Get the decoded value of a uri parameter from any uri. The uri does not
        // need to have any domain, it can start with the character "?"
        function getURIParameter(paramName, uri)
        {
            var paramName2 = paramName.replace(/[\[\]]/g, '\\$&');
            var rx = new RegExp('[?&]' + paramName2 + '(=([^&#]*)|&|#|$)');
            var params = rx.exec(uri);

            if (!params)
            {
                return null;
            }

            if (!params[2])
            {
                return '';
            }
            return decodeURIComponent(params[2].replace(/\+/g, ' '));
        }

        // Process an OpenId Connect callback coming from the provider, try to
        // validate the callback data and get the authentication token from our
        // server and redirect to vote
        function processOpenIdAuthCallback()
        {
            // validate csrf token from uri and from state in the hash
            var randomNonce = validateCsrfToken();
            var uri = "?" + $window.location.hash;

            var data = {
                id_token: getURIParameter("id_token", uri),
                provider: attrs.provider,
                nonce: randomNonce
            };

            // Send the authentication request to our server
            Authmethod.login(data, attrs.eventId)
                .success(function(rcvData)
                {
                    if (rcvData.status === "ok")
                    {
                        scope.khmac = rcvData.khmac;
                        var postfix = "_authevent_" + attrs.eventId;
                        $cookies["authevent_" + attrs.eventId] = attrs.eventId;
                        $cookies["userid" + postfix] = rcvData.username;
                        $cookies["user" + postfix] = scope.email;
                        $cookies["auth" + postfix] = rcvData['auth-token'];
                        $cookies["isAdmin" + postfix] = scope.isAdmin;
                        Authmethod.setAuth($cookies["auth" + postfix], scope.isAdmin, attrs.eventId);

                        if (angular.isDefined(rcvData['redirect-to-url']))
                        {
                            $window.location.href = rcvData['redirect-to-url'];
                        }
                        else
                        {
                            // redirecting to vote link
                            Authmethod.getPerm("vote", "AuthEvent", attrs.eventId)
                                .success(function(rcvData2)
                                {
                                    var khmac = rcvData2['permission-token'];
                                    var path = khmac.split(";")[1];
                                    var hash = path.split("/")[0];
                                    var msg = path.split("/")[1];
                                    $window.location.href = '/booth/' + attrs.eventId + '/vote/' + hash + '/' + msg;
                                });
                        }
                    } else
                    {
                        // TODO: show error
                        redirectToLogin();
                        return;
                    }
                })
                .error(function(error)
                {
                    // TODO: show error
                    redirectToLogin();
                    return;
                });
        }

        // This is an OpenId Connect callback coming from the provider, try to
        // validate the callback data and get the authentication token from our
        // server and redirect to vote
        if (attrs.isRedirect === "true")
        {
            processOpenIdAuthCallback();
        }
        // This is an OpenID Connect authentication request, try to redirect
        // to the provider for authentication
        else if (attrs.provider && attrs.randomState)
        {
            processOpenIdAuthRequest();
        }
      }
      return {
        restrict: 'AE',
        scope: true,
        link: link,
        templateUrl: 'avRegistration/openid-connect-directive/openid-connect-directive.html'
      };
    });
