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
  .directive('avrCodeField', function($state, Plugins) {
    function link(scope, element, attrs) {
      scope.codePattern = /[abcdefghjklmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-]{8,9}/;
      var rand_code = '' + _.random(1e12);
      scope.code_id = 'input' + scope.index + rand_code;

      scope.showResendAuthCode = function ()
      { 
        var data = {showUserSendAuthCode: true};
        Plugins.hook('hide-user-send-auth-code', data);
        return data.showUserSendAuthCode;
      };

      // TODO: validate email for email-otp. For now, we just allow the resend
      // button for that use-case
      if (_.contains(['sms', 'sms-otp'], scope.method)) {
        var telInput =
          angular.element(document.getElementById('input' + scope.telIndex));
        scope.isValidTel = telInput.intlTelInput("isValidNumber");
        scope.$watch('telField.value',
          function (newValue, oldValue) {
            scope.isValidTel = telInput.intlTelInput("isValidNumber");
          },
          true);
      }
    }
    return {
      restrict: 'AE',
      scope: true,
      link: link,
      templateUrl: 'avRegistration/fields/code-field-directive/code-field-directive.html'
    };
  });
