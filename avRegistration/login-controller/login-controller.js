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
  .controller(
    'LoginController',
    function(
      $scope,
      $stateParams,
      $filter,
      $i18next,
      $cookies,
      $window,
      ConfigService,
      Authmethod)
    {
      $scope.event_id = $stateParams.id;
      $scope.code = $stateParams.code;
      $scope.email = $stateParams.email;
      $scope.provider = $stateParams.provider;
      $scope.randomState = $stateParams.randomState;
      $scope.is_redirect = $stateParams.is_redirect;
    }
  );
