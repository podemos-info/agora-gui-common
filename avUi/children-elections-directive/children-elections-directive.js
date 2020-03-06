/**
 * This file is part of agora-gui-admin.
 * Copyright (C) 2020  Agora Voting SL <agora@agoravoting.com>

 * agora-gui-admin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License.

 * agora-gui-admin  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with agora-gui-admin.  If not, see <http://www.gnu.org/licenses/>.
**/

angular.module('avUi')
  .directive(
    'avChildrenElections', 
    function(ConfigService) 
    {
      // we use it as something similar to a controller here
      function link(scope, element, attrs) {
        scope.mode = attrs.mode;
        scope.children_election_info = attrs.childrenElectionInfo;

        // process each election
        _.each(
          scope.children_election_info.presentation.categories,
          function (category) {
            _.each (
              category.events,
              function (election) {
                if (scope.mode === 'checkbox') {
                  election.data = false;
                }
              }
            );
          }
        );

        // add a processElection function
        scope.processElection = function (election_id) {
          console.log("election_id = " + election_id);
        };
      }

      return {
        restrict: 'AE',
        scope: {
        },
        link: link,
        templateUrl: 'avUi/foot-directive/foot-directive.html'
      };
    }
  );
