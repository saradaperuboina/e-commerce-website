angular.module('app')
    .controller('LoginCtrl', function ($scope, $state, $auth, toastr) {
        $scope.login = function () {
            $scope.user.locationInfo = appSettings.locationInfo;
            $auth.login($scope.user)
                .then(function () {
                    toastr.success('You have successfully signed in!');
                    $state.go('main');
                })
                .catch(function (error) {
                    toastr.error(error.data.message, error.status);
                });
        };
        $scope.authenticate = function (provider) {
            $auth.authenticate(provider)
                .then(function () {
                    toastr.success('You have successfully signed in with ' + provider + '!');
                    $state.go('main');
                })
                .catch(function (error) {
                    if (error.message) {
                        // Satellizer promise reject error.
                        toastr.error(error.message);
                    } else if (error.data) {
                        // HTTP response error from server
                        toastr.error(error.data.message, error.status);
                    } else {
                        toastr.error(error);
                    }
                });
        };

        if ($auth.isAuthenticated()) {
            // $location.path('#/user/main');
            $state.go('main');
        }

    });
