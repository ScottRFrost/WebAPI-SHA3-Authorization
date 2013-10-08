var app = angular.module('app', []);

//#region SERVICES
app.service('ajax', function ($rootScope, $http) {
    this.success = function (result) {
        return result.data;
    };

    this.error = function (result) {
        switch (result.status) {
            case 0:
                $rootScope.$broadcast('errorThrown', 'Timeout waiting for server.  Check your internet connection');
                break;
            case 400:
                $rootScope.$broadcast('errorThrown', 'Invalid Request.  ' + result.data.MessageDetail);
                break;
            case 401:
                $rootScope.$broadcast('errorThrown', 'You do not have permission to do that.  ' + result.data.MessageDetail);
                break;
            case 404:
                $rootScope.$broadcast('errorThrown', 'API URL not found.  ' + result.data.MessageDetail);
                break;
            case 500:
                $rootScope.$broadcast('errorThrown', 'Server error when processing your request.  ' + result.data.MessageDetail);
                break;
            default:
                $rootScope.$broadcast('errorThrown', 'ERROR ' + result.status + ' ' + result.data.MessageDetail);
                break;
        }
        return null;
    };

    this.get = function (url, params) {
        var now = new Date();
        var utcNumber = now.getTime();
        var auth = localStorage.username + "|" + utcNumber + "|" + CryptoJS.SHA3(url + localStorage.apikey + utcNumber).toString(CryptoJS.enc.Base64);
        return $http.get(url, { params: params, timeout: 60000, cache: false, headers: { 'Authorization': auth } }).then(this.success, this.error);
    };

    this.post = function (url, params, data) {
        var now = new Date();
        var utcNumber = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours(), now.getUTCMinutes(), now.getUTCSeconds(), now.getUTCMilliseconds);
        var auth = localStorage.username + "|" + utcNumber + "|" + CryptoJS.SHA3(url + localStorage.apikey + utcNumber).toString(CryptoJS.enc.Base64);
        return $http.post(url, { params: params, data: data, timeout: 60000, cache: false, headers: { 'Authorization': auth } }).then(this.success, this.error);
    };
});

app.service('TimeSvc', function($http, ajax) {
    this.GetTime = function() {
        return ajax.get('/api/Time');
    };
});
//#endregion

//#region CONTROLLERS
app.controller('MainCntl', function($scope, TimeSvc) {
    $scope.time = TimeSvc.GetTime();
    $scope.$on('errorThrown', function(event, args) {
        $scope.errorMessage = args;
    });
});
//#endregion