'use strict';
var oauthTest = angular.module('oauthTest', ['ui.bootstrap', 'ngStorage', 'ngClipboard', 'ui.codemirror']);

oauthTest.config(function ($sceDelegateProvider) {
    $sceDelegateProvider.resourceUrlWhitelist([
        // Allow same origin resource loads.
        'self',
        // Allow loading from our assets domain.  Notice the difference between * and **.
        'http://*.*/**'
    ]);

    // The blacklist overrides the whitelist so the open redirect here is blocked.
    $sceDelegateProvider.resourceUrlBlacklist([
        'http://myapp.example.com/clickThru**'
    ]);
});

oauthTest.controller('MainController', function ($scope, $http, $sessionStorage, $sce, $location, $window, $q, AlertingService) {

//    $scope.cmOption = {
//    lineNumbers: true,
//    indentWithTabs: true,
//     lineWrapping : true,
//    onLoad : function(_cm){
// 
//      // HACK to have the codemirror instance in the scope...
//      $scope.modeChanged = function(){
//        _cm.setOption("mode", "javascript");
//      };
//      
//      $scope.refresh = function(){
//          _cm.refresh();
//      };
//    }
//  };


    var init = function () {
        $scope.authorizationCode = $location.absUrl().split('code=')[1];
        if ($scope.authorizationCode !== undefined) {
            //$scope.addAlert('success', 'New Authorzation Code available');
        }

        $sessionStorage.authorizationCode = $scope.authorizationCode;
        $scope.user = undefined;
        $scope.basicKey = $sessionStorage.basicKey;
        $scope.client_id = $sessionStorage.client_id;
        $scope.redirect_uri = $sessionStorage.redirect_uri;
        $scope.authorizationCode = $sessionStorage.authorizationCode;
        $scope.secret = $sessionStorage.secret;
        $scope.server = $sessionStorage.server;
        $scope.service = $sessionStorage.service;
        $scope.realm = $sessionStorage.realm;


    };

    var getBasicKey = function () {
        var bk = btoa($scope.client_id+':' + $scope.secret);
        $scope.basicKey = bk;

        return 'Basic ' + bk;
    };

    var getBearerKey = function () {

        return 'Bearer ' + $scope.access_token;
    };

    init();

    $scope.getTokenFromCode = function () {
        var code_endpoint = $scope.server + '/realms/' + $scope.realm + '/tokens/access/codes';
        var params = 'code=' + $scope.authorizationCode + '&redirect_uri=' + $scope.redirect_uri;
        if ($scope.authorizationCode === '') {
            this.addAlert('warning', 'Authorization Code not available');
        }
        if ($scope.redirect_uri === '') {
            this.addAlert('warning', 'Redirect URI is not available.');
        }

        $http.post(code_endpoint, params,
                {'headers': {
                        'Authorization': getBasicKey(),
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }}).success(function (data) {
            
            $scope.displayResult(data);
            $sessionStorage.token = data;
            $scope.access_token = $sessionStorage.token.access_token;
            $scope.refresh_token = $sessionStorage.token.refresh_token;
            $scope.authorizationCode = '';
        });

    };

    if (!library)
        var library = {};

    library.json = {
        replacer: function (match, pIndent, pKey, pVal, pEnd) {
            var key = '<span class=json-key>';
            var val = '<span class=json-value>';
            var str = '<span class=json-string>';
            var r = pIndent || '';
            if (pKey)
                r = r + key + pKey.replace(/[": ]/g, '') + '</span>: ';
            if (pVal)
                r = r + (pVal[0] == '"' ? str : val) + pVal + '</span>';
            return r + (pEnd || '');
        },
        prettyPrint: function (obj) {
            var jsonLine = /^( *)("[\w]+": )?("[^"]*"|[\w.+-]*)?([,[{])?$/mg;
            return JSON.stringify(obj, null, 3)
                    .replace(/&/g, '&amp;').replace(/\\"/g, '&quot;')
                    .replace(/</g, '&lt;').replace(/>/g, '&gt;')
                    .replace(jsonLine, library.json.replacer);
        }
    };
    
    $scope.displayResult = function(data){
        $scope.testResult = JSON.stringify(data, null, 4);
//        $scope.testResult = $sce.trustAsHtml(library.json.prettyPrint(data));
    };

    $scope.logout = function () {

        $sessionStorage.token = null;
        $window.location.href = $scope.server + '/realms/' + $scope.realm + '/tokens/logout?redirect_uri=' + $scope.redirect_uri;
    };

    $scope.validateToken = function () {
        $window.open($scope.server + '/realms/' + $scope.realm + '/tokens/validate?access_token=' + $scope.access_token, '_blank');
    };

    $scope.testToken = function () {
        var params = 'access_token=' + $scope.access_token;
        $http.get($scope.service + '?' + params)
                .success(function (data, status) {
                    $scope.addAlert('success', 'Successful service test (' + status + ')');

                    $scope.displayResult(data);
                }).error(function (data, status) {

            $scope.addAlert('warning', 'Failed service test (' + status + ')');
        });
    };

    $scope.refreshToken = function () {

        $http.post($scope.server + '/realms/' + $scope.realm + '/tokens/refresh',
                'refresh_token=' + $scope.refresh_token,
                {'headers': {
                        'Authorization': getBasicKey(),
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }})
                .success(function (data) {
                    $sessionStorage.token = data;
                    $scope.access_token = $sessionStorage.token.access_token;
                    $scope.refresh_token = $sessionStorage.token.refresh_token;
                    $scope.displayResult(data);
                    $scope.addAlert('success', 'Token Refreshed');
                }).error(function () {
        });
    };

    $scope.saveValues = function () {
        var def = $q.defer();

        $sessionStorage.client_id = $scope.client_id;
        $sessionStorage.redirect_uri = $scope.redirect_uri;
        $sessionStorage.secret = $scope.secret;
        $sessionStorage.server = $scope.server;
        $sessionStorage.service = $scope.service;
        $sessionStorage.realm = $scope.realm;

        def.resolve("Values stored.");
        return def.promise;
    };

    $scope.getAuthorizationCode = function () {
        var loginEndpoint = $scope.server + '/realms/' + $scope.realm + '/tokens/login';

        this.saveValues().then(function () {
            $scope.loginLink = loginEndpoint + '?client_id=' + $scope.client_id + '&redirect_uri=' + $scope.redirect_uri + '&response_type=code';
            $window.location.href = $scope.loginLink;
        });

    };

    $scope.alerts = [];

    $scope.addAlert = function (type, msg) {
        $scope.alerts.push({type: type, msg: msg});
    };

    $scope.closeAlert = function (index) {
        $scope.alerts.splice(index, 1);
    };

    $scope.copyConfirm = function () {
        this.addAlert("success", "Copied");
    };

});

oauthTest.factory('AlertingService', function () {
    return {
    };
});