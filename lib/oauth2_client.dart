import 'dart:convert';

import 'package:oauth2_client/authorization_response.dart';
import 'package:oauth2_client/src/oauth2_utils.dart';
import 'package:random_string/random_string.dart';

// import 'package:oauth2_client/src/web_auth.dart';

import 'src/base_web_auth.dart';
import 'src/web_auth.dart'
// ignore: uri_does_not_exist
    if (dart.library.io) 'src/io_web_auth.dart'
// ignore: uri_does_not_exist
    if (dart.library.html) 'src/browser_web_auth.dart';

enum CredentialsLocation { header, body }

class OAuth2Client {
  String redirectUri;
  String customUriScheme;

  String? refreshUrl;
  String? revokeUrl;
  String authorizeUrl;
  String scopeSeparator;

  BaseWebAuth webAuthClient = createWebAuth();
  CredentialsLocation credentialsLocation;

  OAuth2Client({
    required this.authorizeUrl,
    this.refreshUrl,
    this.revokeUrl,
    required this.redirectUri,
    required this.customUriScheme,
    this.credentialsLocation = CredentialsLocation.header,
    this.scopeSeparator = ' ',
  });

  /// Requests an Access Token to the OAuth2 endpoint using the Authorization Code Flow.
  Future<AuthorizationResponse> getAuthCodeFlow({
    required String clientId,
    List<String>? scopes,
    String? clientSecret,
    bool enablePKCE = true,
    bool enableState = true,
    String? state,
    required String codeVerifier,
    required String codeChallenge,
    Function? afterAuthorizationCodeCb,
    Map<String, dynamic>? authCodeParams,
    Map<String, dynamic>? accessTokenParams,
    Map<String, String>? accessTokenHeaders,
    httpClient,
    BaseWebAuth? webAuthClient,
    Map<String, dynamic>? webAuthOpts,
  }) async {
    try {
      var authResp = await requestAuthorization(
          webAuthClient: webAuthClient,
          clientId: clientId,
          scopes: scopes,
          codeChallenge: codeChallenge,
          enableState: enableState,
          state: state,
          customParams: authCodeParams,
          webAuthOpts: webAuthOpts);
      return authResp;
    } catch (exception) {
      rethrow;
    }
  }

  /// Requests an Authorization Code to be used in the Authorization Code grant.
  Future<AuthorizationResponse> requestAuthorization(
      {required String clientId,
      List<String>? scopes,
      String? codeChallenge,
      bool enableState = true,
      String? state,
      Map<String, dynamic>? customParams,
      BaseWebAuth? webAuthClient,
      Map<String, dynamic>? webAuthOpts}) async {
    webAuthClient ??= this.webAuthClient;

    if (enableState) {
      state ??= randomAlphaNumeric(25);
    }

    final authorizeUrl = getAuthorizeUrl(
        clientId: clientId,
        redirectUri: redirectUri,
        scopes: scopes,
        enableState: enableState,
        state: state,
        codeChallenge: codeChallenge,
        customParams: customParams);

    // Present the dialog to the user
    final result = await webAuthClient.authenticate(
        url: authorizeUrl,
        callbackUrlScheme: customUriScheme,
        redirectUrl: redirectUri,
        opts: webAuthOpts);

    return AuthorizationResponse.fromRedirectUri(result, state);
  }

  /// Generates the url to be used for fetching the authorization code.
  String getAuthorizeUrl(
      {required String clientId,
      String responseType = 'code',
      String? redirectUri,
      List<String>? scopes,
      bool enableState = true,
      String? state,
      String? codeChallenge,
      Map<String, dynamic>? customParams}) {
    final params = <String, dynamic>{
      'response_type': responseType,
      'client_id': clientId
    };

    if (redirectUri != null && redirectUri.isNotEmpty) {
      params['redirect_uri'] = redirectUri;
    }

    if (scopes != null && scopes.isNotEmpty) {
      params['scope'] = serializeScopes(scopes);
    }

    if (enableState && state != null && state.isNotEmpty) {
      params['state'] = state;
    }

    if (codeChallenge != null && codeChallenge.isNotEmpty) {
      params['code_challenge'] = codeChallenge;
      params['code_challenge_method'] = 'S256';
    }

    if (customParams != null) {
      params.addAll(customParams);
    }

    return OAuth2Utils.addParamsToUrl(authorizeUrl, params);
  }

  Map<String, String> getAuthorizationHeader(
      {required String clientId, String? clientSecret}) {
    var headers = <String, String>{};

    if ((clientId.isNotEmpty) && (clientSecret != null)) {
      var credentials = base64.encode(utf8.encode('$clientId:$clientSecret'));

      headers['Authorization'] = 'Basic $credentials';
    }

    return headers;
  }

  String serializeScopes(List<String> scopes) {
    return scopes.map((s) => s.trim()).join(scopeSeparator);
  }
}
