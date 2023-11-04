import 'package:oauth2_client/oauth2_client.dart';

/// Implements an OAuth2 client against Reddit
///
/// In order to use this client you need to first create a new OAuth2 App in Reddit autorized apps settings (https://www.reddit.com/prefs/apps)
///
class GozleOAuth2Client extends OAuth2Client {
  GozleOAuth2Client({
    required String redirectUri,
    required String customUriScheme,
    required String authorizeUrl,
  }) : super(
          authorizeUrl: authorizeUrl,
          redirectUri: redirectUri,
          customUriScheme: customUriScheme,
          scopeSeparator: ',',
          credentialsLocation: CredentialsLocation.header,
        );
}
