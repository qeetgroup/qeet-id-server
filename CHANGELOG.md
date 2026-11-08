# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first release, 1.0.0, is in preparation. No version has been published yet.

### Added

- Sign-in requests reach the native Qeet ID apps: Apple Push Notification service for iOS (token-based,
  `APNS_AUTH_KEY`, `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_BUNDLE_ID`, `APNS_SANDBOX`) and Firebase Cloud Messaging
  for Android (`FCM_SERVICE_ACCOUNT`). Each phone is sent through the service that issued its token; Expo tokens
  still go to Expo. A service without credentials is off; a phone it would serve is not sent the request but
  finds it when the app opens, and the sign-in no longer fails for that phone alone.
- `POST /v1/mfa/push/devices/{id}/push-token`: a linked phone replaces the push token its platform rotated,
  with its unexpired device credential.
- `POST /v1/mfa/push/devices/{id}/pending`: a linked phone lists the sign-in requests waiting on its account,
  with its unexpired device credential, so a request whose push was late or lost can still be answered.
- The pairing claim answers the linked account's email (`account.email`), so the app can name it.
- A sign-in or step-up request for a phone records where it came from (`context.location`, such as
  "Bengaluru, India"), from the trusted proxy's country and city headers, so the phone can show it.

### Fixed

- A request whose client hung up or gave up waiting is answered 499 and noted at info level, not logged as an
  unhandled error and counted as a 500.

