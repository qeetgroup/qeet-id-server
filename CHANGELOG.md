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
  still go to Expo. A service without credentials is off, and a phone it would serve is skipped and logged.
- `POST /v1/mfa/push/devices/{id}/push-token`: a linked phone replaces the push token its platform rotated,
  with its unexpired device credential.
- The pairing claim answers the linked account's email (`account.email`), so the app can name it.
