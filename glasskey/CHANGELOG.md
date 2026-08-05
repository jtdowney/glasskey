# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-rc1] - 2026-08-04

### Added

- Registration and authentication ceremonies with `start_registration` and `start_authentication`
- Autofill-mediated authentication with `start_conditional_authentication`
- Decoders for the ceremony options JSON produced by glasslock
- Capability detection with `supports_webauthn`, `supports_platform_authenticator`, and `supports_webauthn_autofill`

[1.0.0-rc1]: https://github.com/jtdowney/glasskey/releases/tag/glasskey-v1.0.0-rc1
