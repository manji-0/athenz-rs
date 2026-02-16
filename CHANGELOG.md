# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

- Docs: reorganized README and added core documentation guides
- Docs: added async-client/async-validate README examples and feature notes
- Test: added tokio-based async HTTP path tests for async clients/validation
- Metadata: set MSRV to 1.88
- Breaking: JwtValidationOptions adds allow_es512; struct literal initializers must include the new field (prefer constructor helpers).
- Breaking: JwtValidationOptions adds validate_nbf; struct literal initializers must include the new field (prefer constructor helpers).

## 0.1.0

- Initial release
