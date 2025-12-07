🔐 Licensed under Apache License 2.0 — free to use with attribution, no warranty.
All third-party components remain under their original licenses.
See the [LICENSE](LICENSE) file for full license text.

### Third-Party Licenses

This project uses OpenSSL and may include or depend on libraries and software
provided by third parties. These components are **licensed separately** by
their respective authors.

All copyrights, trademarks, and licenses for any third-party software remain
the property of their owners. Inclusion in this project does not grant
additional rights to those components. Users must comply with the applicable
third-party license terms.

## Build Mode + Logging Enforcement Rules (Policy v1.0)

| Mode  | TLS | mTLS | Sanitizers | ERROR | WARN | INFO | DEBUG |
|-------|-----|------|------------|-------|------|------|-------|
| PROD  | ✔   | ✔    | ❌         | ✔     | opt  | opt  | ❌    |
| DEV   | ✔   | opt  | ✔ (Opt-B)  | ✔     | ✔    | ✔    | ✔     |
| BENCH | ✔   | opt  | ❌         | ✔     | ❌    | ❌    | ❌    |

### Mandatory Hard Rules

- TLS can **never** be disabled
- mTLS **must** be enabled in hardened builds (PROD/BENCH)
- **DEBUG is forbidden** in PROD and BENCH builds
- **BENCH = ERROR-only**
- Sanitizers only permitted in DEV mode

Any change that violates these rules **must be rejected automatically**  
and flagged as a **policy violation**.

# TCP_Server_with_ECDSA

[![Build Validation](https://github.com/rxa1031/TCP_Server_with_ECDSA/actions/workflows/build-validation.yml/badge.svg)](https://github.com/rxa1031/TCP_Server_with_ECDSA/actions/workflows/build-validation.yml)
[![Hardened PROD Build](https://github.com/rxa1031/TCP_Server_with_ECDSA/actions/workflows/hardened-prod.yml/badge.svg)](https://github.com/rxa1031/TCP_Server_with_ECDSA/actions/workflows/hardened-prod.yml)

High-assurance mutual-TLS server implementation with Defence-style build enforcement.
