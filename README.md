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
## 🔒 Logging Policy & Defaults

### Default Logging Behavior (when no flags passed)

| Build Mode | ERROR | WARN | INFO | DEBUG |
|-----------|:-----:|:----:|:----:|:-----:|
| **PROD**  | ✅ ON  | ❌ OFF | ❌ OFF | ❌ OFF |
| **BENCH** | ✅ ON  | ❌ OFF | ❌ OFF | ❌ OFF |
| **DEV**   | ✅ ON  | ✅ ON  | ✅ ON  | ✅ ON  |

> **Note:** “ON” = logging enabled by default; “OFF” = disabled by default.

---

### Configurable via Makefile Flags

| Flag(s) | PROD | BENCH | DEV | Effect |
|--------|------|-------|-----|--------|
| `WARN=1` / `-D__LOG_ENABLE_WARN__` | ❌ Blocked | ✅ Allowed | ✅ Allowed | Enables WARN logs |
| `INFO=1` / `-D__LOG_ENABLE_INFO__` | ❌ Blocked | ✅ Allowed | ✅ Allowed | Enables INFO logs |
| `DEBUG=1` / `-D__LOG_ENABLE_DEBUG__` | ❌ Blocked | ❌ Blocked | ✅ Allowed | Enables DEBUG logs (DEV only) |
| `LOG_ALL=1` (expands to WARN+INFO+DEBUG in DEV) | ❌ Blocked | ❌ Blocked | ✅ Allowed | Enables WARN, INFO, DEBUG (DEV only) |

> 🚨 **Security policy summary**:  
> * PROD — only ERROR logs allowed (no WARN / INFO / DEBUG)  
> * BENCH — ERROR always; WARN/INFO disabled in default build and optionally enabled using flags; DEBUG forbidden  
> * DEV — all logs types enabled by default and optionally controlled by flags

---

### Examples of Allowed / Disallowed Makes

| Make Command | Result |
|-------------|--------|
| `make` or `make PROD=1` | PROD defaults → ERROR only |
| `make BENCH=1` | BENCH defaults → ERROR only |
| `make BENCH=1 WARN=1 INFO=1` | ERROR + WARN + INFO logs enabled |
| `make BENCH=1 DEBUG=1` | ❌ Build fails — DEBUG forbidden in BENCH |
| `make PROD=1 WARN=1` | ❌ Build fails — WARN forbidden in PROD |
| `make PROD=0` (DEV mode) | All logs by default |
| `make PROD=0 DEBUG=0 INFO=0 WARN=0` | Only ERROR logs — minimal logs in DEV |

---

### Why This Policy

- **PROD** → Zero-trust hardened deployment, no internal info leakage
- **BENCH** → Accurate performance testing, no disruptive DEBUG logs
- **DEV** → Maximum visibility and diagnostics

---

### Mandatory Hard Rules

- TLS **always enabled** (never plaintext TCP)
- mTLS **required in PROD and BENCH**
- **DEBUG forbidden** outside DEV
- **Sanitizers allowed only in DEV**
- Invalid combinations must fail hard (Makefile + compile checks)

# TCP_Server_with_ECDSA

[![Build Validation](https://github.com/rxa1031/TCP_Server_with_ECDSA/actions/workflows/build-validation.yml/badge.svg)](https://github.com/rxa1031/TCP_Server_with_ECDSA/actions/workflows/build-validation.yml)
[![Hardened PROD Build](https://github.com/rxa1031/TCP_Server_with_ECDSA/actions/workflows/hardened-prod.yml/badge.svg)](https://github.com/rxa1031/TCP_Server_with_ECDSA/actions/workflows/hardened-prod.yml)

High-assurance mutual-TLS server implementation with Defence-style build enforcement.
