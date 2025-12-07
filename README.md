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

## Build Mode Summary

| Mode  | Purpose | mTLS | Revocation | Logging Defaults | Running Privileges |
|------|---------|------|------------|-----------------|------------------|
| **PROD** | Hardened deployment | Required | Required | ERROR only | Must start as root → chroot + drop to www-data |
| **BENCH** | Performance testing | Required | Required | ERROR only | Must start as root → chroot + drop to www-data |
| **DEV** | Debug + development | Optional | Optional | ERROR+WARN+INFO+DEBUG | No chroot + sanitizers enabled |

> TLS encryption is **always ON** in all modes (no plaintext allowed).

---

### 🔑 Certificate Revocation Policy

This project currently supports **CRL-based** certificate revocation.

| Build Mode | CRL Required? | Notes |
|-----------|:-------------:|------|
| PROD | ✅ Yes | Fail-closed (startup fails if CRL missing/invalid) |
| BENCH | ✅ Yes | Same as PROD |
| DEV | ⚠️ Optional | Fail-open allowed for developer convenience |

> 🔎 **OCSP Status**  
> OCSP is **not implemented yet**.  
> `REVOCATION_LEVEL__ >= 2` is reserved for future OCSP support.  
> DEV mode may experiment with values ≥ 2 — PROD/BENCH builds **reject it**.

---

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

### Mandatory Hard Rules

- TLS **always enabled** (never plaintext TCP)
- mTLS **required in PROD and BENCH**
- **DEBUG forbidden** outside DEV
- **Sanitizers allowed only in DEV**
- OCSP not implemented yet — any `REVOCATION_LEVEL__ >= 2` is rejected in PROD/BENCH
- Invalid combinations must fail hard (Makefile + compile checks)

---

## Valid Build Commands

| Goal | Command |
|------|---------|
| Default hardened production build | `make` |
| Explicit PROD | `make PROD=1` |
| BENCH build | `make BENCH=1` |
| DEV build (mTLS on by default) | `make PROD=0` |
| DEV with mTLS disabled | `make PROD=0 mTLS=0` |
| DEV with DEBUG logging | `make PROD=0 DEBUG=1` |
| DEV all logs enabled | `make PROD=0 LOG_ALL=1` |

> Any forbidden combination **fails** automatically via Makefile and compile-time checks.

---

### Why This Policy

- **PROD** → Zero-trust hardened deployment, no internal info leakage
- **BENCH** → Accurate performance testing, no disruptive DEBUG logs
- **DEV** → Maximum visibility and diagnostics

---

### Testing Policy

> 💡 CI/Test Reminder  
> Only **DEV mode** may build with `REVOCATION_LEVEL__ >= 2`.  
> Hardened builds must fail if OCSP is attempted before implementation.

---

## 🔭 Hardening Roadmap

- Add OCSP support for real-time revocation (upgrade path from CRL-only model)

---

# TCP_Server_with_ECDSA

[![Build Validation](https://github.com/rxa1031/TCP_Server_with_ECDSA/actions/workflows/build-validation.yml/badge.svg)](https://github.com/rxa1031/TCP_Server_with_ECDSA/actions/workflows/build-validation.yml)
[![Hardened PROD Build](https://github.com/rxa1031/TCP_Server_with_ECDSA/actions/workflows/hardened-prod.yml/badge.svg)](https://github.com/rxa1031/TCP_Server_with_ECDSA/actions/workflows/hardened-prod.yml)

High-assurance mutual-TLS server implementation with Defence-style build enforcement.
