🔐 Licensed under Apache License 2.0 — free to use with attribution, no warranty.  
All third-party components remain under their original licenses.  
See the [LICENSE](LICENSE) file for full license text.

### Third-Party Licenses

This project uses OpenSSL and may include or depend on software licensed
separately by third-party authors. Users must comply with those terms.

---

# Build Mode Summary

| Mode | Purpose | mTLS | Security Level | Logging Defaults | Running Privileges |
|------|---------|------|----------------|-----------------|------------------|
| **PROD** | Hardened deployment | Required | **2** | ERROR only | Must start as root → chroot + drop to www-data |
| **BENCH** | Performance testing | Required | **2** | ERROR only | Must start as root → chroot + drop to www-data |
| **DEV** | Debug + development | Optional | **1** | ERROR+WARN+INFO+DEBUG | No chroot + sanitizers enabled |

> **TLS encryption is always ON** in all modes (no plaintext allowed).  
> Only authentication enforcement levels change.

---

## 🔐 Security Level (Trust Enforcement Policy)

Controls certificate **authentication strength** (not TLS encryption).

| SECURITY_LEVEL | mTLS | CRL Check | OCSP Check | Allowed Modes | Notes |
|---:|:---:|:---:|:---:|---|---|
| **1** | Optional *(DEV only)* | Optional | Not supported | DEV | Baseline: TLS always ON |
| **2** *(default for PROD/BENCH)* | Required | Required | Not supported | PROD/BENCH/DEV | Hardened baseline |
| **3** *(future)* | Required | Required | Required | PROD | Highest trust enforcement |

✔ Higher number = stronger security guarantees  
✔ Even Level 1 still enforces TLS (server authentication)

---

### 🔎 OCSP Status

OCSP support is **not implemented yet**.

- `SECURITY_LEVEL >= 3` is reserved for future OCSP enablement
- Hardened builds **reject** OCSP requirements until implemented

---

## 🔒 Logging Policy

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
| `WARN=1` / `-D__LOG_ENABLE_WARN__` | ❌ Blocked | ⚙️ Configurable | ⚙️ Configurable | Enables WARN logs |
| `INFO=1` / `-D__LOG_ENABLE_INFO__` | ❌ Blocked | ⚙️ Configurable | ⚙️ Configurable | Enables INFO logs |
| `DEBUG=1` / `-D__LOG_ENABLE_DEBUG__` | ❌ Blocked | ❌ Blocked | ⚙️ Configurable | Enables DEBUG logs (DEV only) |

### 🚨 Security Logging Summary
- **PROD** → only **ERROR** logs allowed (no WARN / INFO / DEBUG)  
- **BENCH** → **ERROR** always; WARN/INFO optional (enabled via flag); DEBUG forbidden  
- **DEV** → All logs configurable for diagnostics  

---

### Mandatory Hard Rules

- TLS **always enabled** (no plaintext TCP)
- mTLS **required in PROD and BENCH**
- **SECURITY_LEVEL >= 2 required** in PROD and BENCH
- **DEBUG forbidden** outside DEV
- Sanitizers enabled only in DEV
- Forbidden combinations **fail hard** (Makefile + compile-time checks)

---

## Valid Build Commands

| Goal | Command |
|------|---------|
| Default hardened PROD build | `make` |
| Explicit PROD build | `make PROD=1` |
| BENCH hardened build | `make BENCH=1` |
| DEV build (all logs ON by default) | `make PROD=0` |
| DEV with mTLS disabled | `make PROD=0 SECURITY_LEVEL=1 mTLS=0` |
| DEV disable INFO/WARN/DEBUG | `make PROD=0 WARN=0 INFO=0 DEBUG=0` |
| DEV disable DEBUG only | `make PROD=0 DEBUG=0` |

> ❌ Hardened builds disallow lowering security or disabling mTLS.

---

## Why This Policy

- **PROD →** Zero-trust hardened deployment
- **BENCH →** Hardened behavior, predictable timing
- **DEV →** Fast iteration & visibility for debugging

---

## Testing Policy

> CI or static builds may temporarily disable enforcement via:
> `__SKIP_SECURITY__=1`  
> **TLS remains ON**, but security checks are not enforced (test-only).

---

## 🔭 Hardening Roadmap

- Implement OCSP validation (`SECURITY_LEVEL=3`)
- Optional:
  - Certificate Transparency
  - HSM-based private key protection
  - Kernel namespace isolation improvements

---

# TCP_Server_with_ECDSA

[![Build Validation](https://github.com/rxa1031/TCP_Server_with_ECDSA/actions/workflows/build-validation.yml/badge.svg)](https://github.com/rxa1031/TCP_Server_with_ECDSA/actions/workflows/build-validation.yml)
[![Hardened PROD Build](https://github.com/rxa1031/TCP_Server_with_ECDSA/actions/workflows/hardened-prod.yml/badge.svg)](https://github.com/rxa1031/TCP_Server_with_ECDSA/actions/workflows/hardened-prod.yml)

High-assurance mutual-TLS server implementation with Defence-grade build enforcement.
