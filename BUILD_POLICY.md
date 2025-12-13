# BUILD_POLICY.md

## Build Policy & Default Configuration

This document defines the **build modes**, **security levels**, and **user-controllable options** for the `mtls_server` project.  
It is intended as a **human-readable policy reference**.  
The **Makefile is the authoritative enforcement point**.

---

## 1. Build Modes

Exactly **one build mode** must be active at a time.

| Mode  | Purpose                 | Typical Use Case                    |
|------:|-------------------------|-------------------------------------|
| PROD  | Production deployment   | Real deployments                    |
| BENCH | Performance testing     | Benchmarking / latency measurement  |
| DEV   | Development & debugging | Feature development, diagnostics    |

### Mode Selection

| Command            | Selected Mode |
|--------------------|---------------|
| `make`             | PROD          |
| `make PROD=1`      | PROD          |
| `make PROD=0`      | DEV           |
| `make BENCH=1`     | BENCH         |

Invalid or conflicting combinations result in a **hard build error**.

---

## 2. Security Level (SL)

Security Level controls **authentication and trust enforcement**.  
**TLS encryption is always enabled** in all modes.

| SL | Meaning                              | TLS | mTLS | CRL | OCSP | Allowed Modes |
|---:|--------------------------------------|:---:|:----:|:---:|:----:|:-------------|
| 1  | TLS only                             | ON  | Optional | OFF | OFF | DEV only |
| 2  | TLS + mTLS + CRL                     | ON  | Required | ON  | OFF | DEV / PROD / BENCH |
| 3  | TLS + mTLS + CRL + OCSP (future)     | ON  | Required | ON  | ON* | DEV only |

*OCSP support is not implemented yet.*

### Default SL

| Mode  | Default SL | User Override Allowed |
|------:|------------|-----------------------|
| PROD  | 2          | No                    |
| BENCH | 2          | No                    |
| DEV   | 2          | Yes (1, 2, or 3)      |

---

## 3. Mutual TLS (mTLS)

mTLS controls **client certificate authentication**.

| Mode  | Default mTLS  | User Override |
|------:|---------------|---------------|
| PROD  | ON            | Forbidden     |
| BENCH | ON            | Forbidden     |
| DEV   | Depends on SL | Allowed       |

### DEV Default mTLS Behavior

| DEV SL | Default mTLS | Resulting Trust Model            |
|-------:|--------------|----------------------------------|
| 1      | OFF          | TLS only                         |
| 2      | ON           | TLS + mTLS + CRL                 |
| 3      | ON           | TLS + mTLS + CRL (+ OCSP future) |

---

## 4. Certificate & Trust Requirements

| Mode  | Server Cert | Server Key | CA Cert | CRL |
|------:|:-----------:|:----------:|:-------:|:---:|
| PROD  | Required    | Required   | Required | Required |
| BENCH | Required    | Required   | Required | Required |
| DEV   | Conditional | Conditional | Optional | Optional |

---

## 5. Logging Policy

### Default Logging

| Mode  | ERROR | WARN | INFO | DEBUG |
|------:|:-----:|:----:|:----:|:-----:|
| PROD  | ON    | OFF  | OFF  | OFF   |
| BENCH | ON    | OFF  | OFF  | OFF   |
| DEV   | ON    | ON   | ON   | ON    |

### User-Controllable Flags

| Flag  | PROD | BENCH | DEV |
|-------|:----:|:-----:|:---:|
| WARN  | No   | Yes   | Yes |
| INFO  | No   | Yes   | Yes |
| DEBUG | No   | No    | Yes |

---

## 6. Sanitizer Policy

| Mode  | Sanitisers | User Control |
|------:|------------|--------------|
| DEV   | Enabled    | Yes          |
| PROD  | Disabled   | No           |
| BENCH | Disabled   | No           |

---

## 7. Mandatory Rules

- TLS is always enabled
- PROD/BENCH require SL=2 and mTLS enabled
- CRL enforcement applies when SL>=2
- DEV allows controlled relaxation
- Invalid combinations fail at build time

---

## 8. Authoritative Source

The Makefile is the **single source of truth**.
