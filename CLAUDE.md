# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Spring Boot 4.0 REST API server for the URL Sentinel Android application.

- **Spring Boot 4.0** on **Spring Framework 7.0**
- **Java 17+** required (compatible up to Java 25)
- **Gradle 8.14+** or 9.x (Kotlin DSL)
- **Language**: Kotlin

## Build & Run Commands

- **Build**: `./gradlew build`
- **Run**: `./gradlew bootRun`
- **Test all**: `./gradlew test`
- **Test single class**: `./gradlew test --tests "com.example.ClassName"`
- **Test single method**: `./gradlew test --tests "com.example.ClassName.methodName"`
- **Clean build**: `./gradlew clean build`

## Architecture

The system follows a **security-first, clean layered architecture**:

```
[ Android Client ]
        ↓
[ Sentinel Server (Spring Boot) ]
   ├─ Verification Engine  → SSL/TLS MITM detection (ALWAYS FIRST)
   ├─ Rule Engine          → URL phishing detection (conditional, only if SSL ≥70)
   ├─ Decision Engines     → Verdict aggregation
   ├─ AI Adapter           → External AI service interface
   └─ Policy Store         → Configuration (YAML / Properties)
        ↓
[ AI Service (FastAPI + LightGBM) ]
```

- **API style**: REST, serving an Android client
- **Security-first flow**: SSL verification runs before URL analysis
- Spring Boot plugin: `org.springframework.boot`
- Dependency management: `io.spring.dependency-management`
- Snapshot repo required: `https://repo.spring.io/snapshot`

### Key Components

**Verification Engine** (`com.seheon99.urlsentinel.verification`):
- `VerificationCheck` fun interface → implemented by check components
- `VerificationEngine` service → orchestrates checks and aggregates scores
- `ServerDataFetcher` → fetches server-side TLS metadata via HTTPS connection
- `VerificationDecisionEngine` → maps scores to three-tier verdicts
- **Six verification checks (all auto-discovered `@Component`):**
  - `SpkiMatchCheck` - Public key comparison (+50/-40) - **Critical check**
  - `ChainValidatesCheck` - Certificate chain validation (+10/-10)
  - `IpAsnMatchCheck` - ASN comparison for DNS hijacking detection (+20/-20)
  - `CtLogPresenceCheck` - Certificate Transparency validation (+30/-15)
  - `TlsMetadataMatchCheck` - Protocol/cipher/ALPN comparison (+10/-10)
  - `MultiRegionConsistencyCheck` - Multi-vantage point check (+5/0, disabled by default)
- Returns `VerificationResult` with verdict, score (0-100), check details, and server certificate
- **Three-tier verdicts:**
  - `LIKELY_LEGITIMATE` (score ≥70): Proceed with URL analysis
  - `SUSPICIOUS` (20 ≤ score < 70): Ambiguous indicators
  - `LIKELY_INTERCEPTION` (score < 20): Strong MITM indicators, skip URL analysis
- **SSL-first flow:** URL analysis only runs if verification score ≥70

**Supporting Services** (`com.seheon99.urlsentinel.verification`):
- `CertificateUtils` - PEM parsing, SPKI extraction, chain validation
- `AsnLookupService` - ASN lookups via ipapi.co (fail-open, 3s timeout)
- `CertificateTransparencyService` - SCT extension checking

**Rule Engine** (`com.seheon99.urlsentinel.rule`):
- `PhishingRule` fun interface → implemented by rule components
- `RuleEngine` service → executes all rules and returns results
- Each rule is a `@Component` auto-discovered by Spring
- Returns `List<RuleResult>` for decision engine
- **Only runs after SSL verification passes (score ≥70)**

**Decision Engines**:
- `VerificationDecisionEngine` (`com.seheon99.urlsentinel.verification`) → maps SSL scores to three-tier verdicts
- `DefaultDecisionEngine` (`com.seheon99.urlsentinel.decision`) → aggregates phishing rule results into ALLOW/REJECT
- Uses `VerdictProperties` and `VerificationProperties` from Policy Store

**AI Adapter** (`com.seheon99.urlsentinel.adapter`):
- `AiAdapter` interface → abstracts AI service communication
- `RestAiAdapter` → HTTP REST implementation for url-sentinel-ai
- Used by `AiModelRule` for ML-based phishing detection
- Best-effort with fail-open behavior

**Network Features** (`com.seheon99.urlsentinel.network`):
- `NetworkFeaturesService` → collects DNS/SSL/HTTP features
- DNS: `time_response`, `qty_ip_resolved` (using `InetAddress`)
- SSL: `tls_ssl_certificate` (0/1/-1, direct HTTPS connection)
- HTTP: `qty_redirects` (follows redirect chain with HEAD requests)
- Configuration: Three-tier enable/disable (master + per-feature)
- Timeouts: 5s for HTTP, 10s for SSL
- Error handling: Failed features return -1.0

**Policy Store** (`com.seheon99.urlsentinel.config`):
- `@ConfigurationProperties` with `@ConfigurationPropertiesScan`
- `VerificationProperties` - SSL verification thresholds and per-check scoring
- `VerdictProperties` - Phishing detection policy
- `AiProperties`, `NetworkFeaturesProperties`, etc.
- See `application.yml` for all configurable values
- Environment variables: `URLSENTINEL_*` prefix

## API Changes (Post-Refactoring)

**POST /analyze** - Security-first endpoint:
- **Request**: Requires `url` (string) and `clientObservation` (object with full TLS metadata)
- **Response**: Always includes `sslVerification` (verdict, score, checks); `urlCheck` is optional (only if SSL passed)
- **Breaking change**: `clientFingerprint` removed, replaced with comprehensive `clientObservation`
- **Flow**: SSL verification → (if score ≥70) → URL phishing detection

## MCP rules

- Always use Context7 MCP when I need library/API documentation, code generation, setup or configuration steps without me having to explicitly ask.
