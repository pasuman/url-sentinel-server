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

The system follows a clean layered architecture:

```
[ Android Client ]
        ↓
[ Sentinel Server (Spring Boot) ]
   ├─ Rule Engine          → Executes phishing detection rules
   ├─ Decision Engine      → Aggregates results into ALLOW/REJECT verdict
   ├─ AI Adapter           → Interfaces with external AI service
   └─ Policy Store         → Configuration (YAML / Properties)
        ↓
[ AI Service (FastAPI + LightGBM) ]
```

- **API style**: REST, serving an Android client
- Spring Boot plugin: `org.springframework.boot`
- Dependency management: `io.spring.dependency-management`
- Snapshot repo required: `https://repo.spring.io/snapshot`

### Key Components

**Rule Engine** (`com.seheon99.urlsentinel.rule`):
- `PhishingRule` fun interface → implemented by rule components
- `RuleEngine` service → executes all rules and returns results
- Each rule is a `@Component` auto-discovered by Spring
- Returns `List<RuleResult>` for decision engine

**Decision Engine** (`com.seheon99.urlsentinel.decision`):
- `DecisionEngine` interface → aggregates rule results into verdict
- `DefaultDecisionEngine` → configurable policy-based implementation
- Uses `VerdictProperties` from Policy Store
- Returns `Verdict.ALLOW` or `Verdict.REJECT`

**AI Adapter** (`com.seheon99.urlsentinel.adapter`):
- `AiAdapter` interface → abstracts AI service communication
- `RestAiAdapter` → HTTP REST implementation for url-sentinel-ai
- Used by `AiModelRule` for ML-based phishing detection
- Best-effort with fail-open behavior

**Network Features** (`com.seheon99.urlsentinel.network`):
- `NetworkFeaturesService` → collects DNS/SSL/HTTP features
- DNS: `time_response`, `qty_ip_resolved` (using `InetAddress`)
- SSL: `tls_ssl_certificate` (0/1/-1, reuses `SslCertificateService`)
- HTTP: `qty_redirects` (follows redirect chain with HEAD requests)
- Configuration: Three-tier enable/disable (master + per-feature)
- Timeouts: 5s for HTTP, 10s for SSL
- Error handling: Failed features return -1.0

**Policy Store** (`com.seheon99.urlsentinel.config`):
- `@ConfigurationProperties` with `@ConfigurationPropertiesScan`
- `VerdictProperties`, `AiProperties`, `NetworkFeaturesProperties`, etc.
- See `application.yml` for all configurable values
- Environment variables: `URLSENTINEL_*` prefix

## MCP rules

- Always use Context7 MCP when I need library/API documentation, code generation, setup or configuration steps without me having to explicitly ask.
