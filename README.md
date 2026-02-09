# URL Sentinel Server

REST API server for phishing URL detection and SSL/TLS verification. Provides three key security features:

1. **SSL/TLS MITM detection**: Six-check verification system that detects man-in-the-middle attacks, DNS hijacking, and rogue certificates
2. **AI-powered phishing detection**: Machine learning model with network feature analysis for advanced threat detection
3. **Rule-based URL analysis**: Evaluates URLs against configurable detection rules and returns an ALLOW or REJECT verdict

## Tech Stack

- Spring Boot 4.0 / Spring Framework 7.0
- Kotlin 2.2
- Java 17+
- Gradle 8.14+ (Kotlin DSL)

## Getting Started

```bash
# Build
./gradlew build

# Run
./gradlew bootRun

# Test
./gradlew test
```

The server starts on `http://localhost:8080` by default.

## API

### Analyze URL

```
POST /analyze
Content-Type: application/json
```

**Security-first endpoint** that performs SSL/TLS verification before URL phishing analysis. SSL verification is **mandatory** - URL analysis only runs if SSL passes with score ≥70.

**Request:**
```json
{
  "url": "https://example.com",
  "clientObservation": {
    "certificateChain": ["-----BEGIN CERTIFICATE-----\n..."],
    "serverIp": "93.184.216.34",
    "serverAsn": 15133,
    "tlsProtocol": "TLSv1.3",
    "cipherSuite": "TLS_AES_128_GCM_SHA256",
    "alpnProtocol": "h2"
  }
}
```

**Response (SSL passed):**
```json
{
  "sslVerification": {
    "verdict": "LIKELY_LEGITIMATE",
    "totalScore": 90,
    "checks": [
      {
        "name": "SPKI_MATCH",
        "passed": true,
        "score": 50,
        "message": "Subject Public Key Info matches"
      },
      {
        "name": "CHAIN_VALIDATES",
        "passed": true,
        "score": 10,
        "message": "Certificate chain is valid and trusted"
      },
      {
        "name": "IP_ASN_MATCH",
        "passed": true,
        "score": 20,
        "message": "ASN matches (AS15133)"
      },
      {
        "name": "CT_LOG_PRESENCE",
        "passed": true,
        "score": 30,
        "message": "Certificate has CT log entry"
      },
      {
        "name": "TLS_METADATA_MATCH",
        "passed": false,
        "score": -10,
        "message": "TLS metadata MISMATCH (1/3 fields match)"
      }
    ],
    "serverCertificate": {
      "subject": "CN=example.com",
      "issuer": "CN=DigiCert TLS RSA SHA256 2020 CA1",
      "validFrom": "2024-01-30T00:00:00Z",
      "validTo": "2025-03-01T23:59:59Z",
      "isExpired": false,
      "spki": "7ab0797e7dd168b228be3bddb49623c9a7b4596b58fd98ce57b2c8135577c31c"
    }
  },
  "urlCheck": {
    "verdict": "ALLOW",
    "reasons": [],
    "riskScore": 0
  }
}
```

**Response (SSL failed - URL check skipped):**
```json
{
  "sslVerification": {
    "verdict": "LIKELY_INTERCEPTION",
    "totalScore": 15,
    "checks": [
      {
        "name": "SPKI_MATCH",
        "passed": false,
        "score": -40,
        "message": "Subject Public Key Info MISMATCH - possible MITM attack"
      },
      {
        "name": "CHAIN_VALIDATES",
        "passed": false,
        "score": -40,
        "message": "Certificate chain validation FAILED"
      },
      {
        "name": "IP_ASN_MATCH",
        "passed": false,
        "score": -20,
        "message": "ASN MISMATCH - possible DNS hijacking"
      },
      {
        "name": "CT_LOG_PRESENCE",
        "passed": true,
        "score": 30,
        "message": "Certificate has CT log entry"
      },
      {
        "name": "TLS_METADATA_MATCH",
        "passed": true,
        "score": 10,
        "message": "TLS metadata matches (3/3 fields)"
      }
    ],
    "serverCertificate": { "..." }
  },
  "urlCheck": null
}
```

#### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | Yes | URL to analyze (must be HTTPS) |
| `clientObservation` | object | Yes | Client-observed TLS connection metadata |
| `clientObservation.certificateChain` | string[] | Yes | PEM-encoded X.509 certificates (leaf first) |
| `clientObservation.serverIp` | string | Yes | IP address client connected to |
| `clientObservation.serverAsn` | number | No | Autonomous System Number of server IP |
| `clientObservation.tlsProtocol` | string | Yes | TLS protocol version (e.g., "TLSv1.3") |
| `clientObservation.cipherSuite` | string | Yes | Negotiated cipher suite |
| `clientObservation.alpnProtocol` | string | No | ALPN negotiation result (e.g., "h2") |

#### Response Fields

| Field | Description |
|-------|-------------|
| `sslVerification` | **Always present** - SSL/TLS verification results |
| `sslVerification.verdict` | Three-tier: `LIKELY_LEGITIMATE` (≥70), `SUSPICIOUS` (20-69), `LIKELY_INTERCEPTION` (<20) |
| `sslVerification.totalScore` | Aggregated score from all checks (0-100) |
| `sslVerification.checks` | Individual check results with scores |
| `sslVerification.serverCertificate` | Server certificate details |
| `urlCheck` | **Conditional** - Only present if SSL score ≥70 |
| `urlCheck.verdict` | `ALLOW` or `REJECT` (from phishing detection) |
| `urlCheck.reasons` | List of triggered rules |
| `urlCheck.riskScore` | Phishing risk score (0-100) |

**Validation:**
- URL must not be blank (returns 400)
- URL must use HTTPS protocol (SSL verification requires TLS)
- `clientObservation` is mandatory (cannot skip SSL verification)

## SSL/TLS Verification Checks

The verification system runs **6 independent checks** that compare client-observed TLS metadata against server-side observations to detect MITM attacks:

| Check | Pass/Fail Score | Purpose |
|-------|----------------|---------|
| **SPKI_MATCH** | +50 / -40 | Compares public keys - different keys indicate MITM |
| **IP_ASN_MATCH** | +20 / -20 | Verifies network location - detects DNS hijacking |
| **CT_LOG_PRESENCE** | +30 / -15 | Checks Certificate Transparency - detects rogue/self-signed certs |
| **TLS_METADATA_MATCH** | +10 / -10 | Compares protocol/cipher/ALPN - detects connection tampering |
| **CHAIN_VALIDATES** | +10 / -40 | Validates certificate chain against system trust store |
| **MULTI_REGION_CONSISTENCY** | +5 / 0 | *(Optional, disabled by default)* Multi-vantage point check |

### Verdict Thresholds

- **LIKELY_LEGITIMATE** (score ≥ 70): Connection appears authentic, proceed with URL analysis
- **SUSPICIOUS** (20 ≤ score < 70): Some checks failed but not conclusive
- **LIKELY_INTERCEPTION** (score < 20): Strong indicators of MITM attack, URL analysis skipped

### Example Scenarios

**Legitimate connection (all checks pass):**
```
SPKI: +50, ASN: +20, CT: +30, TLS: +10, CHAIN: +10 = 120 → capped at 100 → LIKELY_LEGITIMATE
```

**MITM attack (SPKI fails, others pass):**
```
SPKI: -40, ASN: +20, CT: +30, TLS: +10, CHAIN: +10 = 30 → SUSPICIOUS
```

**Self-signed MITM (multiple failures):**
```
SPKI: -40, ASN: -20, CT: -15, TLS: -10, CHAIN: -40 = -125 → clamped to 0 → LIKELY_INTERCEPTION
```

## URL Phishing Detection Rules

**Note:** URL analysis only runs if SSL verification passes with score ≥70.

| Rule | Code | Severity | Description |
|------|------|----------|-------------|
| **AI Model** | `AI_MODEL_PHISHING` | CRITICAL | LightGBM ensemble model with network features detects phishing |
| IP Address Domain | `IP_ADDRESS_DOMAIN` | CRITICAL | Host is an IP address instead of a domain |
| Suspicious Keyword | `SUSPICIOUS_KEYWORD` | MAJOR | URL contains keywords like login, verify, bank |
| URL Shortener | `URL_SHORTENER` | MAJOR | Uses a known URL shortener (bit.ly, tinyurl, etc.) |
| Excessive Subdomains | `EXCESSIVE_SUBDOMAINS` | MAJOR | Too many subdomain levels |
| Suspicious TLD | `SUSPICIOUS_TLD` | MAJOR | Uses a suspicious top-level domain (.xyz, .tk, etc.) |
| URL Too Long | `URL_TOO_LONG` | MINOR | URL exceeds length threshold |
| Excessive Special Chars | `EXCESSIVE_SPECIAL_CHARS` | MINOR | Too many special characters |
| Encoded Characters | `ENCODED_CHARACTERS` | MINOR | Excessive percent-encoded characters |

### AI Model Rule

The AI model rule integrates with the [url-sentinel-ai](https://github.com/seheon99/url-police-ai) service, which uses a LightGBM ensemble model trained on 14 network features:

**Collected Network Features:**
- `time_response` - DNS lookup time in milliseconds
- `qty_ip_resolved` - Number of IP addresses resolved
- `tls_ssl_certificate` - SSL certificate status (0=HTTP, 1=valid HTTPS, -1=error)
- `qty_redirects` - Number of HTTP redirects followed

**Not Yet Implemented** (default to -1):
- Advanced DNS: `qty_nameservers`, `qty_mx_servers`, `ttl_hostname`
- WHOIS: `time_domain_activation`, `time_domain_expiration`
- Search index: `url_google_index`, `domain_google_index`
- Other: `asn_ip`, `domain_spf`, `url_shortened`

Network features are collected on a best-effort basis with fail-open behavior. If feature collection fails, the AI model still runs with missing values (-1).

## Verdict Logic

The server returns `REJECT` if any of the following conditions are met:

- Any **CRITICAL** rule triggers
- **2 or more** MAJOR rules trigger
- Total risk score reaches **50** or higher

Severity weights: CRITICAL = 40, MAJOR = 20, MINOR = 10.

## Configuration

All thresholds, checks, and rules are configurable in `application.yml` or via environment variables:

```bash
# SSL Verification
URLSENTINEL_VERIFICATION_ENABLED=true
URLSENTINEL_VERIFICATION_LEGITIMATE_THRESHOLD=70
URLSENTINEL_VERIFICATION_SUSPICIOUS_THRESHOLD=20

# Individual check configuration
URLSENTINEL_VERIFICATION_CHECKS_SPKI_MATCH_ENABLED=true
URLSENTINEL_VERIFICATION_CHECKS_SPKI_MATCH_PASS_SCORE=50
URLSENTINEL_VERIFICATION_CHECKS_SPKI_MATCH_FAIL_SCORE=-40

URLSENTINEL_VERIFICATION_CHECKS_IP_ASN_MATCH_ENABLED=true
URLSENTINEL_VERIFICATION_CHECKS_IP_ASN_MATCH_PASS_SCORE=20
URLSENTINEL_VERIFICATION_CHECKS_IP_ASN_MATCH_FAIL_SCORE=-20

# ... (similar for ct-log, tls-metadata, chain-validation, multi-region)

# Rule thresholds
URLSENTINEL_RULES_MAX_URL_LENGTH=150
URLSENTINEL_RULES_SPECIAL_CHAR_THRESHOLD=10
URLSENTINEL_VERDICT_MAJOR_COUNT_THRESHOLD=3
URLSENTINEL_VERDICT_RISK_SCORE_THRESHOLD=60

# AI service
URLSENTINEL_AI_BASE_URL=http://localhost:8000

# Network features
URLSENTINEL_NETWORK_FEATURES_ENABLED=true
URLSENTINEL_NETWORK_FEATURES_DNS_ENABLED=true
URLSENTINEL_NETWORK_FEATURES_SSL_ENABLED=true
URLSENTINEL_NETWORK_FEATURES_HTTP_ENABLED=true
URLSENTINEL_NETWORK_FEATURES_HTTP_CONNECT_TIMEOUT=5000
URLSENTINEL_NETWORK_FEATURES_HTTP_READ_TIMEOUT=5000
URLSENTINEL_NETWORK_FEATURES_HTTP_MAX_REDIRECTS=10
```

See [`application.yml`](src/main/resources/application.yml) for the full configuration reference.

## Architecture

The system follows a **security-first, clean layered architecture**:

```
[ Android Client ]
        ↓
[ Sentinel Server (Spring Boot) ]
   ├─ Verification Engine  → SSL/TLS MITM detection (runs FIRST)
   ├─ Rule Engine          → URL phishing detection (conditional)
   ├─ Decision Engine      → Aggregates results into verdicts
   ├─ AI Adapter           → Interfaces with external AI service
   └─ Policy Store         → Configuration (YAML / Properties)
        ↓
[ AI Service (FastAPI + LightGBM) ]
```

### Request Flow (SSL-First)

```
POST /analyze
  -> UrlAnalyzeController
    |
    +---> 1. VerificationEngine (MANDATORY, ALWAYS FIRST)
    |       ├─ ServerDataFetcher
    |       |   └─ Fetches server-side TLS metadata
    |       ├─ SpkiMatchCheck
    |       ├─ ChainValidatesCheck
    |       ├─ IpAsnMatchCheck
    |       ├─ CtLogPresenceCheck
    |       ├─ TlsMetadataMatchCheck
    |       └─ MultiRegionConsistencyCheck
    |       |
    |       └─ VerificationDecisionEngine
    |           ├─ Calculates total score (0-100)
    |           └─ Returns: LIKELY_LEGITIMATE / SUSPICIOUS / LIKELY_INTERCEPTION
    |
    +---> 2. RuleEngine (ONLY if SSL score ≥ 70)
    |       ├─ AiModelRule
    |       |   ├─ NetworkFeaturesService (DNS, SSL, HTTP features)
    |       |   └─ AiAdapter → POST /classify to AI service
    |       ├─ UrlLengthRule
    |       ├─ IpAddressDomainRule
    |       ├─ SuspiciousKeywordRule
    |       └─ [Other PhishingRule implementations...]
    |       |
    |       └─ DecisionEngine (DefaultDecisionEngine)
    |           ├─ Policy Store (VerdictProperties)
    |           └─ Returns: ALLOW or REJECT verdict
    |
    └─ UrlAnalyzeResponse
        ├─ sslVerification (always present)
        └─ urlCheck (only if SSL passed)
```

### Component Details

**Verification Engine:**
- Orchestrates SSL/TLS verification checks (always runs first)
- Each check implements `VerificationCheck` fun interface
- Checks are auto-discovered by Spring via `@Component`
- Fetches server-side TLS data and compares with client observations
- Returns aggregated score (0-100) and three-tier verdict
- Fail-open for external services (ASN lookup, CT logs)

**Rule Engine:**
- Coordinates execution of all `PhishingRule` implementations (only if SSL ≥70)
- Each rule is auto-discovered by Spring via `@Component`
- Rules evaluate independently and return `RuleResult` (triggered, severity, message)
- Adding new rules: create a single file implementing `PhishingRule` interface

**Decision Engine:**
- Two separate engines:
  - `VerificationDecisionEngine`: Maps SSL scores to verdicts
  - `DefaultDecisionEngine`: Aggregates phishing rule results
- Default phishing policy: REJECT if CRITICAL rule triggers, ≥2 MAJOR rules, or risk score ≥50
- Extensible: implement interfaces for custom logic

**AI Adapter:**
- Abstracts communication with external AI service
- Current implementation: `RestAiAdapter` (HTTP REST)
- Sends URL + network features → receives phishing probability
- Fail-open: AI unavailability doesn't block URL checks

**Policy Store:**
- Configuration via `application.yml` and `@ConfigurationProperties`
- Environment variables: `URLSENTINEL_*` prefix
- Separate config for verification checks and phishing rules
- Supports runtime configuration updates

**Network Features Collection:**
- DNS: Uses `InetAddress.getAllByName()` for IP resolution and timing
- SSL: Direct HTTPS connection for certificate validation
- HTTP: Follows redirect chain with HEAD requests and configurable timeouts
- Error handling: Individual feature failures return -1.0 (missing value)
- Performance: Sequential collection, ~500-2000ms worst case

## License

All rights reserved.
