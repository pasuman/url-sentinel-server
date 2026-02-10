# URL Sentinel Server

REST API server for URL phishing detection. Provides AI-powered and rule-based analysis to detect phishing URLs.

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

Analyzes a URL for phishing indicators using both AI models and rule-based detection.

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response (Safe URL):**
```json
{
  "verdict": "ALLOW",
  "reasons": [],
  "riskScore": 0
}
```

**Response (Phishing Detected):**
```json
{
  "verdict": "REJECT",
  "reasons": [
    {
      "code": "IP_ADDRESS_DOMAIN",
      "severity": "CRITICAL",
      "message": "URL uses an IP address"
    },
    {
      "code": "SUSPICIOUS_KEYWORD",
      "severity": "MAJOR",
      "message": "URL contains: login"
    }
  ],
  "riskScore": 60
}
```

#### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | Yes | URL to analyze |

#### Response Fields

| Field | Description |
|-------|-------------|
| `verdict` | `ALLOW` or `REJECT` |
| `reasons` | List of triggered detection rules |
| `riskScore` | Phishing risk score (0-100) |

**Validation:**
- URL must not be blank (returns 400)

## Phishing Detection Rules

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

All thresholds and rules are configurable in `application.yml` or via environment variables:

```bash
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

The system follows a clean layered architecture:

```
[ Android Client ]
        ↓
[ Sentinel Server (Spring Boot) ]
   ├─ Rule Engine          → URL phishing detection
   ├─ Decision Engine      → Aggregates results into verdicts
   ├─ AI Adapter           → Interfaces with external AI service
   └─ Policy Store         → Configuration (YAML / Properties)
        ↓
[ AI Service (FastAPI + LightGBM) ]
```

### Request Flow

```
POST /analyze
  -> UrlAnalyzeController
    |
    +---> RuleEngine
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
```

### Component Details

**Rule Engine:**
- Coordinates execution of all `PhishingRule` implementations
- Each rule is auto-discovered by Spring via `@Component`
- Rules evaluate independently and return `RuleResult` (triggered, severity, message)
- Adding new rules: create a single file implementing `PhishingRule` interface

**Decision Engine:**
- `DefaultDecisionEngine`: Aggregates phishing rule results
- Default policy: REJECT if CRITICAL rule triggers, ≥2 MAJOR rules, or risk score ≥50
- Extensible: implement interface for custom logic

**AI Adapter:**
- Abstracts communication with external AI service
- Current implementation: `RestAiAdapter` (HTTP REST)
- Sends URL + network features → receives phishing probability
- Fail-open: AI unavailability doesn't block URL checks

**Policy Store:**
- Configuration via `application.yml` and `@ConfigurationProperties`
- Environment variables: `URLSENTINEL_*` prefix
- Supports runtime configuration updates

**Network Features Collection:**
- DNS: Uses `InetAddress.getAllByName()` for IP resolution and timing
- SSL: Direct HTTPS connection for certificate validation
- HTTP: Follows redirect chain with HEAD requests and configurable timeouts
- Error handling: Individual feature failures return -1.0 (missing value)
- Performance: Sequential collection, ~500-2000ms worst case

## License

All rights reserved.
