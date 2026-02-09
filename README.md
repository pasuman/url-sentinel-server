# URL Sentinel Server

REST API server for phishing URL detection and SSL certificate verification. Provides three key security features:

1. **AI-powered phishing detection**: Machine learning model with network feature analysis for advanced threat detection
2. **Rule-based URL analysis**: Evaluates URLs against configurable detection rules and returns an ALLOW or REJECT verdict
3. **SSL certificate verification**: Detects DNS hijacking and MITM attacks by comparing SSL certificate fingerprints

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

Unified endpoint that performs both phishing detection and optional SSL certificate verification.

**Request (URL check only):**
```json
{
  "url": "http://192.168.1.1/login/verify"
}
```

**Request (URL check + SSL verification):**
```json
{
  "url": "https://www.google.com",
  "clientFingerprint": "A1:B2:C3:D4:E5:F6:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
}
```

**Response (URL check only):**
```json
{
  "verdict": "REJECT",
  "reasons": [
    {
      "code": "IP_ADDRESS_DOMAIN",
      "severity": "CRITICAL",
      "message": "URL uses an IP address instead of a domain name"
    },
    {
      "code": "SUSPICIOUS_KEYWORD",
      "severity": "MAJOR",
      "message": "URL contains suspicious keywords: login, verify"
    }
  ],
  "riskScore": 60
}
```

**Response (with SSL verification):**
```json
{
  "verdict": "ALLOW",
  "reasons": [],
  "riskScore": 0,
  "sslVerification": {
    "verdict": "MATCH",
    "serverFingerprint": "A1:B2:C3:...",
    "clientFingerprint": "A1:B2:C3:...",
    "certificateDetails": {
      "subject": "CN=www.google.com",
      "issuer": "CN=GTS CA 1C3",
      "validFrom": "2023-01-01T00:00:00Z",
      "validTo": "2024-01-01T00:00:00Z",
      "isExpired": false
    },
    "message": "Certificate fingerprints match. Connection is secure."
  }
}
```

#### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | Yes | URL to analyze |
| `clientFingerprint` | string | No | SHA-256 certificate fingerprint for SSL verification |

#### Response Fields

| Field | Description |
|-------|-------------|
| `verdict` | `ALLOW` or `REJECT` (from phishing detection) |
| `reasons` | List of triggered rules with code, severity, and message |
| `riskScore` | 0-100, sum of triggered rule weights capped at 100 |
| `sslVerification` | SSL verification results (only present if `clientFingerprint` was provided) |

#### SSL Verification Result

| Field | Description |
|-------|-------------|
| `verdict` | `MATCH` (safe), `MISMATCH` (potential attack), or `ERROR` (unable to verify) |
| `serverFingerprint` | SHA-256 fingerprint of the certificate the server fetched (null on ERROR) |
| `clientFingerprint` | Client's fingerprint echoed back |
| `certificateDetails` | Certificate subject, issuer, validity dates, and expiration status (null on ERROR) |
| `message` | Human-readable explanation of the SSL verdict |

**Validation:**
- URL must not be blank (returns 400)
- If `clientFingerprint` is provided and URL uses HTTP, SSL verification will fail with ERROR verdict

## Detection Rules

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

All rule thresholds and lists are configurable in `application.yml` or via environment variables:

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

### Unified Analyze Flow
```
POST /analyze
  -> UrlAnalyzeController
    |
    +-> RuleEngine (executes all PhishingRule beans)
    |     -> AiModelRule
    |       -> NetworkFeaturesService (collect DNS, SSL, HTTP features)
    |       -> AiClassifyClient (POST to url-sentinel-ai)
    |     -> [Other rules: UrlLengthRule, IpAddressDomainRule, etc.]
    |     -> DefaultVerdictPolicy (aggregates results into ALLOW/REJECT)
    |
    +-> SslCertificateService (if clientFingerprint provided)
          -> fetchCertificate() (HTTPS connection to get server cert)
          -> computeFingerprint() (SHA-256 hash)
          -> Compare with client fingerprint
    |
    -> UrlAnalyzeResponse (combines both results)
```

Each rule implements the `PhishingRule` fun interface and is auto-discovered by Spring as a `@Component`. Adding a new rule requires only creating a single file.

**Network Features Collection:**
- DNS: Uses `InetAddress.getAllByName()` for IP resolution and timing
- SSL: Delegates to `SslCertificateService` for certificate validation
- HTTP: Follows redirect chain with HEAD requests and configurable timeouts
- Error handling: Individual feature failures return -1.0 (missing value)
- Performance: Sequential collection, ~500-2000ms worst case (DNS + SSL + HTTP)

## License

All rights reserved.
