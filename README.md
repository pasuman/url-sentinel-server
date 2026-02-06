# URL Police Server

REST API server for rule-based phishing URL detection. Receives a URL from a mobile client, evaluates it against configurable detection rules, and returns an ALLOW or REJECT verdict with reason codes.

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

### Check URL

```
POST /api/v1/url/check
Content-Type: application/json
```

**Request:**
```json
{
  "url": "http://192.168.1.1/login/verify"
}
```

**Response:**
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

| Field | Description |
|-------|-------------|
| `verdict` | `ALLOW` or `REJECT` |
| `reasons` | List of triggered rules with code, severity, and human-readable message |
| `riskScore` | 0-100, sum of triggered rule weights capped at 100 |

## Detection Rules

| Rule | Code | Severity | Description |
|------|------|----------|-------------|
| IP Address Domain | `IP_ADDRESS_DOMAIN` | CRITICAL | Host is an IP address instead of a domain |
| Suspicious Keyword | `SUSPICIOUS_KEYWORD` | MAJOR | URL contains keywords like login, verify, bank |
| URL Shortener | `URL_SHORTENER` | MAJOR | Uses a known URL shortener (bit.ly, tinyurl, etc.) |
| Excessive Subdomains | `EXCESSIVE_SUBDOMAINS` | MAJOR | Too many subdomain levels |
| Suspicious TLD | `SUSPICIOUS_TLD` | MAJOR | Uses a suspicious top-level domain (.xyz, .tk, etc.) |
| URL Too Long | `URL_TOO_LONG` | MINOR | URL exceeds length threshold |
| Excessive Special Chars | `EXCESSIVE_SPECIAL_CHARS` | MINOR | Too many special characters |
| Encoded Characters | `ENCODED_CHARACTERS` | MINOR | Excessive percent-encoded characters |

## Verdict Logic

The server returns `REJECT` if any of the following conditions are met:

- Any **CRITICAL** rule triggers
- **2 or more** MAJOR rules trigger
- Total risk score reaches **50** or higher

Severity weights: CRITICAL = 40, MAJOR = 20, MINOR = 10.

## Configuration

All rule thresholds and lists are configurable in `application.yml` or via environment variables:

```bash
# Examples
URLPOLICE_RULES_MAX_URL_LENGTH=150
URLPOLICE_RULES_SPECIAL_CHAR_THRESHOLD=10
URLPOLICE_VERDICT_MAJOR_COUNT_THRESHOLD=3
URLPOLICE_VERDICT_RISK_SCORE_THRESHOLD=60
```

See [`application.yml`](src/main/resources/application.yml) for the full configuration reference.

## Architecture

```
POST /api/v1/url/check
  -> UrlCheckController
    -> RuleEngine (executes all PhishingRule beans)
      -> DefaultVerdictPolicy (aggregates results into ALLOW/REJECT)
        -> UrlCheckResponse
```

Each rule implements the `PhishingRule` fun interface and is auto-discovered by Spring as a `@Component`. Adding a new rule requires only creating a single file.

## License

All rights reserved.
