package com.seheon99.urlsentinel.verification

/**
 * Three-tier confidence system for SSL verification verdicts.
 *
 * - LIKELY_LEGITIMATE: Score >= 70, connection appears authentic
 * - SUSPICIOUS: 20 <= Score < 70, some checks failed but not conclusive
 * - LIKELY_INTERCEPTION: Score < 20, strong indicators of MITM attack
 */
enum class VerificationVerdict {
    LIKELY_LEGITIMATE,
    SUSPICIOUS,
    LIKELY_INTERCEPTION
}
