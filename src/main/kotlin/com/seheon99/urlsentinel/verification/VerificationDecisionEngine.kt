package com.seheon99.urlsentinel.verification

import com.seheon99.urlsentinel.config.VerificationProperties
import org.springframework.stereotype.Component

/**
 * Maps aggregated verification scores to three-tier verdicts.
 * Uses configurable thresholds to determine confidence level.
 */
@Component
class VerificationDecisionEngine(
    private val properties: VerificationProperties
) {

    /**
     * Determines verdict based on total score and configured thresholds.
     *
     * @param results List of check results
     * @return Verdict (LIKELY_LEGITIMATE, SUSPICIOUS, or LIKELY_INTERCEPTION)
     */
    fun decide(results: List<CheckResult>): VerificationVerdict {
        val totalScore = results.sumOf { it.score }.coerceIn(0, 100)

        return when {
            totalScore >= properties.legitimateThreshold -> VerificationVerdict.LIKELY_LEGITIMATE
            totalScore >= properties.suspiciousThreshold -> VerificationVerdict.SUSPICIOUS
            else -> VerificationVerdict.LIKELY_INTERCEPTION
        }
    }
}
