package com.seheon99.urlsentinel.verification.checks

import com.seheon99.urlsentinel.config.VerificationProperties
import com.seheon99.urlsentinel.verification.CheckResult
import com.seheon99.urlsentinel.verification.ClientObservation
import com.seheon99.urlsentinel.verification.ServerData
import com.seheon99.urlsentinel.verification.VerificationCheck
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Component

/**
 * Checks if the certificate is consistent across multiple geographic regions.
 * This is a stub implementation for MVP - always returns neutral score.
 *
 * Future: Fetch certificate from multiple vantage points and compare.
 *
 * Score: +5 if consistent, 0 if inconsistent or check unavailable
 */
@Component
@ConditionalOnProperty(
    prefix = "urlsentinel.verification.checks.multi-region",
    name = ["enabled"],
    havingValue = "true",
    matchIfMissing = false
)
class MultiRegionConsistencyCheck(
    private val properties: VerificationProperties
) : VerificationCheck {

    override fun verify(observation: ClientObservation, serverData: ServerData): CheckResult {
        // Stub implementation - always return neutral
        return CheckResult(
            checkName = "MULTI_REGION_CONSISTENCY",
            passed = true,
            score = 0,
            message = "Multi-region check not implemented (stub)",
            details = mapOf("implemented" to false)
        )
    }
}
