package com.seheon99.urlsentinel.verification.checks

import com.seheon99.urlsentinel.config.VerificationProperties
import com.seheon99.urlsentinel.verification.CheckResult
import com.seheon99.urlsentinel.verification.ClientObservation
import com.seheon99.urlsentinel.verification.ServerData
import com.seheon99.urlsentinel.verification.VerificationCheck
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Component

/**
 * Compares Autonomous System Numbers (ASN) between client and server observations.
 * Detects DNS hijacking to different networks.
 *
 * Score: +20 on match, -20 on mismatch, 0 if either ASN is unknown
 */
@Component
@ConditionalOnProperty(
    prefix = "urlsentinel.verification.checks.ip-asn-match",
    name = ["enabled"],
    havingValue = "true",
    matchIfMissing = true
)
class IpAsnMatchCheck(
    private val properties: VerificationProperties
) : VerificationCheck {

    override fun verify(observation: ClientObservation, serverData: ServerData): CheckResult {
        val config = properties.checks.ipAsnMatch

        // If either ASN is null, treat as neutral (can't determine)
        if (observation.serverAsn == null || serverData.serverAsn == null) {
            return CheckResult(
                checkName = "IP_ASN_MATCH",
                passed = true, // Neutral = pass
                score = 0,
                message = "ASN data unavailable for comparison",
                details = mapOf(
                    "clientAsn" to (observation.serverAsn?.toString() ?: "null"),
                    "serverAsn" to (serverData.serverAsn?.toString() ?: "null"),
                    "clientIp" to observation.serverIp,
                    "serverIp" to serverData.serverIp
                )
            )
        }

        val matches = observation.serverAsn == serverData.serverAsn

        return if (matches) {
            CheckResult(
                checkName = "IP_ASN_MATCH",
                passed = true,
                score = config.passScore,
                message = "ASN matches (AS${observation.serverAsn})",
                details = mapOf(
                    "asn" to observation.serverAsn,
                    "clientIp" to observation.serverIp,
                    "serverIp" to serverData.serverIp
                )
            )
        } else {
            CheckResult(
                checkName = "IP_ASN_MATCH",
                passed = false,
                score = config.failScore,
                message = "ASN MISMATCH - possible DNS hijacking",
                details = mapOf(
                    "clientAsn" to observation.serverAsn,
                    "serverAsn" to serverData.serverAsn,
                    "clientIp" to observation.serverIp,
                    "serverIp" to serverData.serverIp
                )
            )
        }
    }
}
