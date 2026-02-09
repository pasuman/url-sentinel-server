package com.seheon99.urlsentinel.verification.checks

import com.seheon99.urlsentinel.config.VerificationProperties
import com.seheon99.urlsentinel.verification.CertificateTransparencyService
import com.seheon99.urlsentinel.verification.CheckResult
import com.seheon99.urlsentinel.verification.ClientObservation
import com.seheon99.urlsentinel.verification.ServerData
import com.seheon99.urlsentinel.verification.VerificationCheck
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Component

/**
 * Checks for Certificate Transparency (CT) log presence in the server certificate.
 * Legitimate certificates from public CAs should have SCT extensions.
 *
 * Score: +30 if found, -15 if not found
 */
@Component
@ConditionalOnProperty(
    prefix = "urlsentinel.verification.checks.ct-log",
    name = ["enabled"],
    havingValue = "true",
    matchIfMissing = true
)
class CtLogPresenceCheck(
    private val properties: VerificationProperties,
    private val ctService: CertificateTransparencyService
) : VerificationCheck {

    override fun verify(observation: ClientObservation, serverData: ServerData): CheckResult {
        val config = properties.checks.ctLog

        val hasCtLog = try {
            ctService.hasCertificateTransparency(serverData.certificate)
        } catch (e: Exception) {
            // Fail-open: treat exception as neutral
            return CheckResult(
                checkName = "CT_LOG_PRESENCE",
                passed = true,
                score = 0,
                message = "CT log check failed: ${e.message}",
                details = mapOf("error" to (e.message ?: "Unknown error"))
            )
        }

        return if (hasCtLog) {
            CheckResult(
                checkName = "CT_LOG_PRESENCE",
                passed = true,
                score = config.passScore,
                message = "Certificate has CT log entry (SCT extension present)",
                details = mapOf("hasSct" to true)
            )
        } else {
            CheckResult(
                checkName = "CT_LOG_PRESENCE",
                passed = false,
                score = config.failScore,
                message = "Certificate lacks CT log entry - possible self-signed or rogue CA",
                details = mapOf("hasSct" to false)
            )
        }
    }
}
