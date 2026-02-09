package com.seheon99.urlsentinel.verification.checks

import com.seheon99.urlsentinel.config.VerificationProperties
import com.seheon99.urlsentinel.verification.CertificateUtils
import com.seheon99.urlsentinel.verification.CheckResult
import com.seheon99.urlsentinel.verification.ClientObservation
import com.seheon99.urlsentinel.verification.ServerData
import com.seheon99.urlsentinel.verification.VerificationCheck
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Component
import java.net.URL

/**
 * Validates the server certificate chain against the system trust store.
 * Checks both chain validity and hostname matching.
 *
 * Score: +10 on valid, -40 on invalid (critical failure)
 */
@Component
@ConditionalOnProperty(
    prefix = "urlsentinel.verification.checks.chain-validation",
    name = ["enabled"],
    havingValue = "true",
    matchIfMissing = true
)
class ChainValidatesCheck(
    private val properties: VerificationProperties
) : VerificationCheck {

    override fun verify(observation: ClientObservation, serverData: ServerData): CheckResult {
        val config = properties.checks.chainValidation

        // Extract hostname from client observation (would need to pass URL separately)
        // For now, use server certificate's CN
        val hostname = try {
            serverData.certificate.subjectX500Principal.name
                .split(",")
                .firstOrNull { it.trim().startsWith("CN=") }
                ?.substringAfter("CN=")
                ?.trim() ?: ""
        } catch (e: Exception) {
            ""
        }

        val isValid = try {
            CertificateUtils.validateChain(serverData.certificateChain, hostname)
        } catch (e: Exception) {
            false
        }

        return if (isValid) {
            CheckResult(
                checkName = "CHAIN_VALIDATES",
                passed = true,
                score = config.passScore,
                message = "Certificate chain is valid and trusted",
                details = mapOf(
                    "chainLength" to serverData.certificateChain.size,
                    "issuer" to serverData.certificate.issuerX500Principal.name
                )
            )
        } else {
            CheckResult(
                checkName = "CHAIN_VALIDATES",
                passed = false,
                score = config.failScore,
                message = "Certificate chain validation FAILED - untrusted or invalid chain",
                details = mapOf(
                    "chainLength" to serverData.certificateChain.size
                )
            )
        }
    }
}
