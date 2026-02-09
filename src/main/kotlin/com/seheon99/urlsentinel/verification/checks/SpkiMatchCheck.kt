package com.seheon99.urlsentinel.verification.checks

import com.seheon99.urlsentinel.config.VerificationProperties
import com.seheon99.urlsentinel.verification.CertificateUtils
import com.seheon99.urlsentinel.verification.CheckResult
import com.seheon99.urlsentinel.verification.ClientObservation
import com.seheon99.urlsentinel.verification.ServerData
import com.seheon99.urlsentinel.verification.VerificationCheck
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Component

/**
 * Verifies that the Subject Public Key Info (SPKI) matches between client and server certificates.
 * This is the most critical check - different public keys indicate MITM attack.
 *
 * Score: +50 on match, -40 on mismatch
 */
@Component
@ConditionalOnProperty(
    prefix = "urlsentinel.verification.checks.spki-match",
    name = ["enabled"],
    havingValue = "true",
    matchIfMissing = true
)
class SpkiMatchCheck(
    private val properties: VerificationProperties
) : VerificationCheck {

    override fun verify(observation: ClientObservation, serverData: ServerData): CheckResult {
        val config = properties.checks.spkiMatch

        // Parse client certificate (leaf)
        val clientCert = try {
            CertificateUtils.parsePem(observation.certificateChain.first())
        } catch (e: Exception) {
            return CheckResult(
                checkName = "SPKI_MATCH",
                passed = false,
                score = config.failScore,
                message = "Failed to parse client certificate: ${e.message}",
                details = mapOf("error" to (e.message ?: "Unknown error"))
            )
        }

        // Extract SPKIs
        val clientSpki = CertificateUtils.extractSpki(clientCert)
        val serverSpki = CertificateUtils.extractSpki(serverData.certificate)

        // Compare
        val matches = clientSpki.contentEquals(serverSpki)

        return if (matches) {
            CheckResult(
                checkName = "SPKI_MATCH",
                passed = true,
                score = config.passScore,
                message = "Subject Public Key Info matches",
                details = mapOf(
                    "spki" to CertificateUtils.sha256Fingerprint(clientSpki)
                )
            )
        } else {
            CheckResult(
                checkName = "SPKI_MATCH",
                passed = false,
                score = config.failScore,
                message = "Subject Public Key Info MISMATCH - possible MITM attack",
                details = mapOf(
                    "clientSpki" to CertificateUtils.sha256Fingerprint(clientSpki),
                    "serverSpki" to CertificateUtils.sha256Fingerprint(serverSpki)
                )
            )
        }
    }
}
