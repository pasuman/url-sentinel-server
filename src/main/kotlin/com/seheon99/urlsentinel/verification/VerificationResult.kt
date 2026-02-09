package com.seheon99.urlsentinel.verification

import java.security.cert.X509Certificate

/**
 * Complete verification result from the VerificationEngine.
 *
 * @property verdict Three-tier confidence assessment
 * @property totalScore Aggregated score from all checks (0-100)
 * @property checkResults Individual check results
 * @property serverCertificate Server's leaf certificate
 */
data class VerificationResult(
    val verdict: VerificationVerdict,
    val totalScore: Int,
    val checkResults: List<CheckResult>,
    val serverCertificate: X509Certificate
)
