package com.seheon99.urlsentinel.api

import com.seheon99.urlsentinel.rule.Verdict
import com.seheon99.urlsentinel.verification.VerificationVerdict

/**
 * Response from /analyze endpoint.
 * SSL verification is ALWAYS performed first, URL check is conditional.
 */
data class UrlAnalyzeResponse(
    val sslVerification: SslVerificationResult,  // MANDATORY (always present)
    val urlCheck: UrlCheckResult? = null         // OPTIONAL (only if SSL passed with score >= 70)
)

/**
 * SSL/TLS verification results.
 */
data class SslVerificationResult(
    val verdict: VerificationVerdict,  // Three-tier: LIKELY_LEGITIMATE, SUSPICIOUS, LIKELY_INTERCEPTION
    val totalScore: Int,
    val checks: List<CheckDetail>,
    val serverCertificate: CertificateInfo
)

/**
 * URL phishing detection results.
 */
data class UrlCheckResult(
    val verdict: Verdict,         // ALLOW or REJECT
    val reasons: List<ReasonDetail>,
    val riskScore: Int
)
