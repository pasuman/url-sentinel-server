package com.seheon99.urlsentinel.api

import com.seheon99.urlsentinel.rule.Verdict

data class UrlAnalyzeResponse(
    // URL phishing detection results
    val verdict: Verdict,
    val reasons: List<ReasonDetail>,
    val riskScore: Int,

    // SSL certificate verification results (only present if clientFingerprint was provided)
    val sslVerification: SslVerificationResult? = null,
)

data class SslVerificationResult(
    val verdict: SslVerdict,
    val serverFingerprint: String?,
    val clientFingerprint: String,
    val certificateDetails: CertificateDetails?,
    val message: String,
)
