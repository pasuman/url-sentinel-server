package com.seheon99.urlsentinel.api

import com.seheon99.urlsentinel.rule.RuleEngine
import com.seheon99.urlsentinel.ssl.SslCertificateService
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

@RestController
class UrlAnalyzeController(
    private val ruleEngine: RuleEngine,
    private val sslCertificateService: SslCertificateService,
) {

    @PostMapping("/analyze")
    fun analyze(@RequestBody request: UrlAnalyzeRequest): UrlAnalyzeResponse {
        require(request.url.isNotBlank()) { "URL must not be blank" }

        // Always run URL phishing detection
        val urlCheckResult = ruleEngine.evaluate(request.url)

        // Optionally verify SSL certificate if fingerprint provided
        val sslVerification = if (request.clientFingerprint != null) {
            val sslResult = sslCertificateService.verifyCertificate(request.url, request.clientFingerprint)
            SslVerificationResult(
                verdict = sslResult.verdict,
                serverFingerprint = sslResult.serverFingerprint,
                clientFingerprint = sslResult.clientFingerprint,
                certificateDetails = sslResult.certificateDetails,
                message = sslResult.message,
            )
        } else {
            null
        }

        return UrlAnalyzeResponse(
            verdict = urlCheckResult.verdict,
            reasons = urlCheckResult.reasons,
            riskScore = urlCheckResult.riskScore,
            sslVerification = sslVerification,
        )
    }
}
