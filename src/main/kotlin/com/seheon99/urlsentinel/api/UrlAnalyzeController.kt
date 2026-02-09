package com.seheon99.urlsentinel.api

import com.seheon99.urlsentinel.rule.RuleEngine
import com.seheon99.urlsentinel.verification.CertificateUtils
import com.seheon99.urlsentinel.verification.VerificationEngine
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import java.time.format.DateTimeFormatter

@RestController
class UrlAnalyzeController(
    private val verificationEngine: VerificationEngine,  // NEW: SSL verification first
    private val ruleEngine: RuleEngine
) {

    @PostMapping("/analyze")
    fun analyze(@RequestBody request: UrlAnalyzeRequest): UrlAnalyzeResponse {
        require(request.url.isNotBlank()) { "URL must not be blank" }

        // STEP 1: SSL verification (MANDATORY, ALWAYS FIRST)
        val verificationResult = verificationEngine.verify(request.url, request.clientObservation)

        val sslVerification = SslVerificationResult(
            verdict = verificationResult.verdict,
            totalScore = verificationResult.totalScore,
            checks = verificationResult.checkResults.map { checkResult ->
                CheckDetail(
                    name = checkResult.checkName,
                    passed = checkResult.passed,
                    score = checkResult.score,
                    message = checkResult.message
                )
            },
            serverCertificate = CertificateInfo(
                subject = verificationResult.serverCertificate.subjectX500Principal.name,
                issuer = verificationResult.serverCertificate.issuerX500Principal.name,
                validFrom = verificationResult.serverCertificate.notBefore.toInstant()
                    .atZone(java.time.ZoneOffset.UTC)
                    .format(DateTimeFormatter.ISO_INSTANT),
                validTo = verificationResult.serverCertificate.notAfter.toInstant()
                    .atZone(java.time.ZoneOffset.UTC)
                    .format(DateTimeFormatter.ISO_INSTANT),
                isExpired = verificationResult.serverCertificate.notAfter.before(java.util.Date()),
                spki = CertificateUtils.sha256Fingerprint(
                    CertificateUtils.extractSpki(verificationResult.serverCertificate)
                )
            )
        )

        // STEP 2: URL phishing detection (ONLY if SSL score >= 70)
        val urlCheck = if (verificationResult.totalScore >= 70) {
            val ruleResult = ruleEngine.evaluate(request.url)
            UrlCheckResult(
                verdict = ruleResult.verdict,
                reasons = ruleResult.reasons,
                riskScore = ruleResult.riskScore
            )
        } else {
            null  // Skip URL check if SSL verification failed
        }

        return UrlAnalyzeResponse(
            sslVerification = sslVerification,
            urlCheck = urlCheck
        )
    }
}
