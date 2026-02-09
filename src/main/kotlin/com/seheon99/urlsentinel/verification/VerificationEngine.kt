package com.seheon99.urlsentinel.verification

import org.springframework.stereotype.Service

/**
 * Orchestrates SSL/TLS verification checks and aggregates results.
 * Mirrors the RuleEngine pattern for consistency.
 */
@Service
class VerificationEngine(
    private val checks: List<VerificationCheck>,
    private val decisionEngine: VerificationDecisionEngine,
    private val serverDataFetcher: ServerDataFetcher
) {

    /**
     * Verifies SSL/TLS connection integrity by running all checks.
     *
     * @param url Target URL to verify
     * @param observation Client-observed TLS metadata
     * @return Complete verification result with verdict and score
     */
    fun verify(url: String, observation: ClientObservation): VerificationResult {
        // Fetch server-side data
        val serverData = serverDataFetcher.fetch(url)

        // Run all enabled checks
        val checkResults = checks.map { check ->
            try {
                check.verify(observation, serverData)
            } catch (e: Exception) {
                // Fail-open: if a check throws an exception, treat as neutral (0 score)
                CheckResult(
                    checkName = check::class.simpleName ?: "UNKNOWN",
                    passed = false,
                    score = 0,
                    message = "Check failed with exception: ${e.message}",
                    details = mapOf("error" to (e.message ?: "Unknown error"))
                )
            }
        }

        // Calculate total score (clamped to 0-100)
        val totalScore = checkResults.sumOf { it.score }.coerceIn(0, 100)

        // Determine verdict
        val verdict = decisionEngine.decide(checkResults)

        return VerificationResult(
            verdict = verdict,
            totalScore = totalScore,
            checkResults = checkResults,
            serverCertificate = serverData.certificate
        )
    }
}
