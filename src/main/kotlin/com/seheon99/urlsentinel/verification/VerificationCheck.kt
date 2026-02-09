package com.seheon99.urlsentinel.verification

/**
 * Fun interface for SSL verification checks.
 * Mirrors the PhishingRule pattern for consistency.
 */
fun interface VerificationCheck {
    /**
     * Verifies SSL/TLS connection integrity by comparing client and server observations.
     *
     * @param observation Client-observed TLS metadata
     * @param serverData Server-side TLS data fetched by the server
     * @return Check result with pass/fail status and score contribution
     */
    fun verify(observation: ClientObservation, serverData: ServerData): CheckResult
}
