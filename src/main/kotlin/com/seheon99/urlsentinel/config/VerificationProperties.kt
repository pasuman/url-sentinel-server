package com.seheon99.urlsentinel.config

import org.springframework.boot.context.properties.ConfigurationProperties

/**
 * Configuration properties for SSL/TLS verification system.
 */
@ConfigurationProperties("urlsentinel.verification")
data class VerificationProperties(
    /**
     * Master enable/disable switch for verification system.
     */
    val enabled: Boolean = true,

    /**
     * Minimum score threshold for LIKELY_LEGITIMATE verdict.
     */
    val legitimateThreshold: Int = 70,

    /**
     * Minimum score threshold for SUSPICIOUS verdict (below this is LIKELY_INTERCEPTION).
     */
    val suspiciousThreshold: Int = 20,

    /**
     * Per-check configuration.
     */
    val checks: ChecksProperties = ChecksProperties()
)

/**
 * Configuration for individual verification checks.
 */
data class ChecksProperties(
    val spkiMatch: CheckScoreProperties = CheckScoreProperties(
        enabled = true,
        passScore = 50,
        failScore = -40
    ),
    val ipAsnMatch: CheckScoreProperties = CheckScoreProperties(
        enabled = true,
        passScore = 20,
        failScore = -20
    ),
    val ctLog: CheckScoreProperties = CheckScoreProperties(
        enabled = true,
        passScore = 30,
        failScore = -15
    ),
    val tlsMetadata: CheckScoreProperties = CheckScoreProperties(
        enabled = true,
        passScore = 10,
        failScore = -10
    ),
    val chainValidation: CheckScoreProperties = CheckScoreProperties(
        enabled = true,
        passScore = 10,
        failScore = -40
    ),
    val multiRegion: CheckScoreProperties = CheckScoreProperties(
        enabled = false,
        passScore = 5,
        failScore = 0
    )
)

/**
 * Score configuration for a single check.
 *
 * @property enabled Whether the check is enabled
 * @property passScore Score added when check passes
 * @property failScore Score added when check fails (typically negative)
 */
data class CheckScoreProperties(
    val enabled: Boolean = true,
    val passScore: Int,
    val failScore: Int = 0
)
