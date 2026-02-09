package com.seheon99.urlsentinel.verification

/**
 * Result from a single verification check.
 *
 * @property checkName Name of the check (e.g., "SPKI_MATCH", "CHAIN_VALIDATES")
 * @property passed Whether the check passed
 * @property score Score contribution (can be negative)
 * @property message Human-readable explanation
 * @property details Additional structured data about the check
 */
data class CheckResult(
    val checkName: String,
    val passed: Boolean,
    val score: Int,
    val message: String,
    val details: Map<String, Any> = emptyMap()
)
