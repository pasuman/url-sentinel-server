package com.seheon99.urlsentinel.api

/**
 * Certificate information for API responses.
 */
data class CertificateInfo(
    val subject: String,
    val issuer: String,
    val validFrom: String,  // ISO-8601 timestamp
    val validTo: String,    // ISO-8601 timestamp
    val isExpired: Boolean,
    val spki: String  // Hex-encoded SPKI (Subject Public Key Info)
)
