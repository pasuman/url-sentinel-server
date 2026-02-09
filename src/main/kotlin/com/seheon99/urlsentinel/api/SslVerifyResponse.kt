package com.seheon99.urlsentinel.api

enum class SslVerdict {
    MATCH,      // Fingerprints match - safe
    MISMATCH,   // Different fingerprints - potential attack
    ERROR       // Unable to fetch certificate
}

data class CertificateDetails(
    val subject: String,
    val issuer: String,
    val validFrom: String,  // ISO-8601 timestamp
    val validTo: String,    // ISO-8601 timestamp
    val isExpired: Boolean,
)

data class SslVerifyResponse(
    val verdict: SslVerdict,
    val serverFingerprint: String?,  // Null on ERROR
    val clientFingerprint: String,   // Echo back
    val certificateDetails: CertificateDetails?,  // Null on ERROR
    val message: String,  // Human-readable explanation
)
