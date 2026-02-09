package com.seheon99.urlsentinel.verification.checks

import com.seheon99.urlsentinel.config.VerificationProperties
import com.seheon99.urlsentinel.verification.CheckResult
import com.seheon99.urlsentinel.verification.ClientObservation
import com.seheon99.urlsentinel.verification.ServerData
import com.seheon99.urlsentinel.verification.VerificationCheck
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Component

/**
 * Compares TLS metadata (protocol version, cipher suite, ALPN) between client and server.
 * Lenient check - passes if 2 out of 3 fields match.
 *
 * Score: +10 on pass, -10 on fail
 */
@Component
@ConditionalOnProperty(
    prefix = "urlsentinel.verification.checks.tls-metadata",
    name = ["enabled"],
    havingValue = "true",
    matchIfMissing = true
)
class TlsMetadataMatchCheck(
    private val properties: VerificationProperties
) : VerificationCheck {

    override fun verify(observation: ClientObservation, serverData: ServerData): CheckResult {
        val config = properties.checks.tlsMetadata

        var matches = 0
        val details = mutableMapOf<String, Any>()

        // Compare protocol
        val protocolMatch = observation.tlsProtocol == serverData.tlsProtocol
        if (protocolMatch) matches++
        details["protocolMatch"] = protocolMatch
        details["clientProtocol"] = observation.tlsProtocol
        details["serverProtocol"] = serverData.tlsProtocol ?: "null"

        // Compare cipher suite
        val cipherMatch = observation.cipherSuite == serverData.cipherSuite
        if (cipherMatch) matches++
        details["cipherMatch"] = cipherMatch
        details["clientCipher"] = observation.cipherSuite
        details["serverCipher"] = serverData.cipherSuite ?: "null"

        // Compare ALPN
        val alpnMatch = observation.alpnProtocol == serverData.alpnProtocol
        if (alpnMatch) matches++
        details["alpnMatch"] = alpnMatch
        details["clientAlpn"] = observation.alpnProtocol ?: "null"
        details["serverAlpn"] = serverData.alpnProtocol ?: "null"

        // Pass if 2 out of 3 match (lenient)
        val passed = matches >= 2

        return CheckResult(
            checkName = "TLS_METADATA_MATCH",
            passed = passed,
            score = if (passed) config.passScore else config.failScore,
            message = if (passed) {
                "TLS metadata matches ($matches/3 fields)"
            } else {
                "TLS metadata MISMATCH ($matches/3 fields match)"
            },
            details = details
        )
    }
}
