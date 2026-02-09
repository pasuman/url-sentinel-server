package com.seheon99.urlsentinel.verification.checks

import com.seheon99.urlsentinel.config.CheckScoreProperties
import com.seheon99.urlsentinel.config.ChecksProperties
import com.seheon99.urlsentinel.config.VerificationProperties
import com.seheon99.urlsentinel.verification.ClientObservation
import com.seheon99.urlsentinel.verification.ServerData
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import java.security.cert.X509Certificate
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TlsMetadataMatchCheckTest {

    private val properties = VerificationProperties(
        checks = ChecksProperties(
            tlsMetadata = CheckScoreProperties(enabled = true, passScore = 10, failScore = -10)
        )
    )
    private val check = TlsMetadataMatchCheck(properties)
    private val mockCert = mock<X509Certificate>()

    @Test
    fun `returns positive score when all metadata matches`() {
        val observation = ClientObservation(
            certificateChain = listOf("cert"),
            serverIp = "93.184.216.34",
            serverAsn = 15133,
            tlsProtocol = "TLSv1.3",
            cipherSuite = "TLS_AES_128_GCM_SHA256",
            alpnProtocol = "h2"
        )
        val serverData = ServerData(
            certificate = mockCert,
            certificateChain = listOf(mockCert),
            serverIp = "93.184.216.34",
            serverAsn = 15133,
            tlsProtocol = "TLSv1.3",
            cipherSuite = "TLS_AES_128_GCM_SHA256",
            alpnProtocol = "h2"
        )

        val result = check.verify(observation, serverData)

        assertTrue(result.passed)
        assertEquals(10, result.score)
        assertEquals("TLS_METADATA_MATCH", result.checkName)
        assertTrue(result.message.contains("3/3"))
    }

    @Test
    fun `returns positive score when 2 out of 3 fields match (lenient)`() {
        val observation = ClientObservation(
            certificateChain = listOf("cert"),
            serverIp = "93.184.216.34",
            serverAsn = 15133,
            tlsProtocol = "TLSv1.3",
            cipherSuite = "TLS_AES_128_GCM_SHA256",
            alpnProtocol = "h2"
        )
        val serverData = ServerData(
            certificate = mockCert,
            certificateChain = listOf(mockCert),
            serverIp = "93.184.216.34",
            serverAsn = 15133,
            tlsProtocol = "TLSv1.3",
            cipherSuite = "TLS_AES_128_GCM_SHA256",
            alpnProtocol = "http/1.1" // Different ALPN
        )

        val result = check.verify(observation, serverData)

        assertTrue(result.passed)
        assertEquals(10, result.score)
        assertTrue(result.message.contains("2/3"))
    }

    @Test
    fun `returns negative score when less than 2 fields match`() {
        val observation = ClientObservation(
            certificateChain = listOf("cert"),
            serverIp = "93.184.216.34",
            serverAsn = 15133,
            tlsProtocol = "TLSv1.3",
            cipherSuite = "TLS_AES_128_GCM_SHA256",
            alpnProtocol = "h2"
        )
        val serverData = ServerData(
            certificate = mockCert,
            certificateChain = listOf(mockCert),
            serverIp = "93.184.216.34",
            serverAsn = 15133,
            tlsProtocol = "TLSv1.2", // Different
            cipherSuite = "TLS_RSA_WITH_AES_256_CBC_SHA", // Different
            alpnProtocol = "http/1.1" // Different
        )

        val result = check.verify(observation, serverData)

        assertFalse(result.passed)
        assertEquals(-10, result.score)
        assertEquals("TLS_METADATA_MATCH", result.checkName)
        assertTrue(result.message.contains("MISMATCH"))
    }

    @Test
    fun `handles null server metadata gracefully`() {
        val observation = ClientObservation(
            certificateChain = listOf("cert"),
            serverIp = "93.184.216.34",
            serverAsn = 15133,
            tlsProtocol = "TLSv1.3",
            cipherSuite = "TLS_AES_128_GCM_SHA256",
            alpnProtocol = "h2"
        )
        val serverData = ServerData(
            certificate = mockCert,
            certificateChain = listOf(mockCert),
            serverIp = "93.184.216.34",
            serverAsn = 15133,
            tlsProtocol = null,
            cipherSuite = null,
            alpnProtocol = null
        )

        val result = check.verify(observation, serverData)

        // Should not crash, and will fail since nothing matches
        assertFalse(result.passed)
        assertEquals(-10, result.score)
    }
}
