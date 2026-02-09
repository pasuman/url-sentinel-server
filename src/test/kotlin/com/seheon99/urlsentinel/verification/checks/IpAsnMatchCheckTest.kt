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

class IpAsnMatchCheckTest {

    private val properties = VerificationProperties(
        checks = ChecksProperties(
            ipAsnMatch = CheckScoreProperties(enabled = true, passScore = 20, failScore = -20)
        )
    )
    private val check = IpAsnMatchCheck(properties)
    private val mockCert = mock<X509Certificate>()

    @Test
    fun `returns positive score when ASN matches`() {
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
        assertEquals(20, result.score)
        assertEquals("IP_ASN_MATCH", result.checkName)
        assertTrue(result.message.contains("AS15133"))
    }

    @Test
    fun `returns negative score when ASN mismatches`() {
        val observation = ClientObservation(
            certificateChain = listOf("cert"),
            serverIp = "192.0.2.1",
            serverAsn = 12345,
            tlsProtocol = "TLSv1.3",
            cipherSuite = "TLS_AES_128_GCM_SHA256",
            alpnProtocol = "h2"
        )
        val serverData = ServerData(
            certificate = mockCert,
            certificateChain = listOf(mockCert),
            serverIp = "198.51.100.1",
            serverAsn = 67890,
            tlsProtocol = "TLSv1.3",
            cipherSuite = "TLS_AES_128_GCM_SHA256",
            alpnProtocol = "h2"
        )

        val result = check.verify(observation, serverData)

        assertFalse(result.passed)
        assertEquals(-20, result.score)
        assertEquals("IP_ASN_MATCH", result.checkName)
        assertTrue(result.message.contains("MISMATCH"))
        assertTrue(result.message.contains("DNS hijacking"))
    }

    @Test
    fun `returns neutral score when client ASN is null`() {
        val observation = ClientObservation(
            certificateChain = listOf("cert"),
            serverIp = "93.184.216.34",
            serverAsn = null,
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

        assertTrue(result.passed) // Neutral = pass
        assertEquals(0, result.score)
        assertTrue(result.message.contains("unavailable"))
    }

    @Test
    fun `returns neutral score when server ASN is null`() {
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
            serverAsn = null,
            tlsProtocol = "TLSv1.3",
            cipherSuite = "TLS_AES_128_GCM_SHA256",
            alpnProtocol = "h2"
        )

        val result = check.verify(observation, serverData)

        assertTrue(result.passed)
        assertEquals(0, result.score)
        assertTrue(result.message.contains("unavailable"))
    }
}
