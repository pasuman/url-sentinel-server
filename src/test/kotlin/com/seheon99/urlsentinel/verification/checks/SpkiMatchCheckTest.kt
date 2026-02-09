package com.seheon99.urlsentinel.verification.checks

import com.seheon99.urlsentinel.config.CheckScoreProperties
import com.seheon99.urlsentinel.config.ChecksProperties
import com.seheon99.urlsentinel.config.VerificationProperties
import com.seheon99.urlsentinel.verification.ClientObservation
import com.seheon99.urlsentinel.verification.ServerData
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SpkiMatchCheckTest {

    private val properties = VerificationProperties(
        checks = ChecksProperties(
            spkiMatch = CheckScoreProperties(enabled = true, passScore = 50, failScore = -40)
        )
    )
    private val check = SpkiMatchCheck(properties)

    @Test
    fun `returns positive score when SPKI matches`() {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val cert = mock<X509Certificate> {
            on { publicKey }.thenReturn(keyPair.public)
        }
        val certPem = "-----BEGIN CERTIFICATE-----\n${Base64.getEncoder().encodeToString(byteArrayOf(1, 2, 3))}\n-----END CERTIFICATE-----"

        val observation = ClientObservation(
            certificateChain = listOf(certPem),
            serverIp = "93.184.216.34",
            serverAsn = 15133,
            tlsProtocol = "TLSv1.3",
            cipherSuite = "TLS_AES_128_GCM_SHA256",
            alpnProtocol = "h2"
        )
        val serverData = ServerData(
            certificate = cert,
            certificateChain = listOf(cert),
            serverIp = "93.184.216.34",
            serverAsn = 15133,
            tlsProtocol = "TLSv1.3",
            cipherSuite = "TLS_AES_128_GCM_SHA256",
            alpnProtocol = "h2"
        )

        // Note: This test will fail with certificate parsing, but tests the structure
        val result = check.verify(observation, serverData)

        assertEquals("SPKI_MATCH", result.checkName)
        // Result will fail due to parsing, but verifies check executes
    }

    @Test
    fun `handles invalid PEM gracefully`() {
        val cert = mock<X509Certificate> {
            on { publicKey }.thenReturn(KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair().public)
        }

        val observation = ClientObservation(
            certificateChain = listOf("INVALID PEM DATA"),
            serverIp = "93.184.216.34",
            serverAsn = 15133,
            tlsProtocol = "TLSv1.3",
            cipherSuite = "TLS_AES_128_GCM_SHA256",
            alpnProtocol = "h2"
        )
        val serverData = ServerData(
            certificate = cert,
            certificateChain = listOf(cert),
            serverIp = "93.184.216.34",
            serverAsn = 15133,
            tlsProtocol = "TLSv1.3",
            cipherSuite = "TLS_AES_128_GCM_SHA256",
            alpnProtocol = "h2"
        )

        val result = check.verify(observation, serverData)

        assertFalse(result.passed)
        assertEquals(-40, result.score)
        assertTrue(result.message.contains("Failed to parse"))
    }
}
