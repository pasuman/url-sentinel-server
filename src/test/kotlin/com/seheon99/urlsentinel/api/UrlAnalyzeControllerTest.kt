package com.seheon99.urlsentinel.api

import com.seheon99.urlsentinel.rule.RuleEngine
import com.seheon99.urlsentinel.rule.Verdict
import com.seheon99.urlsentinel.verification.*
import org.junit.jupiter.api.Test
import org.mockito.Mockito.`when`
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest
import org.springframework.http.MediaType
import org.springframework.test.context.bean.override.mockito.MockitoBean
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.security.cert.X509Certificate
import java.util.*

@WebMvcTest(controllers = [UrlAnalyzeController::class, GlobalExceptionHandler::class])
class UrlAnalyzeControllerTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @MockitoBean
    private lateinit var verificationEngine: VerificationEngine

    @MockitoBean
    private lateinit var ruleEngine: RuleEngine

    private val mockCert = mock<X509Certificate> {
        on { subjectX500Principal }.thenReturn(javax.security.auth.x500.X500Principal("CN=example.com"))
        on { issuerX500Principal }.thenReturn(javax.security.auth.x500.X500Principal("CN=Test CA"))
        on { notBefore }.thenReturn(java.util.Date())
        on { notAfter }.thenReturn(java.util.Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000))
        on { publicKey }.thenReturn(mock())
        on { encoded }.thenReturn(byteArrayOf(1, 2, 3))
    }

    @Test
    fun `returns SSL verification and URL check when SSL passes`() {
        val url = "https://www.google.com"

        // Mock SSL verification (passes with score 90)
        `when`(verificationEngine.verify(any(), any())).thenReturn(
            VerificationResult(
                verdict = VerificationVerdict.LIKELY_LEGITIMATE,
                totalScore = 90,
                checkResults = listOf(
                    CheckResult("SPKI_MATCH", true, 50, "Subject Public Key Info matches"),
                    CheckResult("CHAIN_VALIDATES", true, 10, "Certificate chain is valid"),
                    CheckResult("IP_ASN_MATCH", true, 20, "ASN matches"),
                    CheckResult("CT_LOG_PRESENCE", true, 30, "Certificate has CT log entry"),
                    CheckResult("TLS_METADATA_MATCH", false, -10, "TLS metadata MISMATCH"),
                ),
                serverCertificate = mockCert
            )
        )

        // Mock URL check (runs because SSL passed)
        `when`(ruleEngine.evaluate(url)).thenReturn(
            UrlCheckResponse(
                verdict = Verdict.ALLOW,
                reasons = emptyList(),
                riskScore = 0,
            ),
        )

        mockMvc.perform(
            post("/analyze")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "url": "$url",
                      "clientObservation": {
                        "certificateChain": ["-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"],
                        "serverIp": "142.250.185.68",
                        "serverAsn": 15169,
                        "tlsProtocol": "TLSv1.3",
                        "cipherSuite": "TLS_AES_128_GCM_SHA256",
                        "alpnProtocol": "h2"
                      }
                    }
                """.trimIndent()),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.sslVerification").exists())
            .andExpect(jsonPath("$.sslVerification.verdict").value("LIKELY_LEGITIMATE"))
            .andExpect(jsonPath("$.sslVerification.totalScore").value(90))
            .andExpect(jsonPath("$.sslVerification.checks").isArray)
            .andExpect(jsonPath("$.sslVerification.checks.length()").value(5))
            .andExpect(jsonPath("$.urlCheck").exists())
            .andExpect(jsonPath("$.urlCheck.verdict").value("ALLOW"))
            .andExpect(jsonPath("$.urlCheck.riskScore").value(0))
    }

    @Test
    fun `skips URL check when SSL score is below threshold`() {
        val url = "https://suspicious.com"

        // Mock SSL verification (fails with score 30)
        `when`(verificationEngine.verify(any(), any())).thenReturn(
            VerificationResult(
                verdict = VerificationVerdict.SUSPICIOUS,
                totalScore = 30,
                checkResults = listOf(
                    CheckResult("SPKI_MATCH", false, -40, "SPKI MISMATCH - possible MITM"),
                    CheckResult("CHAIN_VALIDATES", false, -40, "Chain validation FAILED"),
                    CheckResult("IP_ASN_MATCH", true, 20, "ASN matches"),
                    CheckResult("CT_LOG_PRESENCE", true, 30, "Certificate has CT log entry"),
                    CheckResult("TLS_METADATA_MATCH", true, 10, "TLS metadata matches"),
                ),
                serverCertificate = mockCert
            )
        )

        mockMvc.perform(
            post("/analyze")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "url": "$url",
                      "clientObservation": {
                        "certificateChain": ["-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"],
                        "serverIp": "192.0.2.1",
                        "serverAsn": 12345,
                        "tlsProtocol": "TLSv1.3",
                        "cipherSuite": "TLS_AES_128_GCM_SHA256",
                        "alpnProtocol": "h2"
                      }
                    }
                """.trimIndent()),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.sslVerification").exists())
            .andExpect(jsonPath("$.sslVerification.verdict").value("SUSPICIOUS"))
            .andExpect(jsonPath("$.sslVerification.totalScore").value(30))
            .andExpect(jsonPath("$.urlCheck").doesNotExist()) // URL check skipped
    }

    @Test
    fun `returns LIKELY_INTERCEPTION verdict for severe SSL issues`() {
        val url = "https://evil.com"

        // Mock SSL verification (fails badly with score 0)
        `when`(verificationEngine.verify(any(), any())).thenReturn(
            VerificationResult(
                verdict = VerificationVerdict.LIKELY_INTERCEPTION,
                totalScore = 0,
                checkResults = listOf(
                    CheckResult("SPKI_MATCH", false, -40, "SPKI MISMATCH"),
                    CheckResult("CHAIN_VALIDATES", false, -40, "Chain validation FAILED"),
                    CheckResult("IP_ASN_MATCH", false, -20, "ASN MISMATCH - DNS hijacking"),
                    CheckResult("CT_LOG_PRESENCE", false, -15, "No CT log entry"),
                    CheckResult("TLS_METADATA_MATCH", false, -10, "TLS metadata MISMATCH"),
                ),
                serverCertificate = mockCert
            )
        )

        mockMvc.perform(
            post("/analyze")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "url": "$url",
                      "clientObservation": {
                        "certificateChain": ["-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"],
                        "serverIp": "198.51.100.1",
                        "serverAsn": 99999,
                        "tlsProtocol": "TLSv1.2",
                        "cipherSuite": "TLS_RSA_WITH_AES_128_CBC_SHA",
                        "alpnProtocol": null
                      }
                    }
                """.trimIndent()),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.sslVerification.verdict").value("LIKELY_INTERCEPTION"))
            .andExpect(jsonPath("$.sslVerification.totalScore").value(0))
            .andExpect(jsonPath("$.urlCheck").doesNotExist())
    }

    @Test
    fun `returns REJECT with reasons when URL is phishing and SSL passes`() {
        val url = "http://192.168.1.1/login"

        // Mock SSL verification (passes)
        `when`(verificationEngine.verify(any(), any())).thenReturn(
            VerificationResult(
                verdict = VerificationVerdict.LIKELY_LEGITIMATE,
                totalScore = 80,
                checkResults = listOf(
                    CheckResult("SPKI_MATCH", true, 50, "SPKI matches"),
                    CheckResult("CHAIN_VALIDATES", true, 10, "Chain valid"),
                    CheckResult("IP_ASN_MATCH", true, 20, "ASN matches"),
                ),
                serverCertificate = mockCert
            )
        )

        // Mock URL check (phishing detected)
        `when`(ruleEngine.evaluate(url)).thenReturn(
            UrlCheckResponse(
                verdict = Verdict.REJECT,
                reasons = listOf(
                    ReasonDetail("IP_ADDRESS_DOMAIN", "CRITICAL", "URL uses an IP address"),
                    ReasonDetail("SUSPICIOUS_KEYWORD", "MAJOR", "URL contains: login"),
                ),
                riskScore = 60,
            ),
        )

        mockMvc.perform(
            post("/analyze")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "url": "$url",
                      "clientObservation": {
                        "certificateChain": ["-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"],
                        "serverIp": "192.168.1.1",
                        "serverAsn": null,
                        "tlsProtocol": "TLSv1.3",
                        "cipherSuite": "TLS_AES_128_GCM_SHA256",
                        "alpnProtocol": "h2"
                      }
                    }
                """.trimIndent()),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.sslVerification.verdict").value("LIKELY_LEGITIMATE"))
            .andExpect(jsonPath("$.urlCheck.verdict").value("REJECT"))
            .andExpect(jsonPath("$.urlCheck.reasons.length()").value(2))
            .andExpect(jsonPath("$.urlCheck.riskScore").value(60))
    }

    @Test
    fun `returns 400 for blank URL`() {
        mockMvc.perform(
            post("/analyze")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "url": "  ",
                      "clientObservation": {
                        "certificateChain": ["cert"],
                        "serverIp": "1.1.1.1",
                        "serverAsn": null,
                        "tlsProtocol": "TLSv1.3",
                        "cipherSuite": "TLS_AES_128_GCM_SHA256",
                        "alpnProtocol": "h2"
                      }
                    }
                """.trimIndent()),
        )
            .andExpect(status().isBadRequest)
    }

    @Test
    fun `returns 400 when clientObservation is missing`() {
        mockMvc.perform(
            post("/analyze")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"url": "https://example.com"}"""),
        )
            .andExpect(status().isBadRequest)
    }

    @Test
    fun `returns 404 for unknown paths`() {
        mockMvc.perform(get("/unknown-path"))
            .andExpect(status().isNotFound)
    }

    @Test
    fun `returns 404 for unknown POST endpoints`() {
        mockMvc.perform(
            post("/api/v1/unknown")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"test": "value"}"""),
        )
            .andExpect(status().isNotFound)
    }
}
