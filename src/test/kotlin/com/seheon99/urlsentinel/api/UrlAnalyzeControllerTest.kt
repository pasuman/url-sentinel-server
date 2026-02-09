package com.seheon99.urlsentinel.api

import com.seheon99.urlsentinel.rule.RuleEngine
import com.seheon99.urlsentinel.rule.Verdict
import com.seheon99.urlsentinel.ssl.SslCertificateService
import org.junit.jupiter.api.Test
import org.mockito.Mockito.`when`
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest
import org.springframework.http.MediaType
import org.springframework.test.context.bean.override.mockito.MockitoBean
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@WebMvcTest(controllers = [UrlAnalyzeController::class, GlobalExceptionHandler::class])
class UrlAnalyzeControllerTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @MockitoBean
    private lateinit var ruleEngine: RuleEngine

    @MockitoBean
    private lateinit var sslCertificateService: SslCertificateService

    @Test
    fun `returns ALLOW for safe URL without SSL verification`() {
        val url = "https://www.google.com"
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
                .content("""{"url": "$url"}"""),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.verdict").value("ALLOW"))
            .andExpect(jsonPath("$.reasons").isEmpty())
            .andExpect(jsonPath("$.riskScore").value(0))
            .andExpect(jsonPath("$.sslVerification").doesNotExist())
    }

    @Test
    fun `returns REJECT with reasons`() {
        val url = "http://192.168.1.1/login"
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
                .content("""{"url": "$url"}"""),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.verdict").value("REJECT"))
            .andExpect(jsonPath("$.reasons.length()").value(2))
            .andExpect(jsonPath("$.riskScore").value(60))
    }

    @Test
    fun `returns URL check and SSL verification when fingerprint provided`() {
        val url = "https://example.com"
        val fingerprint = "A1:B2:C3:D4:E5:F6:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"

        `when`(ruleEngine.evaluate(url)).thenReturn(
            UrlCheckResponse(
                verdict = Verdict.ALLOW,
                reasons = emptyList(),
                riskScore = 0,
            ),
        )

        `when`(sslCertificateService.verifyCertificate(url, fingerprint)).thenReturn(
            SslVerifyResponse(
                verdict = SslVerdict.MATCH,
                serverFingerprint = fingerprint,
                clientFingerprint = fingerprint,
                certificateDetails = CertificateDetails(
                    subject = "CN=example.com",
                    issuer = "CN=Test CA",
                    validFrom = "2024-01-01T00:00:00Z",
                    validTo = "2025-01-01T00:00:00Z",
                    isExpired = false,
                ),
                message = "Certificate fingerprints match. Connection is secure.",
            ),
        )

        mockMvc.perform(
            post("/analyze")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"url": "$url", "clientFingerprint": "$fingerprint"}"""),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.verdict").value("ALLOW"))
            .andExpect(jsonPath("$.sslVerification").exists())
            .andExpect(jsonPath("$.sslVerification.verdict").value("MATCH"))
            .andExpect(jsonPath("$.sslVerification.serverFingerprint").value(fingerprint))
            .andExpect(jsonPath("$.sslVerification.message").exists())
    }

    @Test
    fun `returns 400 for blank URL`() {
        mockMvc.perform(
            post("/analyze")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"url": "  "}"""),
        )
            .andExpect(status().isBadRequest)
    }

    @Test
    fun `handles SSL verification failure gracefully`() {
        val url = "https://evil.com"
        val fingerprint = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"

        `when`(ruleEngine.evaluate(url)).thenReturn(
            UrlCheckResponse(
                verdict = Verdict.REJECT,
                reasons = listOf(
                    ReasonDetail("SUSPICIOUS_TLD", "MAJOR", "Suspicious TLD"),
                ),
                riskScore = 20,
            ),
        )

        `when`(sslCertificateService.verifyCertificate(url, fingerprint)).thenReturn(
            SslVerifyResponse(
                verdict = SslVerdict.MISMATCH,
                serverFingerprint = "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF",
                clientFingerprint = fingerprint,
                certificateDetails = null,
                message = "Certificate fingerprints do not match. Possible DNS hijacking or MITM attack.",
            ),
        )

        mockMvc.perform(
            post("/analyze")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"url": "$url", "clientFingerprint": "$fingerprint"}"""),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.verdict").value("REJECT"))
            .andExpect(jsonPath("$.sslVerification.verdict").value("MISMATCH"))
            .andExpect(jsonPath("$.sslVerification.message").value("Certificate fingerprints do not match. Possible DNS hijacking or MITM attack."))
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
