package com.seheon99.urlsentinel.api

import com.seheon99.urlsentinel.ssl.SslCertificateService
import org.junit.jupiter.api.Test
import org.mockito.Mockito.`when`
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest
import org.springframework.http.MediaType
import org.springframework.test.context.bean.override.mockito.MockitoBean
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@WebMvcTest(SslVerifyController::class)
class SslVerifyControllerTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @MockitoBean
    private lateinit var sslCertificateService: SslCertificateService

    @Test
    fun `returns MATCH when fingerprints match`() {
        val url = "https://www.google.com"
        val fingerprint = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"

        `when`(sslCertificateService.verifyCertificate(url, fingerprint)).thenReturn(
            SslVerifyResponse(
                verdict = SslVerdict.MATCH,
                serverFingerprint = fingerprint,
                clientFingerprint = fingerprint,
                certificateDetails = CertificateDetails(
                    subject = "CN=www.google.com",
                    issuer = "CN=GTS CA 1C3",
                    validFrom = "2023-01-01T00:00:00Z",
                    validTo = "2024-01-01T00:00:00Z",
                    isExpired = false,
                ),
                message = "Certificate fingerprints match. Connection is secure.",
            ),
        )

        mockMvc.perform(
            post("/api/v1/ssl/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"url": "$url", "clientFingerprint": "$fingerprint"}"""),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.verdict").value("MATCH"))
            .andExpect(jsonPath("$.serverFingerprint").value(fingerprint))
            .andExpect(jsonPath("$.clientFingerprint").value(fingerprint))
            .andExpect(jsonPath("$.certificateDetails.subject").value("CN=www.google.com"))
            .andExpect(jsonPath("$.message").exists())
    }

    @Test
    fun `returns MISMATCH when fingerprints differ`() {
        val url = "https://www.google.com"
        val serverFingerprint = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
        val clientFingerprint = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"

        `when`(sslCertificateService.verifyCertificate(url, clientFingerprint)).thenReturn(
            SslVerifyResponse(
                verdict = SslVerdict.MISMATCH,
                serverFingerprint = serverFingerprint,
                clientFingerprint = clientFingerprint,
                certificateDetails = CertificateDetails(
                    subject = "CN=www.google.com",
                    issuer = "CN=GTS CA 1C3",
                    validFrom = "2023-01-01T00:00:00Z",
                    validTo = "2024-01-01T00:00:00Z",
                    isExpired = false,
                ),
                message = "Certificate fingerprints do not match. Possible DNS hijacking or MITM attack.",
            ),
        )

        mockMvc.perform(
            post("/api/v1/ssl/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"url": "$url", "clientFingerprint": "$clientFingerprint"}"""),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.verdict").value("MISMATCH"))
            .andExpect(jsonPath("$.serverFingerprint").value(serverFingerprint))
            .andExpect(jsonPath("$.clientFingerprint").value(clientFingerprint))
            .andExpect(jsonPath("$.certificateDetails").exists())
            .andExpect(jsonPath("$.message").exists())
    }

    @Test
    fun `returns ERROR when certificate fetch fails`() {
        val url = "https://unreachable-domain.com"
        val fingerprint = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"

        `when`(sslCertificateService.verifyCertificate(url, fingerprint)).thenReturn(
            SslVerifyResponse(
                verdict = SslVerdict.ERROR,
                serverFingerprint = null,
                clientFingerprint = fingerprint,
                certificateDetails = null,
                message = "Unable to resolve hostname",
            ),
        )

        mockMvc.perform(
            post("/api/v1/ssl/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"url": "$url", "clientFingerprint": "$fingerprint"}"""),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.verdict").value("ERROR"))
            .andExpect(jsonPath("$.serverFingerprint").isEmpty)
            .andExpect(jsonPath("$.clientFingerprint").value(fingerprint))
            .andExpect(jsonPath("$.certificateDetails").isEmpty)
            .andExpect(jsonPath("$.message").value("Unable to resolve hostname"))
    }

    @Test
    fun `returns 400 for non-HTTPS URL`() {
        val url = "http://example.com"
        val fingerprint = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"

        `when`(sslCertificateService.verifyCertificate(url, fingerprint))
            .thenThrow(IllegalArgumentException("URL must use HTTPS protocol"))

        mockMvc.perform(
            post("/api/v1/ssl/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"url": "$url", "clientFingerprint": "$fingerprint"}"""),
        )
            .andExpect(status().isBadRequest)
    }

    @Test
    fun `returns 400 for blank URL`() {
        val fingerprint = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"

        mockMvc.perform(
            post("/api/v1/ssl/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"url": "  ", "clientFingerprint": "$fingerprint"}"""),
        )
            .andExpect(status().isBadRequest)
    }

    @Test
    fun `returns 400 for invalid fingerprint format`() {
        val url = "https://example.com"
        val invalidFingerprint = "invalid-fingerprint"

        `when`(sslCertificateService.verifyCertificate(url, invalidFingerprint))
            .thenThrow(IllegalArgumentException("Invalid fingerprint format. Expected 64 hexadecimal characters."))

        mockMvc.perform(
            post("/api/v1/ssl/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"url": "$url", "clientFingerprint": "$invalidFingerprint"}"""),
        )
            .andExpect(status().isBadRequest)
    }
}
