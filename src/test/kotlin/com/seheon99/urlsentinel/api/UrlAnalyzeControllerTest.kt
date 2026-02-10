package com.seheon99.urlsentinel.api

import com.seheon99.urlsentinel.rule.RuleEngine
import com.seheon99.urlsentinel.rule.Verdict
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

    @Test
    fun `returns ALLOW for safe URL`() {
        val url = "https://www.google.com"
        `when`(ruleEngine.evaluate(url)).thenReturn(
            UrlCheckResponse(
                verdict = Verdict.ALLOW,
                reasons = emptyList(),
                riskScore = 0,
            )
        )

        mockMvc.perform(
            post("/analyze")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"url": "$url"}""")
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.verdict").value("ALLOW"))
            .andExpect(jsonPath("$.riskScore").value(0))
            .andExpect(jsonPath("$.reasons").isEmpty)
    }

    @Test
    fun `returns REJECT with reasons when URL is phishing`() {
        val url = "http://192.168.1.1/login"
        `when`(ruleEngine.evaluate(url)).thenReturn(
            UrlCheckResponse(
                verdict = Verdict.REJECT,
                reasons = listOf(
                    ReasonDetail("IP_ADDRESS_DOMAIN", "CRITICAL", "URL uses an IP address"),
                    ReasonDetail("SUSPICIOUS_KEYWORD", "MAJOR", "URL contains: login"),
                ),
                riskScore = 60,
            )
        )

        mockMvc.perform(
            post("/analyze")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"url": "$url"}""")
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.verdict").value("REJECT"))
            .andExpect(jsonPath("$.reasons.length()").value(2))
            .andExpect(jsonPath("$.reasons[0].code").value("IP_ADDRESS_DOMAIN"))
            .andExpect(jsonPath("$.reasons[0].severity").value("CRITICAL"))
            .andExpect(jsonPath("$.reasons[1].code").value("SUSPICIOUS_KEYWORD"))
            .andExpect(jsonPath("$.reasons[1].severity").value("MAJOR"))
            .andExpect(jsonPath("$.riskScore").value(60))
    }

    @Test
    fun `returns REJECT for suspicious URL patterns`() {
        val url = "http://bit.ly/suspicious-link"
        `when`(ruleEngine.evaluate(url)).thenReturn(
            UrlCheckResponse(
                verdict = Verdict.REJECT,
                reasons = listOf(
                    ReasonDetail("URL_SHORTENER", "MAJOR", "URL uses a shortener domain"),
                ),
                riskScore = 40,
            )
        )

        mockMvc.perform(
            post("/analyze")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"url": "$url"}""")
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.verdict").value("REJECT"))
            .andExpect(jsonPath("$.reasons.length()").value(1))
            .andExpect(jsonPath("$.riskScore").value(40))
    }

    @Test
    fun `returns 400 for blank URL`() {
        mockMvc.perform(
            post("/analyze")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"url": "  "}""")
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
                .content("""{"test": "value"}""")
        )
            .andExpect(status().isNotFound)
    }
}
