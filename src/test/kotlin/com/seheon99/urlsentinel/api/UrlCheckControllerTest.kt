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
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@WebMvcTest(UrlCheckController::class)
class UrlCheckControllerTest {

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
            ),
        )

        mockMvc.perform(
            post("/api/v1/url/check")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"url": "$url"}"""),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.verdict").value("ALLOW"))
            .andExpect(jsonPath("$.reasons").isEmpty())
            .andExpect(jsonPath("$.riskScore").value(0))
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
            post("/api/v1/url/check")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"url": "$url"}"""),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.verdict").value("REJECT"))
            .andExpect(jsonPath("$.reasons.length()").value(2))
            .andExpect(jsonPath("$.riskScore").value(60))
    }

    @Test
    fun `returns 400 for blank URL`() {
        mockMvc.perform(
            post("/api/v1/url/check")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"url": "  "}"""),
        )
            .andExpect(status().isBadRequest)
    }
}
