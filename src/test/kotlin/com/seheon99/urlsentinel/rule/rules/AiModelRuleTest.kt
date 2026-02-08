package com.seheon99.urlsentinel.rule.rules

import com.seheon99.urlsentinel.ai.AiClassifyClient
import com.seheon99.urlsentinel.ai.AiClassifyResponse
import com.seheon99.urlsentinel.rule.Severity
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AiModelRuleTest {

    private val client = mock(AiClassifyClient::class.java)
    private val rule = AiModelRule(client)

    @Test
    fun `phishing URL triggers with CRITICAL severity`() {
        `when`(client.classify("http://evil.com/login")).thenReturn(
            AiClassifyResponse(url = "http://evil.com/login", phishingProbability = 0.92, isPhishing = true),
        )

        val result = rule.evaluate("http://evil.com/login")
        assertTrue(result.triggered)
        assertEquals(Severity.CRITICAL, result.severity)
        assertEquals("AI_MODEL_PHISHING", result.code)
        assertTrue(result.message.contains("0.92"))
    }

    @Test
    fun `legit URL does not trigger`() {
        `when`(client.classify("https://www.google.com")).thenReturn(
            AiClassifyResponse(url = "https://www.google.com", phishingProbability = 0.05, isPhishing = false),
        )

        val result = rule.evaluate("https://www.google.com")
        assertFalse(result.triggered)
    }

    @Test
    fun `AI service failure does not trigger (fail-open)`() {
        `when`(client.classify("https://example.com")).thenThrow(RuntimeException("Connection refused"))

        val result = rule.evaluate("https://example.com")
        assertFalse(result.triggered)
    }
}
