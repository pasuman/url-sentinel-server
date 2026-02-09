package com.seheon99.urlsentinel.rule.rules

import com.seheon99.urlsentinel.adapter.AiAdapter
import com.seheon99.urlsentinel.adapter.AiClassificationResult
import com.seheon99.urlsentinel.network.NetworkFeaturesService
import com.seheon99.urlsentinel.rule.Severity
import org.junit.jupiter.api.Test
import org.mockito.Mockito.anyString
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AiModelRuleTest {

    private val aiAdapter = mock(AiAdapter::class.java)
    private val networkFeaturesService = mock(NetworkFeaturesService::class.java)
    private val rule = AiModelRule(aiAdapter, networkFeaturesService)

    @Test
    fun `phishing URL triggers with CRITICAL severity`() {
        `when`(networkFeaturesService.collectFeatures(anyString())).thenReturn(
            mapOf("time_response" to 100.0, "qty_ip_resolved" to 1.0)
        )
        `when`(aiAdapter.classify(anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(
            AiClassificationResult(url = "http://evil.com/login", phishingProbability = 0.92, isPhishing = true),
        )

        val result = rule.evaluate("http://evil.com/login")
        assertTrue(result.triggered)
        assertEquals(Severity.CRITICAL, result.severity)
        assertEquals("AI_MODEL_PHISHING", result.code)
        assertTrue(result.message.contains("0.92"))
    }

    @Test
    fun `legit URL does not trigger`() {
        `when`(networkFeaturesService.collectFeatures(anyString())).thenReturn(
            mapOf("time_response" to 50.0, "qty_ip_resolved" to 2.0, "tls_ssl_certificate" to 1.0)
        )
        `when`(aiAdapter.classify(anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(
            AiClassificationResult(url = "https://www.google.com", phishingProbability = 0.05, isPhishing = false),
        )

        val result = rule.evaluate("https://www.google.com")
        assertFalse(result.triggered)
    }

    @Test
    fun `AI service failure does not trigger (fail-open)`() {
        `when`(networkFeaturesService.collectFeatures(anyString())).thenReturn(emptyMap())
        `when`(aiAdapter.classify(anyString(), org.mockito.ArgumentMatchers.any())).thenThrow(RuntimeException("Connection refused"))

        val result = rule.evaluate("https://example.com")
        assertFalse(result.triggered)
    }

    @Test
    fun `network features collection failure does not prevent AI call`() {
        `when`(networkFeaturesService.collectFeatures(anyString()))
            .thenThrow(RuntimeException("DNS timeout"))
        `when`(aiAdapter.classify(anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(
            AiClassificationResult(url = "https://example.com", phishingProbability = 0.3, isPhishing = false),
        )

        val result = rule.evaluate("https://example.com")
        assertFalse(result.triggered)
    }
}
