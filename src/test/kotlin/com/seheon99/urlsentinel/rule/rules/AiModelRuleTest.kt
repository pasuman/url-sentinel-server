package com.seheon99.urlsentinel.rule.rules

import com.seheon99.urlsentinel.adapter.AiAdapter
import com.seheon99.urlsentinel.adapter.AiClassificationResult
import com.seheon99.urlsentinel.network.NetworkFeaturesService
import com.seheon99.urlsentinel.rule.Severity
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.anyMap
import org.mockito.ArgumentMatchers.anyString
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
    fun `phishing URL triggers with MAJOR severity`() {
        `when`(networkFeaturesService.collectFeatures(anyString())).thenReturn(
            mapOf("time_response" to 100.0, "qty_ip_resolved" to 1.0)
        )
        `when`(aiAdapter.classify(anyString(), anyMap())).thenReturn(
            AiClassificationResult(url = "http://evil.com/login", phishingProbability = 0.92, isPhishing = true),
        )

        val result = rule.evaluate("http://evil.com/login")
        assertTrue(result.triggered)
        assertEquals(Severity.MAJOR, result.severity)
        assertEquals("AI_MODEL_PHISHING", result.code)
        assertTrue(result.message.contains("0.92"))
    }

    @Test
    fun `legit URL triggers with low score`() {
        `when`(networkFeaturesService.collectFeatures(anyString())).thenReturn(
            mapOf("time_response" to 50.0, "qty_ip_resolved" to 2.0, "tls_ssl_certificate" to 1.0)
        )
        `when`(aiAdapter.classify(anyString(), anyMap())).thenReturn(
            AiClassificationResult(url = "https://www.google.com", phishingProbability = 0.05, isPhishing = false),
        )

        val result = rule.evaluate("https://www.google.com")
        assertTrue(result.triggered) // Now triggers with low probability
        assertEquals(2.0, result.score) // Low score: 0.05 × 40 = 2.0
    }

    @Test
    fun `AI service failure does not trigger (fail-open)`() {
        `when`(networkFeaturesService.collectFeatures(anyString())).thenReturn(emptyMap())
        `when`(aiAdapter.classify(anyString(), anyMap())).thenThrow(RuntimeException("Connection refused"))

        val result = rule.evaluate("https://example.com")
        assertFalse(result.triggered)
    }

    @Test
    fun `network features collection failure does not prevent AI call`() {
        `when`(networkFeaturesService.collectFeatures(anyString()))
            .thenThrow(RuntimeException("DNS timeout"))
        `when`(aiAdapter.classify(anyString(), anyMap())).thenReturn(
            AiClassificationResult(url = "https://example.com", phishingProbability = 0.3, isPhishing = false),
        )

        val result = rule.evaluate("https://example.com")
        assertTrue(result.triggered) // Triggers with 0.3 probability
        assertEquals(12.0, result.score) // 0.3 × 40 = 12.0
    }

    @Test
    fun `probability-based score is calculated correctly for high probability`() {
        `when`(networkFeaturesService.collectFeatures(anyString())).thenReturn(emptyMap())
        `when`(aiAdapter.classify(anyString(), anyMap())).thenReturn(
            AiClassificationResult(url = "http://evil.com", phishingProbability = 0.95, isPhishing = true),
        )

        val result = rule.evaluate("http://evil.com")
        assertEquals(38.0, result.score) // 0.95 × 40 = 38.0
    }

    @Test
    fun `probability-based score is calculated correctly for medium probability`() {
        `when`(networkFeaturesService.collectFeatures(anyString())).thenReturn(emptyMap())
        `when`(aiAdapter.classify(anyString(), anyMap())).thenReturn(
            AiClassificationResult(url = "http://suspicious.com", phishingProbability = 0.5, isPhishing = false),
        )

        val result = rule.evaluate("http://suspicious.com")
        assertEquals(20.0, result.score) // 0.5 × 40 = 20.0
    }

    @Test
    fun `probability-based score is calculated correctly for low probability`() {
        `when`(networkFeaturesService.collectFeatures(anyString())).thenReturn(emptyMap())
        `when`(aiAdapter.classify(anyString(), anyMap())).thenReturn(
            AiClassificationResult(url = "https://google.com", phishingProbability = 0.05, isPhishing = false),
        )

        val result = rule.evaluate("https://google.com")
        assertEquals(2.0, result.score) // 0.05 × 40 = 2.0
    }

    @Test
    fun `probability-based score is zero for zero probability`() {
        `when`(networkFeaturesService.collectFeatures(anyString())).thenReturn(emptyMap())
        `when`(aiAdapter.classify(anyString(), anyMap())).thenReturn(
            AiClassificationResult(url = "https://safe.com", phishingProbability = 0.0, isPhishing = false),
        )

        val result = rule.evaluate("https://safe.com")
        assertFalse(result.triggered) // Does not trigger when probability is 0.0
        assertEquals(0.0, result.score) // 0.0 × 40 = 0.0
    }

    @Test
    fun `probability-based score is maximum for 100% probability`() {
        `when`(networkFeaturesService.collectFeatures(anyString())).thenReturn(emptyMap())
        `when`(aiAdapter.classify(anyString(), anyMap())).thenReturn(
            AiClassificationResult(url = "http://phishing.com", phishingProbability = 1.0, isPhishing = true),
        )

        val result = rule.evaluate("http://phishing.com")
        assertEquals(40.0, result.score) // 1.0 × 40 = 40.0
    }
}
