package com.seheon99.urlsentinel.rule.rules

import com.seheon99.urlsentinel.adapter.AiAdapter
import com.seheon99.urlsentinel.network.NetworkFeaturesService
import com.seheon99.urlsentinel.rule.PhishingRule
import com.seheon99.urlsentinel.rule.RuleResult
import com.seheon99.urlsentinel.rule.Severity
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component

/**
 * AI Model Rule: Uses external AI service for phishing detection.
 *
 * Integrates with the AI Adapter to leverage machine learning models
 * (LightGBM ensemble) with network features for advanced threat detection.
 */
@Component
class AiModelRule(
    private val aiAdapter: AiAdapter,
    private val networkFeaturesService: NetworkFeaturesService,
) : PhishingRule {

    private val logger = LoggerFactory.getLogger(AiModelRule::class.java)

    override fun evaluate(url: String): RuleResult {
        // Collect network features (best-effort, use empty map on failure)
        val networkFeatures = try {
            networkFeaturesService.collectFeatures(url)
        } catch (e: Exception) {
            logger.warn("Failed to collect network features: {}", e.message)
            emptyMap()
        }

        val result = try {
            aiAdapter.classify(url, networkFeatures.ifEmpty { null })
        } catch (e: Exception) {
            logger.warn("AI service unavailable, skipping AI rule: {}", e.message)
            return RuleResult(
                triggered = false,
                code = "AI_MODEL_PHISHING",
                severity = Severity.CRITICAL,
                message = "",
            )
        }

        return RuleResult(
            triggered = result.isPhishing,
            code = "AI_MODEL_PHISHING",
            severity = Severity.CRITICAL,
            message = if (result.isPhishing)
                "AI model flagged as phishing (probability: ${"%.2f".format(result.phishingProbability)})"
            else "",
        )
    }
}
