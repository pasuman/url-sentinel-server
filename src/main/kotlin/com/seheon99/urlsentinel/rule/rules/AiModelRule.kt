package com.seheon99.urlsentinel.rule.rules

import com.seheon99.urlsentinel.ai.AiClassifyClient
import com.seheon99.urlsentinel.network.NetworkFeaturesService
import com.seheon99.urlsentinel.rule.PhishingRule
import com.seheon99.urlsentinel.rule.RuleResult
import com.seheon99.urlsentinel.rule.Severity
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component

@Component
class AiModelRule(
    private val aiClassifyClient: AiClassifyClient,
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

        val response = try {
            aiClassifyClient.classify(url, networkFeatures.ifEmpty { null })
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
            triggered = response.isPhishing,
            code = "AI_MODEL_PHISHING",
            severity = Severity.CRITICAL,
            message = if (response.isPhishing)
                "AI model flagged as phishing (probability: ${"%.2f".format(response.phishingProbability)})"
            else "",
        )
    }
}
