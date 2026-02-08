package com.seheon99.urlsentinel.rule.rules

import com.seheon99.urlsentinel.ai.AiClassifyClient
import com.seheon99.urlsentinel.rule.PhishingRule
import com.seheon99.urlsentinel.rule.RuleResult
import com.seheon99.urlsentinel.rule.Severity
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component

@Component
class AiModelRule(private val aiClassifyClient: AiClassifyClient) : PhishingRule {

    private val logger = LoggerFactory.getLogger(AiModelRule::class.java)

    override fun evaluate(url: String): RuleResult {
        val response = try {
            aiClassifyClient.classify(url)
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
