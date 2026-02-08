package com.seheon99.urlsentinel.rule.rules

import com.seheon99.urlsentinel.config.RuleProperties
import com.seheon99.urlsentinel.rule.PhishingRule
import com.seheon99.urlsentinel.rule.RuleResult
import com.seheon99.urlsentinel.rule.Severity
import org.springframework.stereotype.Component

@Component
class SuspiciousKeywordRule(
    private val properties: RuleProperties,
) : PhishingRule {

    override fun evaluate(url: String): RuleResult {
        val lowerUrl = url.lowercase()
        val matched = properties.suspiciousKeywords.filter { it in lowerUrl }
        val triggered = matched.isNotEmpty()
        return RuleResult(
            triggered = triggered,
            code = "SUSPICIOUS_KEYWORD",
            severity = Severity.MAJOR,
            message = if (triggered) "URL contains suspicious keywords: ${matched.joinToString()}" else "",
        )
    }
}
