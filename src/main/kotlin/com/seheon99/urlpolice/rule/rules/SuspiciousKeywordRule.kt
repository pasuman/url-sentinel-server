package com.seheon99.urlpolice.rule.rules

import com.seheon99.urlpolice.config.RuleProperties
import com.seheon99.urlpolice.rule.PhishingRule
import com.seheon99.urlpolice.rule.RuleResult
import com.seheon99.urlpolice.rule.Severity
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
