package com.seheon99.urlsentinel.rule.rules

import com.seheon99.urlsentinel.config.RuleProperties
import com.seheon99.urlsentinel.rule.PhishingRule
import com.seheon99.urlsentinel.rule.RuleResult
import com.seheon99.urlsentinel.rule.Severity
import org.springframework.stereotype.Component

@Component
class UrlLengthRule(
    private val properties: RuleProperties,
) : PhishingRule {

    override fun evaluate(url: String): RuleResult {
        val triggered = url.length > properties.maxUrlLength
        return RuleResult(
            triggered = triggered,
            code = "URL_TOO_LONG",
            severity = Severity.MINOR,
            message = if (triggered) "URL length (${url.length}) exceeds threshold (${properties.maxUrlLength})" else "",
        )
    }
}
