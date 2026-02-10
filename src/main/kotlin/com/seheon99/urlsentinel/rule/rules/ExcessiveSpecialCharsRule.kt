package com.seheon99.urlsentinel.rule.rules

import com.seheon99.urlsentinel.config.RuleProperties
import com.seheon99.urlsentinel.rule.PhishingRule
import com.seheon99.urlsentinel.rule.RuleResult
import com.seheon99.urlsentinel.rule.Severity
import org.springframework.stereotype.Component

@Component
class ExcessiveSpecialCharsRule(
    private val properties: RuleProperties,
) : PhishingRule {

    private val specialChars = setOf('.', '-', '@', '?', '=', '%')

    override fun evaluate(url: String): RuleResult {
        val count = url.count { it in specialChars }
        val triggered = count > properties.specialCharThreshold
        return RuleResult(
            triggered = triggered,
            code = "EXCESSIVE_SPECIAL_CHARS",
            severity = Severity.MINOR,
            message = if (triggered) "URL contains $count special characters (threshold: ${properties.specialCharThreshold})" else "",
            score = 10.0,
        )
    }
}
