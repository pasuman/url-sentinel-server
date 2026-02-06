package com.seheon99.urlpolice.rule.rules

import com.seheon99.urlpolice.config.RuleProperties
import com.seheon99.urlpolice.rule.PhishingRule
import com.seheon99.urlpolice.rule.RuleResult
import com.seheon99.urlpolice.rule.Severity
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
        )
    }
}
