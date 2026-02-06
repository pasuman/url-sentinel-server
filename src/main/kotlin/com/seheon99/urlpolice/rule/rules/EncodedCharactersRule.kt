package com.seheon99.urlpolice.rule.rules

import com.seheon99.urlpolice.config.RuleProperties
import com.seheon99.urlpolice.rule.PhishingRule
import com.seheon99.urlpolice.rule.RuleResult
import com.seheon99.urlpolice.rule.Severity
import org.springframework.stereotype.Component

@Component
class EncodedCharactersRule(
    private val properties: RuleProperties,
) : PhishingRule {

    private val encodedPattern = Regex("""%[0-9A-Fa-f]{2}""")

    override fun evaluate(url: String): RuleResult {
        val count = encodedPattern.findAll(url).count()
        val triggered = count > properties.encodedCharThreshold
        return RuleResult(
            triggered = triggered,
            code = "ENCODED_CHARACTERS",
            severity = Severity.MINOR,
            message = if (triggered) "URL contains $count encoded characters (threshold: ${properties.encodedCharThreshold})" else "",
        )
    }
}
