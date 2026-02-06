package com.seheon99.urlpolice.rule.rules

import com.seheon99.urlpolice.config.RuleProperties
import com.seheon99.urlpolice.rule.PhishingRule
import com.seheon99.urlpolice.rule.RuleResult
import com.seheon99.urlpolice.rule.Severity
import org.springframework.stereotype.Component
import java.net.URI

@Component
class SuspiciousTldRule(
    private val properties: RuleProperties,
) : PhishingRule {

    override fun evaluate(url: String): RuleResult {
        val host = try {
            URI.create(url).host?.lowercase() ?: ""
        } catch (_: Exception) {
            ""
        }

        val tld = host.substringAfterLast('.', "")
        val triggered = tld in properties.suspiciousTlds
        return RuleResult(
            triggered = triggered,
            code = "SUSPICIOUS_TLD",
            severity = Severity.MAJOR,
            message = if (triggered) "URL uses suspicious TLD: .$tld" else "",
        )
    }
}
